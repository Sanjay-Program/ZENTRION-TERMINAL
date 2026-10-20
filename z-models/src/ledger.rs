//! Durable daily usage ledger and hard budget reservations.
//!
//! A reservation is written before a provider call and converted to actual
//! usage afterwards. Reservations are capped at the request's *maximum* output
//! tokens, so a successful call cannot exceed the reserved amount. The ledger
//! is file-locked and atomically replaced; a crashed process leaves a
//! reservation that is pruned after one hour.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

const LEDGER_VERSION: u32 = 1;
const MICROS_PER_USD: f64 = 1_000_000.0;
const STALE_RESERVATION_MINUTES: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UsageFile {
    version: u32,
    days: BTreeMap<String, DayUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DayUsage {
    total_micros: u64,
    agents: BTreeMap<String, u64>,
    sessions: BTreeMap<String, u64>,
    tasks: BTreeMap<String, u64>,
    requests: u64,
    input_tokens: u64,
    output_tokens: u64,
    reservations: BTreeMap<String, ReservationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReservationEntry {
    micros: u64,
    created_at: DateTime<Utc>,
    agent: Option<String>,
    session: Option<String>,
    task: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reservation {
    pub id: String,
    pub day: String,
    pub micros: u64,
    pub agent: Option<String>,
    pub session: Option<String>,
    pub task: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentUsage {
    pub spent_usd: f64,
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsageSummary {
    pub day: String,
    pub budget_usd: f64,
    pub spent_usd: f64,
    pub reserved_usd: f64,
    pub remaining_usd: f64,
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub agents: BTreeMap<String, AgentUsage>,
    pub sessions: BTreeMap<String, f64>,
    pub tasks: BTreeMap<String, f64>,
}

#[derive(Debug)]
pub struct UsageLedger {
    /// `None` keeps the ledger in memory (tests, headless one-shots).
    path: Option<PathBuf>,
    budget_micros: u64,
    agent_budgets: BTreeMap<String, u64>,
    memory: Mutex<UsageFile>,
    lock: Mutex<()>,
}

impl UsageLedger {
    pub fn new(
        path: Option<PathBuf>,
        budget_usd_per_day: f64,
        agent_budgets: &BTreeMap<String, f64>,
    ) -> Self {
        let budget_micros = (budget_usd_per_day.max(0.0) * MICROS_PER_USD) as u64;
        let agent_budgets = agent_budgets
            .iter()
            .map(|(agent, budget)| (agent.clone(), (budget.max(0.0) * MICROS_PER_USD) as u64))
            .collect();
        Self {
            path,
            budget_micros,
            agent_budgets,
            memory: Mutex::new(UsageFile::default()),
            lock: Mutex::new(()),
        }
    }

    pub fn in_memory(budget_usd_per_day: f64) -> Self {
        Self::new(None, budget_usd_per_day, &BTreeMap::new())
    }

    pub fn budget_micros(&self) -> u64 {
        self.budget_micros
    }

    fn today() -> String {
        Utc::now().date_naive().to_string()
    }

    /// Check whether the current day can afford `micros` for `agent`.
    pub fn can_afford(&self, agent: Option<&str>, micros: u64) -> bool {
        self.with_day(|day| {
            let reserved: u64 = day.reservations.values().map(|entry| entry.micros).sum();
            let total = day.total_micros.saturating_add(reserved);
            if total.saturating_add(micros) > self.budget_micros {
                return false;
            }
            if let Some(agent) = agent {
                if let Some(limit) = self.agent_budgets.get(agent) {
                    let spent = day.agents.get(agent).copied().unwrap_or(0);
                    let reserved_agent: u64 = day
                        .reservations
                        .values()
                        .filter(|entry| entry.agent.as_deref() == Some(agent))
                        .map(|entry| entry.micros)
                        .sum();
                    if spent.saturating_add(reserved_agent).saturating_add(micros) > *limit {
                        return false;
                    }
                }
            }
            true
        })
    }

    /// Reserve budget for one call. Fails rather than overspending.
    pub fn reserve(
        &self,
        micros: u64,
        agent: Option<&str>,
        session: Option<&str>,
        task: &str,
    ) -> Result<Reservation, LedgerError> {
        self.with_day_mut(|day, budget| {
            let reserved: u64 = day.reservations.values().map(|entry| entry.micros).sum();
            let total = day.total_micros.saturating_add(reserved);
            if total.saturating_add(micros) > *budget {
                return Err(LedgerError::BudgetExceeded {
                    limit_usd: *budget as f64 / MICROS_PER_USD,
                    spent_usd: (*budget)
                        .saturating_sub(budget.saturating_sub(total.saturating_add(micros)))
                        as f64
                        / MICROS_PER_USD,
                    requested_usd: micros as f64 / MICROS_PER_USD,
                });
            }
            if let Some(agent) = agent {
                if let Some(limit) = self.agent_budgets.get(agent) {
                    let spent = day.agents.get(agent).copied().unwrap_or(0);
                    let agent_reserved: u64 = day
                        .reservations
                        .values()
                        .filter(|entry| entry.agent.as_deref() == Some(agent))
                        .map(|entry| entry.micros)
                        .sum();
                    if spent.saturating_add(agent_reserved).saturating_add(micros) > *limit {
                        return Err(LedgerError::AgentBudgetExceeded {
                            agent: agent.to_string(),
                            limit_usd: *limit as f64 / MICROS_PER_USD,
                        });
                    }
                }
            }
            let id = format!("res_{}", Uuid::new_v4().simple());
            day.reservations.insert(
                id.clone(),
                ReservationEntry {
                    micros,
                    created_at: Utc::now(),
                    agent: agent.map(str::to_string),
                    session: session.map(str::to_string),
                    task: task.to_string(),
                },
            );
            Ok(Reservation {
                id,
                day: Self::today(),
                micros,
                agent: agent.map(str::to_string),
                session: session.map(str::to_string),
                task: task.to_string(),
            })
        })
    }

    /// Turn a reservation into actual recorded usage.
    pub fn commit(
        &self,
        reservation: &Reservation,
        actual_micros: u64,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Result<(), LedgerError> {
        self.with_day_mut(|day, _| {
            let entry = day
                .reservations
                .remove(&reservation.id)
                .ok_or_else(|| LedgerError::UnknownReservation(reservation.id.clone()))?;
            if actual_micros > entry.micros {
                // Keep accounting honest even if a provider reports more than
                // the reserved maximum; the overage is visible in the ledger.
            }
            day.requests = day.requests.saturating_add(1);
            day.input_tokens = day.input_tokens.saturating_add(input_tokens);
            day.output_tokens = day.output_tokens.saturating_add(output_tokens);
            day.total_micros = day.total_micros.saturating_add(actual_micros);
            if let Some(agent) = &reservation.agent {
                *day.agents.entry(agent.clone()).or_insert(0) += actual_micros;
            }
            if let Some(session) = &reservation.session {
                *day.sessions.entry(session.clone()).or_insert(0) += actual_micros;
            }
            *day.tasks.entry(reservation.task.clone()).or_insert(0) += actual_micros;
            Ok(())
        })
    }

    pub fn release(&self, reservation: &Reservation) {
        let _ = self.with_day_mut(|day, _| {
            day.reservations.remove(&reservation.id);
            Ok(())
        });
    }

    pub fn summary(&self, day: Option<&str>) -> UsageSummary {
        let file = self.load();
        let key = day.map(str::to_string).unwrap_or_else(Self::today);
        let usage = file.days.get(&key).cloned().unwrap_or_default();
        let reserved: u64 = usage.reservations.values().map(|entry| entry.micros).sum();
        let spent = usage.total_micros;
        let mut agents = BTreeMap::new();
        for (agent, micros) in &usage.agents {
            agents.insert(
                agent.clone(),
                AgentUsage {
                    spent_usd: *micros as f64 / MICROS_PER_USD,
                    requests: 0,
                    input_tokens: 0,
                    output_tokens: 0,
                },
            );
        }
        UsageSummary {
            day: key,
            budget_usd: self.budget_micros as f64 / MICROS_PER_USD,
            spent_usd: spent as f64 / MICROS_PER_USD,
            reserved_usd: reserved as f64 / MICROS_PER_USD,
            remaining_usd: self
                .budget_micros
                .saturating_sub(spent.saturating_add(reserved)) as f64
                / MICROS_PER_USD,
            requests: usage.requests,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            agents,
            sessions: usage
                .sessions
                .iter()
                .map(|(session, micros)| (session.clone(), *micros as f64 / MICROS_PER_USD))
                .collect(),
            tasks: usage
                .tasks
                .iter()
                .map(|(task, micros)| (task.clone(), *micros as f64 / MICROS_PER_USD))
                .collect(),
        }
    }

    /// Historical summaries for every recorded day.
    pub fn history(&self) -> Vec<UsageSummary> {
        let file = self.load();
        let days: Vec<String> = file.days.keys().cloned().collect();
        days.into_iter()
            .map(|day| self.summary(Some(&day)))
            .collect()
    }

    fn with_day<T>(&self, f: impl FnOnce(&DayUsage) -> T) -> T {
        let file = self.load();
        let day = file.days.get(&Self::today()).cloned().unwrap_or_default();
        f(&day)
    }

    fn with_day_mut<T>(
        &self,
        f: impl FnOnce(&mut DayUsage, &u64) -> Result<T, LedgerError>,
    ) -> Result<T, LedgerError> {
        let _guard = self.lock.lock().expect("ledger lock");
        if let Some(path) = &self.path {
            let _file_lock = FileLock::acquire(path)?;
            // Reload under the file lock so concurrent processes see each
            // other's reservations.
            let mut file = self.load();
            let day = file.days.entry(Self::today()).or_default();
            prune(day);
            let result = f(day, &self.budget_micros)?;
            self.save(&file)?;
            Ok(result)
        } else {
            let mut memory = self.memory.lock().expect("memory ledger lock");
            if memory.version == 0 {
                memory.version = LEDGER_VERSION;
            }
            let day = memory.days.entry(Self::today()).or_default();
            prune(day);
            f(day, &self.budget_micros)
        }
    }

    fn load(&self) -> UsageFile {
        let Some(path) = &self.path else {
            return self.memory.lock().expect("memory ledger lock").clone();
        };
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|_| UsageFile {
                version: LEDGER_VERSION,
                days: BTreeMap::new(),
            }),
            Err(_) => UsageFile {
                version: LEDGER_VERSION,
                days: BTreeMap::new(),
            },
        }
    }

    fn save(&self, file: &UsageFile) -> Result<(), LedgerError> {
        let Some(path) = &self.path else {
            *self.memory.lock().expect("memory ledger lock") = file.clone();
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| LedgerError::Io(e.to_string()))?;
        }
        let text =
            serde_json::to_string_pretty(file).map_err(|e| LedgerError::Io(e.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| LedgerError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, path).map_err(|e| LedgerError::Io(e.to_string()))?;
        Ok(())
    }
}

fn prune(day: &mut DayUsage) {
    let cutoff = Utc::now() - Duration::minutes(STALE_RESERVATION_MINUTES);
    day.reservations
        .retain(|_, entry| entry.created_at > cutoff);
}

#[derive(Debug, Clone, PartialEq)]
pub enum LedgerError {
    BudgetExceeded {
        limit_usd: f64,
        spent_usd: f64,
        requested_usd: f64,
    },
    AgentBudgetExceeded {
        agent: String,
        limit_usd: f64,
    },
    UnknownReservation(String),
    Io(String),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BudgetExceeded {
                limit_usd,
                spent_usd,
                requested_usd,
            } => write!(
                f,
                "daily model budget of ${limit_usd:.2} would be exceeded (spent ${spent_usd:.2}, requested ${requested_usd:.4}); increase [models] budget_usd_per_day or switch to a local model"
            ),
            Self::AgentBudgetExceeded { agent, limit_usd } => write!(
                f,
                "agent `{agent}` would exceed its daily budget of ${limit_usd:.2}"
            ),
            Self::UnknownReservation(id) => write!(f, "unknown budget reservation `{id}`"),
            Self::Io(message) => write!(f, "usage ledger error: {message}"),
        }
    }
}

impl std::error::Error for LedgerError {}

pub fn usd_to_micros(usd: f64) -> u64 {
    (usd.max(0.0) * MICROS_PER_USD) as u64
}

pub fn micros_to_usd(micros: u64) -> f64 {
    micros as f64 / MICROS_PER_USD
}

pub fn estimate_micros(
    input_cost_per_mtok: f64,
    output_cost_per_mtok: f64,
    input_tokens: usize,
    max_output_tokens: u32,
) -> u64 {
    let input = input_tokens as f64 / 1_000_000.0 * input_cost_per_mtok.max(0.0);
    let output = max_output_tokens as f64 / 1_000_000.0 * output_cost_per_mtok.max(0.0);
    usd_to_micros(input + output)
}

struct FileLock {
    path: PathBuf,
}

impl FileLock {
    fn acquire(target: &Path) -> Result<Self, LedgerError> {
        let path = target.with_extension("json.lock");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| LedgerError::Io(e.to_string()))?;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    let _ = writeln!(file, "{}", std::process::id());
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = std::fs::read_to_string(&path)
                        .ok()
                        .and_then(|text| text.trim().parse::<i32>().ok())
                        .map(|pid| !process_alive(pid))
                        .unwrap_or(true);
                    if stale {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(LedgerError::Io("usage ledger is locked".into()));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(error) => return Err(LedgerError::Io(error.to_string())),
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn process_alive(pid: i32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_enforces_daily_budget() {
        let ledger = UsageLedger::in_memory(1.0);
        let reservation = ledger
            .reserve(600_000, Some("agent"), None, "edit")
            .unwrap();
        assert!(!ledger.can_afford(None, 500_000));
        assert!(ledger.can_afford(None, 300_000));
        ledger.commit(&reservation, 500_000, 100, 200).unwrap();
        let summary = ledger.summary(None);
        assert!((summary.spent_usd - 0.5).abs() < 1e-9);
        assert_eq!(summary.requests, 1);
        assert!(ledger.reserve(600_000, None, None, "edit").is_err());
    }

    #[test]
    fn release_restores_capacity() {
        let ledger = UsageLedger::in_memory(1.0);
        let reservation = ledger.reserve(900_000, None, None, "chat").unwrap();
        assert!(ledger.reserve(200_000, None, None, "chat").is_err());
        ledger.release(&reservation);
        assert!(ledger.reserve(200_000, None, None, "chat").is_ok());
    }

    #[test]
    fn agent_budget_is_enforced_independently() {
        let mut budgets = BTreeMap::new();
        budgets.insert("cheap-agent".to_string(), 0.10);
        let ledger = UsageLedger::new(None, 10.0, &budgets);
        let reservation = ledger
            .reserve(50_000, Some("cheap-agent"), None, "edit")
            .unwrap();
        ledger.commit(&reservation, 50_000, 10, 10).unwrap();
        let error = ledger
            .reserve(100_000, Some("cheap-agent"), None, "edit")
            .unwrap_err();
        assert!(matches!(error, LedgerError::AgentBudgetExceeded { .. }));
        assert!(ledger
            .reserve(100_000, Some("other-agent"), None, "edit")
            .is_ok());
    }

    #[test]
    fn zero_budget_allows_only_free_models() {
        let ledger = UsageLedger::in_memory(0.0);
        assert!(ledger.reserve(0, None, None, "chat").is_ok());
        assert!(ledger.reserve(1, None, None, "chat").is_err());
    }

    #[test]
    fn ledger_persists_and_is_private() {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-models-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("usage.json");
        let ledger = UsageLedger::new(Some(path.clone()), 5.0, &BTreeMap::new());
        let reservation = ledger.reserve(250_000, Some("a"), None, "plan").unwrap();
        ledger.commit(&reservation, 250_000, 100, 50).unwrap();
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let reopened = UsageLedger::new(Some(path), 5.0, &BTreeMap::new());
        let summary = reopened.summary(None);
        assert!((summary.spent_usd - 0.25).abs() < 1e-9);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn estimation_uses_max_output_tokens() {
        assert_eq!(estimate_micros(0.0, 0.0, 1000, 1000), 0);
        assert_eq!(estimate_micros(1.0, 10.0, 1_000_000, 100_000), 2_000_000);
    }
}
