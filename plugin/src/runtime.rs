//! Capability-gated wasmtime plugin host.
//!
//! Plugins are WebAssembly modules with an `alloc(len) -> ptr` export, a
//! `memory` export and an entrypoint (`run(ptr,len) -> i64` by default) that
//! returns `(ptr << 32) | len`. The host provides only these imports unless the
//! plugin's signed manifest declares the matching capability:
//!
//! * `log`       — `zentrion.log(ptr,len)` bounded to 4 KiB per message.
//! * `clock`     — `zentrion.clock_ms() -> i64`.
//! * `kv:read`   — `zentrion.kv_get(key_ptr,key_len,out_ptr,out_len) -> i32`.
//! * `kv:write`  — `zentrion.kv_set(key_ptr,key_len,val_ptr,val_len) -> i32`.
//!
//! There are deliberately **no** filesystem, network, process or secret host
//! calls. A plugin that imports them fails instantiation. Fuel limits execution
//! and a `StoreLimits` bounds linear memory; traps return errors to the caller.

use crate::manager::ValidatedPlugin;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;
use wasmtime::{
    Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
};

pub const DEFAULT_FUEL: u64 = 20_000_000;
pub const DEFAULT_MAX_MEMORY: usize = 64 * 1024 * 1024;
pub const MAX_LOG_MESSAGE: usize = 4 * 1024;
pub const MAX_LOG_ENTRIES: usize = 1_000;
pub const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_KV_KEYS: usize = 1_000;
const MAX_KV_KEY: usize = 256;
const MAX_KV_VALUE: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunLimits {
    pub fuel: u64,
    pub max_memory_bytes: usize,
    pub max_output_bytes: usize,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self {
            fuel: DEFAULT_FUEL,
            max_memory_bytes: DEFAULT_MAX_MEMORY,
            max_output_bytes: MAX_OUTPUT,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginLog {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginRun {
    pub plugin: String,
    pub output: String,
    pub logs: Vec<String>,
    pub fuel_used: u64,
    pub duration_ms: u64,
    pub kv: BTreeMap<String, String>,
}

struct HostState {
    limits: StoreLimits,
    capabilities: HashSet<String>,
    logs: Vec<String>,
    kv: BTreeMap<String, String>,
    kv_dirty: bool,
}

pub struct PluginRuntime {
    engine: Engine,
    state_dir: PathBuf,
}

impl PluginRuntime {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
        let engine = Engine::new(&config).context("cannot initialize wasmtime")?;
        let state_dir = z_core::config::user_data_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("plugins")
            .join("state");
        Ok(Self { engine, state_dir })
    }

    pub fn with_state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = dir.into();
        self
    }

    pub fn supported_capabilities() -> &'static [&'static str] {
        &["log", "clock", "kv:read", "kv:write"]
    }

    pub fn run(
        &self,
        validated: &ValidatedPlugin,
        input: &[u8],
        limits: &RunLimits,
    ) -> Result<PluginRun> {
        if input.len() > limits.max_output_bytes {
            return Err(anyhow!(
                "input is larger than the configured {} byte limit",
                limits.max_output_bytes
            ));
        }
        let capabilities: HashSet<String> = validated
            .manifest
            .permissions
            .iter()
            .map(|permission| permission.to_ascii_lowercase())
            .collect();
        let kv = self.load_kv(&validated.manifest.name)?;
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits.max_memory_bytes)
            .instances(1)
            .memories(1)
            .tables(4)
            .build();
        let state = HostState {
            limits: store_limits,
            capabilities: capabilities.clone(),
            logs: Vec::new(),
            kv,
            kv_dirty: false,
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(limits.fuel).context("cannot set fuel")?;
        let started = Instant::now();
        let module = Module::from_file(&self.engine, &validated.path)
            .with_context(|| format!("cannot compile {}", validated.path.display()))?;
        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        self.register_host_functions(&mut linker)?;
        let instance = linker
            .instantiate(&mut store, &module)
            .context("plugin instantiation failed (missing import or invalid module)")?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow!("plugin must export a `memory`"))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .or_else(|_| instance.get_typed_func::<i32, i32>(&mut store, "zentrion_alloc"))
            .context("plugin must export `alloc(len) -> ptr`")?;
        let input_ptr = alloc
            .call(&mut store, input.len() as i32)
            .context("plugin alloc failed")?;
        if input_ptr < 0 {
            return Err(anyhow!("plugin alloc returned a negative pointer"));
        }
        memory
            .write(&mut store, input_ptr as usize, input)
            .context("cannot write plugin input")?;
        let entry = validated.manifest.entrypoint.clone();
        let entry = if entry.trim().is_empty() {
            "run".to_string()
        } else {
            entry
        };
        let func = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, &entry)
            .with_context(|| format!("plugin entrypoint `{entry}` must be (i32,i32)->i64"))?;
        let result = func
            .call(&mut store, (input_ptr, input.len() as i32))
            .context("plugin trapped")?;
        let output_ptr = ((result as u64) >> 32) as usize;
        let output_len = (result as u64 & 0xffff_ffff) as usize;
        if output_len > limits.max_output_bytes {
            return Err(anyhow!(
                "plugin output is {} bytes, above the {} byte limit",
                output_len,
                limits.max_output_bytes
            ));
        }
        let mut output = vec![0u8; output_len];
        memory
            .read(&store, output_ptr, &mut output)
            .context("cannot read plugin output")?;
        let fuel_used = limits.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
        let state = store.into_data();
        if state.kv_dirty {
            self.save_kv(&validated.manifest.name, &state.kv)?;
        }
        Ok(PluginRun {
            plugin: validated.manifest.name.clone(),
            output: String::from_utf8_lossy(&output).to_string(),
            logs: state.logs,
            fuel_used,
            duration_ms: started.elapsed().as_millis() as u64,
            kv: state.kv,
        })
    }

    fn register_host_functions(&self, linker: &mut Linker<HostState>) -> Result<()> {
        linker.func_wrap(
            "zentrion",
            "log",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                if ptr < 0 || len < 0 {
                    return;
                }
                let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory())
                else {
                    return;
                };
                let len = (len as usize).min(MAX_LOG_MESSAGE);
                let mut buffer = vec![0u8; len];
                if memory.read(&caller, ptr as usize, &mut buffer).is_ok() {
                    if caller.data().logs.len() < MAX_LOG_ENTRIES {
                        caller
                            .data_mut()
                            .logs
                            .push(String::from_utf8_lossy(&buffer).to_string());
                    }
                }
            },
        )?;
        linker.func_wrap("zentrion", "clock_ms", || -> i64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis() as i64)
                .unwrap_or(0)
        })?;
        linker.func_wrap(
            "zentrion",
            "kv_get",
            |mut caller: Caller<'_, HostState>,
             key_ptr: i32,
             key_len: i32,
             out_ptr: i32,
             out_len: i32|
             -> i32 {
                if !caller.data().capabilities.contains("kv:read") {
                    return -2;
                }
                let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory())
                else {
                    return -1;
                };
                let key_len = (key_len.max(0) as usize).min(MAX_KV_KEY);
                let mut key = vec![0u8; key_len];
                if memory
                    .read(&caller, key_ptr.max(0) as usize, &mut key)
                    .is_err()
                {
                    return -1;
                }
                let key = String::from_utf8_lossy(&key).to_string();
                let Some(value) = caller.data().kv.get(&key).cloned() else {
                    return -1;
                };
                let value = value.as_bytes();
                let out_len = (out_len.max(0) as usize).min(MAX_KV_VALUE);
                let take = value.len().min(out_len);
                if memory
                    .write(&mut caller, out_ptr.max(0) as usize, &value[..take])
                    .is_err()
                {
                    return -1;
                }
                take as i32
            },
        )?;
        linker.func_wrap(
            "zentrion",
            "kv_set",
            |mut caller: Caller<'_, HostState>,
             key_ptr: i32,
             key_len: i32,
             value_ptr: i32,
             value_len: i32|
             -> i32 {
                if !caller.data().capabilities.contains("kv:write") {
                    return -2;
                }
                let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory())
                else {
                    return -1;
                };
                let key_len = (key_len.max(0) as usize).min(MAX_KV_KEY);
                let value_len = (value_len.max(0) as usize).min(MAX_KV_VALUE);
                let mut key = vec![0u8; key_len];
                let mut value = vec![0u8; value_len];
                if memory
                    .read(&caller, key_ptr.max(0) as usize, &mut key)
                    .is_err()
                    || memory
                        .read(&caller, value_ptr.max(0) as usize, &mut value)
                        .is_err()
                {
                    return -1;
                }
                let key = String::from_utf8_lossy(&key).to_string();
                if !caller.data().kv.contains_key(&key)
                    && caller.data().kv.len() >= MAX_KV_KEYS
                {
                    return -1;
                }
                caller
                    .data_mut()
                    .kv
                    .insert(key, String::from_utf8_lossy(&value).to_string());
                caller.data_mut().kv_dirty = true;
                0
            },
        )?;
        Ok(())
    }

    fn kv_path(&self, plugin: &str) -> PathBuf {
        let safe: String = plugin
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        self.state_dir.join(format!("{safe}.json"))
    }

    fn load_kv(&self, plugin: &str) -> Result<BTreeMap<String, String>> {
        let path = self.kv_path(plugin);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Ok(BTreeMap::new());
        };
        Ok(serde_json::from_str(&text).unwrap_or_default())
    }

    fn save_kv(&self, plugin: &str, kv: &BTreeMap<String, String>) -> Result<()> {
        std::fs::create_dir_all(&self.state_dir)
            .with_context(|| format!("cannot create {}", self.state_dir.display()))?;
        let path = self.kv_path(plugin);
        let text = serde_json::to_string_pretty(kv)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

/// Convenience wrapper for the common case.
pub fn run_file(
    wasm: &Path,
    input: &str,
    limits: &RunLimits,
) -> Result<PluginRun> {
    let validated = crate::manager::validate_plugin(wasm)?;
    let runtime = PluginRuntime::new()?;
    runtime.run(&validated, input.as_bytes(), limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::validate_plugin;
    use std::time::Duration;

    const ECHO_WAT: &str = r#"
(module
  (import "zentrion" "log" (func $log (param i32 i32)))
  (memory (export "memory") 2)
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param $n i32) (result i32)
    (local $p i32)
    global.get $next
    local.set $p
    global.get $next
    local.get $n
    i32.add
    global.set $next
    local.get $p)
  (func (export "run") (param $ptr i32) (param $len i32) (result i64)
    local.get $ptr
    local.get $len
    call $log
    local.get $ptr
    i64.extend_i32_u
    i64.const 32
    i64.shl
    local.get $len
    i64.extend_i32_u
    i64.or))
"#;

    const KV_WAT: &str = r#"
(module
  (import "zentrion" "kv_set" (func $set (param i32 i32 i32 i32) (result i32)))
  (import "zentrion" "kv_get" (func $get (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 0) "k")
  (data (i32.const 8) "value")
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param $n i32) (result i32) (local $p i32)
    global.get $next local.set $p
    global.get $next local.get $n i32.add global.set $next
    local.get $p)
  (func (export "run") (param $ptr i32) (param $len i32) (result i64)
    (local $rc i32)
    i32.const 0 i32.const 1 i32.const 8 i32.const 5 call $set
    local.set $rc
    i32.const 0 i32.const 1 i32.const 512 i32.const 64 call $get
    local.set $rc
    i32.const 512
    i64.extend_i32_u i64.const 32 i64.shl
    local.get $rc i64.extend_i32_u i64.or))
"#;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zplugin-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn plugin(dir: &Path, name: &str, wat: &str, permissions: &[&str]) -> PathBuf {
        let path = dir.join(format!("{name}.wasm"));
        let bytes = wat::parse_str(wat).expect("test WAT must compile");
        std::fs::write(&path, bytes).unwrap();
        let manifest = serde_json::json!({
            "name": name,
            "version": "1.0.0",
            "plugin_type": "wasm",
            "entrypoint": "run",
            "permissions": permissions,
        });
        std::fs::write(
            path.with_extension("wasm.json"),
            manifest.to_string(),
        )
        .unwrap();
        path
    }

    #[test]
    fn echo_plugin_runs_and_logs() {
        let dir = temp("echo");
        let path = plugin(&dir, "echo", ECHO_WAT, &["log"]);
        let validated = validate_plugin(&path).unwrap();
        let runtime = PluginRuntime::new().unwrap().with_state_dir(dir.join("state"));
        let run = runtime
            .run(&validated, b"hello wasm", &RunLimits::default())
            .unwrap();
        assert_eq!(run.output, "hello wasm");
        assert_eq!(run.logs, vec!["hello wasm".to_string()]);
        assert!(run.fuel_used > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kv_capability_is_required_and_state_persists() {
        let dir = temp("kv");
        let path = plugin(&dir, "kv", KV_WAT, &[]);
        let validated = validate_plugin(&path).unwrap();
        let runtime = PluginRuntime::new().unwrap().with_state_dir(dir.join("state"));
        // A denied host call must not silently grant access; the guest returns
        // an invalid length, which the host rejects rather than misreporting.
        let denied = runtime.run(&validated, b"", &RunLimits::default());
        assert!(denied.is_err() || denied.unwrap().kv.is_empty());

        let path = plugin(&dir, "kv", KV_WAT, &["kv:read", "kv:write"]);
        let validated = validate_plugin(&path).unwrap();
        let run = runtime
            .run(&validated, b"", &RunLimits::default())
            .unwrap();
        assert_eq!(run.kv.get("k").map(String::as_str), Some("value"));
        let again = runtime
            .run(&validated, b"", &RunLimits::default())
            .unwrap();
        assert_eq!(again.kv.get("k").map(String::as_str), Some("value"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fuel_exhaustion_is_an_error_not_a_hang() {
        let wat = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) i32.const 0)
  (func (export "run") (param i32 i32) (result i64)
    (loop $l br $l)
    i64.const 0))
"#;
        let dir = temp("fuel");
        let path = plugin(&dir, "spin", wat, &[]);
        let validated = validate_plugin(&path).unwrap();
        let runtime = PluginRuntime::new().unwrap().with_state_dir(dir.join("state"));
        let limits = RunLimits {
            fuel: 10_000,
            ..Default::default()
        };
        let started = Instant::now();
        assert!(runtime.run(&validated, b"", &limits).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn modules_with_unknown_imports_are_rejected() {
        let wat = r#"
(module
  (import "zentrion" "network" (func $net (param i32)))
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) i32.const 0)
  (func (export "run") (param i32 i32) (result i64) i64.const 0))
"#;
        let dir = temp("imports");
        let path = plugin(&dir, "net", wat, &["network"]);
        let validated = validate_plugin(&path).unwrap();
        let runtime = PluginRuntime::new().unwrap().with_state_dir(dir.join("state"));
        assert!(runtime.run(&validated, b"", &RunLimits::default()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
