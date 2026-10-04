use anyhow::Result;
use z_ai::gateway::AIGateway;
use z_ai::models::{ChatMessage, ChatRequest};
use z_ai::provider::provider_from_env;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum AgentRole {
    Planner,
    Operator,
    SecurityReviewer,
    Documenter,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum AgentHandoff {
    None,
    ToSecurityReviewer,
    ToDocumenter,
    ToOperator,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AgentToolPolicy {
    pub allow_shell: bool,
    pub allow_network: bool,
    pub allow_filesystem_write: bool,
    pub allowed_tools: Vec<String>,
}

impl AgentToolPolicy {
    pub fn conservative() -> Self {
        Self {
            allow_shell: false,
            allow_network: false,
            allow_filesystem_write: false,
            allowed_tools: vec![
                "z doctor".to_string(),
                "z status".to_string(),
                "z search".to_string(),
                "z info".to_string(),
                "z bundle plan".to_string(),
            ],
        }
    }

    pub fn permits(&self, tool: &str) -> bool {
        self.allowed_tools
            .iter()
            .any(|allowed| tool.starts_with(allowed))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AgentProfile {
    pub name: String,
    pub role: AgentRole,
    pub model: String,
    pub max_iterations: usize,
    pub tool_policy: AgentToolPolicy,
    pub handoffs: Vec<AgentHandoff>,
}

impl AgentProfile {
    pub fn security_lab_planner() -> Self {
        Self {
            name: "security-lab-planner".to_string(),
            role: AgentRole::Planner,
            model: "default".to_string(),
            max_iterations: 10,
            tool_policy: AgentToolPolicy::conservative(),
            handoffs: vec![
                AgentHandoff::ToSecurityReviewer,
                AgentHandoff::ToOperator,
                AgentHandoff::ToDocumenter,
            ],
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AgentTraceEvent {
    pub step: usize,
    pub role: AgentRole,
    pub event: String,
    pub detail: String,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AgentTrace {
    pub events: Vec<AgentTraceEvent>,
}

impl AgentTrace {
    pub fn push(&mut self, role: AgentRole, event: impl Into<String>, detail: impl Into<String>) {
        self.events.push(AgentTraceEvent {
            step: self.events.len() + 1,
            role,
            event: event.into(),
            detail: detail.into(),
        });
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GuardrailDecision {
    pub allowed: bool,
    pub reason: String,
}

pub fn check_tool_guardrail(policy: &AgentToolPolicy, requested_tool: &str) -> GuardrailDecision {
    if policy.permits(requested_tool) {
        return GuardrailDecision {
            allowed: true,
            reason: "tool is present in the agent allowlist".to_string(),
        };
    }

    GuardrailDecision {
        allowed: false,
        reason: format!(
            "tool `{requested_tool}` is not allowlisted; require explicit user approval or a policy update"
        ),
    }
}

pub struct AgentRuntime {
    memory_limit: usize,
    profile: AgentProfile,
}

impl AgentRuntime {
    pub fn new(memory_limit: usize) -> Self {
        Self {
            memory_limit,
            profile: AgentProfile::security_lab_planner(),
        }
    }

    pub fn with_profile(memory_limit: usize, profile: AgentProfile) -> Self {
        Self {
            memory_limit,
            profile,
        }
    }

    pub fn profile(&self) -> &AgentProfile {
        &self.profile
    }

    pub async fn start(&self) -> Result<()> {
        loop {
            // loop for checking memory and limits
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            self.check_limits()?;
        }
    }

    fn check_limits(&self) -> Result<()> {
        let _memory_limit = self.memory_limit;
        Ok(())
    }
}

pub async fn run_autonomous(goal: &str) -> Result<()> {
    run_autonomous_with_profile(goal, AgentProfile::security_lab_planner())
        .await
        .map(|_| ())
}

pub async fn run_autonomous_with_profile(goal: &str, profile: AgentProfile) -> Result<AgentTrace> {
    let gateway = AIGateway::new(provider_from_env()?);
    let mut trace = AgentTrace::default();
    let mut iterations = 0;
    let max_iterations = profile.max_iterations;
    let model = std::env::var("ZENTRION_AI_MODEL").unwrap_or_else(|_| profile.model.clone());
    trace.push(profile.role.clone(), "goal.received", goal);

    let mut messages = vec![
        ChatMessage {
            role: "system".to_string(),
            content: format!(
                "You are the {} agent. Reply with a plan or safe action. If done, output DONE. Allowed tools: {}.",
                profile.name,
                profile.tool_policy.allowed_tools.join(", ")
            ),
        },
        ChatMessage {
            role: "user".to_string(),
            content: goal.to_string(),
        }
    ];

    while iterations < max_iterations {
        let req = ChatRequest {
            model: model.clone(),
            messages: messages.clone(),
            temperature: Some(0.7),
        };

        let response = gateway.chat(req).await?;
        if let Some(choice) = response.choices.first() {
            let reply = &choice.message.content;
            trace.push(profile.role.clone(), "model.reply", reply.clone());

            if reply.contains("DONE") {
                trace.push(profile.role.clone(), "run.completed", "model reported DONE");
                return Ok(trace);
            }

            let requested_tool = infer_requested_tool(reply);
            let guardrail = check_tool_guardrail(&profile.tool_policy, &requested_tool);
            trace.push(
                AgentRole::SecurityReviewer,
                "guardrail.tool",
                format!("{}: {}", requested_tool, guardrail.reason),
            );

            if !guardrail.allowed {
                messages.push(ChatMessage {
                    role: "user".to_string(),
                    content: format!("Observation: blocked by guardrail. {}", guardrail.reason),
                });
                iterations += 1;
                continue;
            }

            messages.push(choice.message.clone());
            messages.push(ChatMessage {
                role: "user".to_string(),
                content: format!("Observation: `{requested_tool}` was approved for a dry-run style planning step. Proceed."),
            });
        }

        iterations += 1;
    }

    Err(anyhow::anyhow!(
        "Max iterations ({}) reached without completion",
        max_iterations
    ))
}

fn infer_requested_tool(reply: &str) -> String {
    for candidate in [
        "z bundle plan",
        "z search",
        "z info",
        "z status",
        "z doctor",
    ] {
        if reply.contains(candidate) {
            return candidate.to_string();
        }
    }
    "agent-plan".to_string()
}
