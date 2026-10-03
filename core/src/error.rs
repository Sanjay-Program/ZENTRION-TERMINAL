//! Structured error model (04-CORE-RUNTIME).
//!
//! Codes: `ZEN-<AREA>-<NNNN>`. Every user-facing error carries a plain
//! `human` message, optional `remediation`, and a machine `detail`.

use std::fmt;

/// Error areas per 04-CORE-RUNTIME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    Cfg,
    Cor,
    Pol,
    Cap,
    Exe,
    Sbx,
    Sec,
    Net,
    Fs,
    Pr,
    Ai,
    Agt,
    Mcp,
    Reg,
    Upd,
    Aud,
}

impl Area {
    pub fn as_str(&self) -> &'static str {
        match self {
            Area::Cfg => "CFG",
            Area::Cor => "COR",
            Area::Pol => "POL",
            Area::Cap => "CAP",
            Area::Exe => "EXE",
            Area::Sbx => "SBX",
            Area::Sec => "SEC",
            Area::Net => "NET",
            Area::Fs => "FS",
            Area::Pr => "PR",
            Area::Ai => "AI",
            Area::Agt => "AGT",
            Area::Mcp => "MCP",
            Area::Reg => "REG",
            Area::Upd => "UPD",
            Area::Aud => "AUD",
        }
    }
}

/// Process exit codes per 05-CLI-SPEC.
pub fn exit_code_for_area(area: Area) -> i32 {
    match area {
        Area::Pol | Area::Cap => 2,
        Area::Sbx => 4,
        Area::Reg | Area::Net => 6,
        _ => 7,
    }
}

/// Structured Zentrion error.
///
/// Kept deliberately small (the `Err` variant of every `ZenResult` pays for
/// its size) — optional text and detail live behind a single boxed payload.
#[derive(Debug, Clone)]
pub struct ZenError {
    pub area: Area,
    pub code: String,
    pub human: String,
    pub extra: Option<Box<ErrorExtra>>,
}

/// Optional, less frequently used error fields.
#[derive(Debug, Clone, Default)]
pub struct ErrorExtra {
    pub remediation: Option<String>,
    pub detail: Option<serde_json::Value>,
    pub audit_id: Option<String>,
    pub cause: Option<ZenError>,
}

pub type ZenResult<T> = Result<T, ZenError>;

impl ZenError {
    pub fn new(area: Area, code_num: u16, human: impl Into<String>) -> Self {
        Self {
            area,
            code: format!("ZEN-{}-{:04}", area.as_str(), code_num),
            human: human.into(),
            extra: None,
        }
    }

    fn extra_mut(&mut self) -> &mut ErrorExtra {
        self.extra
            .get_or_insert_with(|| Box::new(ErrorExtra::default()))
    }

    pub fn remediation(&self) -> Option<&str> {
        self.extra.as_ref().and_then(|e| e.remediation.as_deref())
    }

    pub fn cause(&self) -> Option<&ZenError> {
        self.extra.as_ref().and_then(|e| e.cause.as_ref())
    }

    pub fn with_remediation(mut self, r: impl Into<String>) -> Self {
        let r = r.into();
        self.extra_mut().remediation = Some(r);
        self
    }

    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.extra_mut().detail = Some(detail);
        self
    }

    pub fn with_audit_id(mut self, id: impl Into<String>) -> Self {
        let id = id.into();
        self.extra_mut().audit_id = Some(id);
        self
    }

    pub fn with_cause(mut self, e: ZenError) -> Self {
        self.extra_mut().cause = Some(e);
        self
    }

    /// Process exit code per 05-CLI-SPEC.
    pub fn exit_code(&self) -> i32 {
        exit_code_for_area(self.area)
    }
}

impl fmt::Display for ZenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code, self.human)?;
        if let Some(e) = &self.extra {
            if let Some(r) = &e.remediation {
                write!(f, "\n  Suggested action: {r}")?;
            }
            if let Some(c) = &e.cause {
                write!(f, "\n  Caused by: {c}")?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for ZenError {}

impl From<std::io::Error> for ZenError {
    fn from(e: std::io::Error) -> Self {
        ZenError::new(Area::Fs, 1000, format!("filesystem error: {e}"))
            .with_remediation("Check file permissions and paths.")
    }
}

impl From<serde_yaml::Error> for ZenError {
    fn from(e: serde_yaml::Error) -> Self {
        ZenError::new(Area::Cfg, 2000, format!("YAML parse error: {e}"))
            .with_remediation("Check the YAML file for syntax errors.")
    }
}

impl From<serde_json::Error> for ZenError {
    fn from(e: serde_json::Error) -> Self {
        ZenError::new(Area::Cfg, 2001, format!("JSON parse error: {e}"))
    }
}
