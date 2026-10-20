//! Shell integration generation and launch planning.
//!
//! Scripts are generated into `<data>/shell-integration/<version>/` with a
//! checksum manifest. They are sourced *after* the user's own configuration so
//! existing prompts (Starship, Oh My Posh, …) keep working.
//!
//! Command text is captured by the shell hook into a small file named by
//! `ZENTRION_CMD_FILE`; the terminal never scrapes the screen when hooks are
//! available. Bash cannot report a fully parsed pipeline (its DEBUG trap sees
//! each simple command), so bash command text is labelled best-effort.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const INTEGRATION_VERSION: &str = "1";
pub const MAX_COMMAND_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellKind {
    Bash,
    Zsh,
    Fish,
    Pwsh,
    Nushell,
    Other,
}

impl ShellKind {
    pub fn parse(value: &str) -> Self {
        // Handle Windows separators even when running tests on Unix.
        let normalized = value.replace('\\', "/");
        let name = normalized
            .rsplit('/')
            .next()
            .unwrap_or(value)
            .to_ascii_lowercase();
        let name = name.strip_suffix(".exe").unwrap_or(&name);
        match name {
            "bash" | "rbash" => Self::Bash,
            "zsh" => Self::Zsh,
            "fish" => Self::Fish,
            "pwsh" | "powershell" => Self::Pwsh,
            "nu" | "nushell" => Self::Nushell,
            _ => Self::Other,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::Pwsh => "pwsh",
            Self::Nushell => "nushell",
            Self::Other => "shell",
        }
    }

    pub fn script(self) -> Option<&'static str> {
        match self {
            Self::Bash => Some("bash.bashrc"),
            Self::Zsh => Some("zsh.zshrc"),
            Self::Fish => Some("fish.fish"),
            Self::Pwsh => Some("pwsh.ps1"),
            Self::Nushell => Some("nushell.nu"),
            Self::Other => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub generated_at: DateTime<Utc>,
    pub files: Vec<ManifestFile>,
}

/// A fully resolved launch plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub shell: ShellKind,
    pub integration: bool,
    pub notes: Vec<String>,
}

const BASH_RC: &str = r#"# Zentrion shell integration (generated; do not edit).
# Source the user's configuration first so prompts/aliases keep working.
if [ -f "$HOME/.bashrc" ]; then . "$HOME/.bashrc"; fi
__zentrion_precmd() {
  local __zentrion_status="$1"
  if [ -n "${__ZENTRION_BLOCK:-}" ]; then
    printf '\033]133;D;%s\007' "$__zentrion_status"
    unset __ZENTRION_BLOCK
  fi
  printf '\033]133;A\007\033]9;9;%s\007' "$PWD"
}
__zentrion_preexec() {
  [ "${__ZENTRION_READY:-0}" = "1" ] || return
  [ -n "${COMP_LINE:-}" ] && return
  [ -n "${__ZENTRION_IN_PROMPT:-}" ] && return
  case "$BASH_COMMAND" in
    __zentrion_*|__ZENTRION_*|PROMPT_COMMAND=*|PS0=*) return;;
  esac
  __ZENTRION_BLOCK=1
  if [ -n "${ZENTRION_CMD_FILE:-}" ]; then
    printf '%s' "$BASH_COMMAND" > "$ZENTRION_CMD_FILE" 2>/dev/null
  fi
  printf '\033]133;B\007\033]133;C\007'
}
__zentrion_prompt_command() {
  local __zentrion_status=$?
  __ZENTRION_IN_PROMPT=1
  __zentrion_precmd "$__zentrion_status"
  if [ -n "${ZENTRION_PROMPT_COMMAND_ORIG:-}" ]; then
    eval "$ZENTRION_PROMPT_COMMAND_ORIG"
  fi
  unset __ZENTRION_IN_PROMPT
}
ZENTRION_PROMPT_COMMAND_ORIG="${PROMPT_COMMAND:-}"
PROMPT_COMMAND="__zentrion_prompt_command"
trap '__zentrion_preexec' DEBUG
__ZENTRION_READY=1
"#;

const ZSH_RC: &str = r#"# Zentrion shell integration (generated; do not edit).
if [ -f "${ZENTRION_ORIG_ZDOTDIR:-$HOME}/.zshrc" ]; then
  source "${ZENTRION_ORIG_ZDOTDIR:-$HOME}/.zshrc"
fi
autoload -Uz add-zsh-hook
__zentrion_precmd() {
  local __zentrion_status=$?
  if [ -n "${__ZENTRION_BLOCK:-}" ]; then
    print -n "\033]133;D;${__zentrion_status}\007"
    unset __ZENTRION_BLOCK
  fi
  print -n "\033]133;A\007\033]9;9;${PWD}\007"
}
__zentrion_preexec() {
  __ZENTRION_BLOCK=1
  if [ -n "${ZENTRION_CMD_FILE:-}" ]; then
    print -rn -- "$1" > "$ZENTRION_CMD_FILE" 2>/dev/null
  fi
  print -n "\033]133;B\007\033]133;C\007"
}
add-zsh-hook precmd __zentrion_precmd
add-zsh-hook preexec __zentrion_preexec
"#;

const FISH_INIT: &str = r#"# Zentrion shell integration (generated; do not edit).
function __zentrion_preexec --on-event fish_preexec
    if set -q ZENTRION_CMD_FILE
        printf '%s' $argv[1] > $ZENTRION_CMD_FILE 2>/dev/null
    end
    printf '\e]133;B\a\e]133;C\a'
end
function __zentrion_postexec --on-event fish_postexec
    printf '\e]133;D;%s\a' $status
end
function __zentrion_prompt --on-event fish_prompt
    printf '\e]133;A\a\e]9;9;%s\a' $PWD
end
"#;

const PWSH_SCRIPT: &str = r#"# Zentrion shell integration (generated; do not edit).
$global:__zentrion_block = $false
$global:__zentrion_orig_prompt = $function:prompt
function global:prompt {
    $code = $global:LASTEXITCODE
    if ($global:__zentrion_block) {
        Write-Host -NoNewline "`e]133;D;$code`a"
        $global:__zentrion_block = $false
    }
    Write-Host -NoNewline "`e]133;A`a`e]9;9;$($PWD.Path)`a"
    if ($null -ne $global:__zentrion_orig_prompt) { & $global:__zentrion_orig_prompt }
}
if (Get-Module -ListAvailable -Name PSReadLine) {
    Set-PSReadLineKeyHandler -Key Enter -ScriptBlock {
        $line = $null; $cursor = $null
        [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)
        if ($line) {
            if ($env:ZENTRION_CMD_FILE) {
                Set-Content -NoNewline -Path $env:ZENTRION_CMD_FILE -Value $line
            }
            Write-Host -NoNewline "`e]133;B`a`e]133;C`a"
            $global:__zentrion_block = $true
        }
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
    }
}
"#;

const NUSHELL_SCRIPT: &str = r#"# Zentrion shell integration (generated; do not edit).
# Nushell hooks are version-dependent; command text is best effort.
$env.config.hooks.pre_prompt = ($env.config.hooks.pre_prompt | append {||
    print -n $"\e]133;D;($env.LAST_EXIT_CODE)\a\e]133;A\a\e]9;9;($env.PWD)\a"
})
$env.config.hooks.pre_execution = ($env.config.hooks.pre_execution | append {||
    print -n "\e]133;B\a\e]133;C\a"
})
"#;

/// Generate scripts into `dir` if absent or out of date. Returns the manifest.
pub fn ensure_scripts(dir: &Path) -> std::io::Result<Manifest> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let files = [
        ("bash.bashrc", BASH_RC),
        ("zsh/.zshrc", ZSH_RC),
        ("fish.fish", FISH_INIT),
        ("pwsh.ps1", PWSH_SCRIPT),
        ("nushell.nu", NUSHELL_SCRIPT),
    ];
    let mut manifest_files = Vec::new();
    for (name, contents) in files {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let needs_write = std::fs::read_to_string(&path)
            .map(|existing| existing != contents)
            .unwrap_or(true);
        if needs_write {
            std::fs::write(&path, contents)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
        manifest_files.push(ManifestFile {
            name: name.to_string(),
            sha256: sha256_hex(contents.as_bytes()),
            bytes: contents.len() as u64,
        });
    }
    let manifest = Manifest {
        version: INTEGRATION_VERSION.to_string(),
        generated_at: Utc::now(),
        files: manifest_files,
    };
    let text = serde_json::to_string_pretty(&manifest)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(dir.join("manifest.json"), text)?;
    Ok(manifest)
}

/// Default integration directory under the user data dir.
pub fn default_integration_dir() -> Option<PathBuf> {
    z_core::config::user_data_dir().map(|dir| {
        dir.join("shell-integration")
            .join(format!("v{INTEGRATION_VERSION}"))
    })
}

/// Resolve a configured integration mode against the actual shell.
pub fn resolve_kind(shell: &str, configured: z_config::ShellIntegration) -> (ShellKind, bool) {
    let detected = ShellKind::parse(shell);
    use z_config::ShellIntegration as Mode;
    match configured {
        Mode::Off => (detected, false),
        Mode::Auto => (detected, detected != ShellKind::Other),
        Mode::Bash => (ShellKind::Bash, true),
        Mode::Zsh => (ShellKind::Zsh, true),
        Mode::Fish => (ShellKind::Fish, true),
        Mode::Pwsh => (ShellKind::Pwsh, true),
        Mode::Nushell => (ShellKind::Nushell, true),
    }
}

/// Build the launch plan for a shell with integration enabled.
pub fn plan_launch(
    shell: &str,
    configured: z_config::ShellIntegration,
    integration_dir: Option<&Path>,
    session_id: &str,
    command_file: &Path,
    extra_env: &[(String, String)],
    login: bool,
) -> Launch {
    let (kind, integration) = resolve_kind(shell, configured);
    let mut args = Vec::new();
    let mut env = vec![
        ("ZENTRION_SESSION_ID".to_string(), session_id.to_string()),
        (
            "ZENTRION_CMD_FILE".to_string(),
            command_file.display().to_string(),
        ),
        (
            "TERM".to_string(),
            std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
        ),
    ];
    env.extend(extra_env.iter().cloned());
    let mut notes = Vec::new();
    let mut active = integration;

    if integration {
        let Some(dir) = integration_dir else {
            notes.push("shell integration requested but no data directory is available".into());
            return Launch {
                program: shell.to_string(),
                args,
                env,
                shell: kind,
                integration: false,
                notes,
            };
        };
        if let Err(error) = ensure_scripts(dir) {
            notes.push(format!("cannot write shell integration scripts: {error}"));
            return Launch {
                program: shell.to_string(),
                args,
                env,
                shell: kind,
                integration: false,
                notes,
            };
        }
        match kind {
            ShellKind::Bash => {
                // Bash requires the rcfile as a separate argument; `--rcfile=`
                // is rejected by some builds (and prints usage + exits).
                args.push("--rcfile".into());
                args.push(dir.join("bash.bashrc").display().to_string());
                if login {
                    args.push("-l".into());
                }
            }
            ShellKind::Zsh => {
                // ZDOTDIR trick: the generated .zshrc sources the real one.
                env.push((
                    "ZENTRION_ORIG_ZDOTDIR".to_string(),
                    std::env::var("ZDOTDIR").unwrap_or_else(|_| {
                        z_core::config::home_dir()
                            .map(|home| home.display().to_string())
                            .unwrap_or_default()
                    }),
                ));
                env.push(("ZDOTDIR".to_string(), dir.join("zsh").display().to_string()));
                if login {
                    args.push("-l".into());
                }
            }
            ShellKind::Fish => {
                args.push("--init-command".into());
                args.push(format!("source {}", dir.join("fish.fish").display()));
            }
            ShellKind::Pwsh => {
                args.push("-NoExit".into());
                args.push("-Command".into());
                args.push(format!(". '{}'", dir.join("pwsh.ps1").display()));
            }
            ShellKind::Nushell => {
                args.push("--config".into());
                args.push(dir.join("nushell.nu").display().to_string());
                notes.push(
                    "nushell integration is best effort and overrides --config; review it first"
                        .into(),
                );
            }
            ShellKind::Other => {
                active = false;
                notes.push(format!(
                    "shell `{shell}` has no integration hooks; blocks will be heuristic"
                ));
            }
        }
    } else {
        notes.push("shell integration disabled; no OSC 133 marks will be emitted".into());
    }

    Launch {
        program: shell.to_string(),
        args,
        env,
        shell: kind,
        integration: active,
        notes,
    }
}

/// Read a captured command written by the shell hook.
pub fn read_captured_command(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() == 0 || metadata.len() > MAX_COMMAND_BYTES as u64 {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    let text = text.trim_end_matches(['\r', '\n']).to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zentrion-zsession-int-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn scripts_and_manifest_are_written() {
        let dir = temp_dir("scripts");
        let manifest = ensure_scripts(&dir).unwrap();
        assert_eq!(manifest.files.len(), 5);
        assert!(dir.join("bash.bashrc").exists());
        assert!(dir.join("zsh/.zshrc").exists());
        assert!(dir.join("manifest.json").exists());
        let text = std::fs::read_to_string(dir.join("bash.bashrc")).unwrap();
        assert!(text.contains("133;A"));
        assert!(text.contains("133;D"));
        // Idempotent.
        let again = ensure_scripts(&dir).unwrap();
        assert_eq!(again.files, manifest.files);
    }

    #[test]
    fn shell_detection_handles_paths_and_windows() {
        assert_eq!(ShellKind::parse("/bin/bash"), ShellKind::Bash);
        assert_eq!(
            ShellKind::parse("C:\\Program Files\\PowerShell\\pwsh.exe"),
            ShellKind::Pwsh
        );
        assert_eq!(ShellKind::parse("nu"), ShellKind::Nushell);
        assert_eq!(ShellKind::parse("/bin/dash"), ShellKind::Other);
    }

    #[test]
    fn bash_plan_uses_rcfile_not_user_config_edit() {
        let dir = temp_dir("plan");
        let launch = plan_launch(
            "/bin/bash",
            z_config::ShellIntegration::Auto,
            Some(&dir),
            "s_1",
            &dir.join("cmd"),
            &[],
            false,
        );
        assert!(launch.integration);
        assert_eq!(launch.args[0], "--rcfile");
        assert!(launch.args[1].ends_with("bash.bashrc"));
        assert!(launch.env.iter().any(|(k, _)| k == "ZENTRION_CMD_FILE"));
        assert!(dir.join("bash.bashrc").exists());
    }

    #[test]
    fn off_disables_integration() {
        let dir = temp_dir("off");
        let launch = plan_launch(
            "/bin/bash",
            z_config::ShellIntegration::Off,
            Some(&dir),
            "s_1",
            &dir.join("cmd"),
            &[],
            false,
        );
        assert!(!launch.integration);
        assert!(launch.args.is_empty());
    }

    #[test]
    fn captured_command_is_bounded_and_trimmed() {
        let dir = temp_dir("cmd");
        let path = dir.join("cmd");
        std::fs::write(&path, "cargo test\n").unwrap();
        assert_eq!(read_captured_command(&path).as_deref(), Some("cargo test"));
        std::fs::write(&path, "").unwrap();
        assert!(read_captured_command(&path).is_none());
    }
}
