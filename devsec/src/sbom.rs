//! Manifest-derived software bill of materials.
//!
//! Supports Cargo.toml and package.json. The output is intentionally simple
//! and deterministic so it can be diffed in CI.

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct SbomPackage {
    pub name: String,
    pub version: String,
    pub scope: String,
    pub ecosystem: String,
}

#[derive(Debug, Serialize)]
pub struct Sbom {
    pub format: String,
    pub name: String,
    pub version: String,
    pub packages: Vec<SbomPackage>,
}

pub fn generate_sbom(content: &str) -> Result<String, anyhow::Error> {
    let trimmed = content.trim_start();
    let sbom = if trimmed.starts_with('{') {
        parse_package_json(content)?
    } else {
        parse_cargo_toml(content)
    };
    Ok(serde_json::to_string_pretty(&sbom)?)
}

fn parse_cargo_toml(content: &str) -> Sbom {
    let mut name = "unknown".to_string();
    let mut version = "0.0.0".to_string();
    let mut packages = Vec::new();
    let mut section = String::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line.trim_matches(&['[', ']'][..]).to_string();
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        if section == "package" || section == "workspace.package" {
            match key {
                "name" if section == "package" => name = value.to_string(),
                "version" => version = value.to_string(),
                _ => {}
            }
        } else if section.ends_with("dependencies") || section == "workspace.dependencies" {
            let scope = if section.contains("dev") {
                "dev"
            } else if section.contains("build") {
                "build"
            } else {
                "runtime"
            };
            packages.push(SbomPackage {
                name: key.to_string(),
                version: value.to_string(),
                scope: scope.to_string(),
                ecosystem: "cargo".to_string(),
            });
        }
    }
    // Deduplicate by (name, scope), keeping the first occurrence.
    packages.sort_by(|a, b| (&a.name, &a.scope).cmp(&(&b.name, &b.scope)));
    packages.dedup_by(|a, b| a.name == b.name && a.scope == b.scope);

    if name == "unknown" && content.contains("[workspace]") {
        name = "workspace".to_string();
    }
    Sbom {
        format: "zentrion.sbom/v1".into(),
        name,
        version,
        packages,
    }
}

fn parse_package_json(content: &str) -> Result<Sbom, anyhow::Error> {
    let value: Value = serde_json::from_str(content)?;
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("0.0.0")
        .to_string();
    let mut packages = Vec::new();
    for (field, scope) in [
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("peerDependencies", "peer"),
        ("optionalDependencies", "optional"),
    ] {
        if let Some(deps) = value.get(field).and_then(Value::as_object) {
            for (dep, dep_version) in deps {
                packages.push(SbomPackage {
                    name: dep.clone(),
                    version: dep_version.as_str().unwrap_or("*").to_string(),
                    scope: scope.to_string(),
                    ecosystem: "npm".to_string(),
                });
            }
        }
    }
    packages.sort_by(|a, b| (&a.name, &a.scope).cmp(&(&b.name, &b.scope)));
    Ok(Sbom {
        format: "zentrion.sbom/v1".into(),
        name,
        version,
        packages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cargo_dependencies() {
        let content = "[package]\nname = \"demo\"\nversion = \"1.2.3\"\n\n[dependencies]\nserde = \"1.0\"\nregex = \"1\"\n\n[dev-dependencies]\ntempfile = \"3\"\n";
        let sbom: Value = serde_json::from_str(&generate_sbom(content).unwrap()).unwrap();
        assert_eq!(sbom["name"], "demo");
        assert_eq!(sbom["packages"].as_array().unwrap().len(), 3);
        assert!(sbom["packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "serde" && p["scope"] == "runtime"));
    }

    #[test]
    fn parses_package_json() {
        let content = r#"{"name":"web","version":"0.1.0","dependencies":{"react":"^18"},"devDependencies":{"vite":"^5"}}"#;
        let sbom: Value = serde_json::from_str(&generate_sbom(content).unwrap()).unwrap();
        assert_eq!(sbom["name"], "web");
        assert_eq!(sbom["packages"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn empty_manifest_is_not_faked() {
        let sbom: Value = serde_json::from_str(&generate_sbom("").unwrap()).unwrap();
        assert_eq!(sbom["packages"].as_array().unwrap().len(), 0);
        assert_eq!(sbom["name"], "unknown");
    }
}
