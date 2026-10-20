pub mod ai_bom;
pub mod sast;
pub mod sbom;
pub mod scanner;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner() {
        let key = concat!("AKIA", "7QZ2", "M4X9", "PLK3", "RT8V");
        let content = format!("my secret is {key}");
        let secrets = scanner::scan_for_secrets(&content);
        assert_eq!(secrets, vec![key.to_string()]);
    }

    #[test]
    fn test_sast() {
        let code = "fn main() { unsafe { } }";
        let alerts = sast::check_dangerous_patterns(code);
        assert_eq!(alerts, vec!["unsafe Rust block".to_string()]);
    }

    #[test]
    fn test_sbom() {
        let content =
            "[package]\nname = \"foo\"\nversion = \"1.0.0\"\n\n[dependencies]\nserde = \"1\"";
        let sbom_json = sbom::generate_sbom(content).unwrap();
        assert!(sbom_json.contains("\"foo\""));
        assert!(sbom_json.contains("serde"));
        assert!(!sbom_json.contains("mock-package"));
    }
}
