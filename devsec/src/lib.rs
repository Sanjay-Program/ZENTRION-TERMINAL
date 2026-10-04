pub mod ai_bom;
pub mod sast;
pub mod sbom;
pub mod scanner;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner() {
        let content = "my secret is AKIAIOSFODNN7EXAMPLE";
        let secrets = scanner::scan_for_secrets(content);
        assert_eq!(secrets, vec!["AKIAIOSFODNN7EXAMPLE"]);
    }

    #[test]
    fn test_sast() {
        let code = "fn main() { unsafe { } }";
        let alerts = sast::check_dangerous_patterns(code);
        assert_eq!(alerts, vec!["unsafe {"]);
    }

    #[test]
    fn test_sbom() {
        let content = "[package]\nname = \"foo\"";
        let sbom_json = sbom::generate_sbom(content).unwrap();
        assert!(sbom_json.contains("mock-package"));
    }
}
