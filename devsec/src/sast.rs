//! Lightweight SAST heuristics. Line-oriented and fast; intended to highlight
//! review targets, not to prove absence or presence of vulnerabilities.

pub fn check_dangerous_patterns(code: &str) -> Vec<String> {
    let patterns: &[(&str, &str)] = &[
        ("eval(", "dynamic code evaluation"),
        ("exec(", "dynamic code execution"),
        ("os.system(", "shell execution via os.system"),
        ("subprocess.call(", "subprocess execution"),
        ("subprocess.run(", "subprocess execution"),
        ("shell=True", "shell interpretation enabled"),
        ("pickle.loads(", "unsafe deserialization"),
        ("yaml.load(", "unsafe YAML load (use safe_load)"),
        ("verify=False", "TLS verification disabled"),
        ("unsafe {", "unsafe Rust block"),
        ("Command::new(\"sh\")", "explicit shell process"),
        ("innerHTML", "HTML injection sink"),
        ("dangerouslySetInnerHTML", "HTML injection sink"),
    ];
    let mut alerts = Vec::new();
    for (needle, label) in patterns {
        if code.contains(needle) && !alerts.iter().any(|a| a == label) {
            alerts.push((*label).to_string());
        }
    }
    alerts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_unsafe_patterns() {
        let alerts = check_dangerous_patterns("eval(x); unsafe { }");
        assert!(alerts.iter().any(|a| a.contains("dynamic code")));
        assert!(alerts.iter().any(|a| a.contains("unsafe")));
    }

    #[test]
    fn clean_code_has_no_alerts() {
        assert!(check_dangerous_patterns("fn main() { println!(\"ok\"); }").is_empty());
    }
}
