pub fn check_dangerous_patterns(code: &str) -> Vec<&str> {
    let mut alerts = Vec::new();
    if code.contains("eval(") {
        alerts.push("eval()");
    }
    if code.contains("system(") {
        alerts.push("system()");
    }
    if code.contains("unsafe {") {
        alerts.push("unsafe {");
    }
    alerts
}
