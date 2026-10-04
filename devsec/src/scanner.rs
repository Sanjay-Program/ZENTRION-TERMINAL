use regex::Regex;

pub fn scan_for_secrets(content: &str) -> Vec<&str> {
    let re = Regex::new(r"(AKIA[0-9A-Z]{16}|sk-proj-[A-Za-z0-9-_]{48,}|xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]+)").unwrap();
    re.find_iter(content).map(|m| m.as_str()).collect()
}
