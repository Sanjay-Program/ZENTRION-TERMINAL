//! Lightweight symbol extraction.
//!
//! This is deliberately a lexer-level approximation, not a tree-sitter parse.
//! It extracts declarations with line numbers for retrieval; it does not claim
//! semantic accuracy and never guesses call graphs. The index records this so
//! the UI can label symbol results as approximate.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub line: usize,
}

pub fn language_for(path: &str) -> &'static str {
    let extension = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match extension.as_str() {
        "rs" => "rust",
        "ts" | "tsx" | "mts" | "cts" => "typescript",
        "js" | "jsx" | "mjs" | "cjs" => "javascript",
        "py" | "pyi" => "python",
        "go" => "go",
        "java" => "java",
        "kt" | "kts" => "kotlin",
        "c" | "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => "cpp",
        "cs" => "csharp",
        "rb" => "ruby",
        "php" => "php",
        "sh" | "bash" | "zsh" => "shell",
        "fish" => "fish",
        "ps1" => "powershell",
        "toml" => "toml",
        "yaml" | "yml" => "yaml",
        "json" => "json",
        "md" | "mdx" => "markdown",
        "sql" => "sql",
        "html" | "htm" => "html",
        "css" | "scss" => "css",
        "lua" => "lua",
        "swift" => "swift",
        "zig" => "zig",
        _ => "text",
    }
}

pub fn extract_symbols(path: &str, content: &str) -> Vec<Symbol> {
    let language = language_for(path);
    let mut symbols = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let number = index + 1;
        if line.len() > 512 {
            continue;
        }
        let trimmed = line.trim_start();
        let hash_comment = trimmed.starts_with('#')
            && matches!(
                language,
                "python" | "shell" | "fish" | "powershell" | "toml" | "yaml" | "text"
            );
        if trimmed.starts_with("//") || hash_comment {
            continue;
        }
        match language {
            "rust" => rust_symbol(trimmed, number, &mut symbols),
            "typescript" | "javascript" => js_symbol(trimmed, number, &mut symbols),
            "python" => python_symbol(trimmed, number, &mut symbols),
            "go" => go_symbol(trimmed, number, &mut symbols),
            "markdown" => {
                if let Some(title) = trimmed.strip_prefix('#') {
                    let title = title.trim_start_matches('#').trim();
                    if !title.is_empty() {
                        symbols.push(Symbol {
                            name: title.to_string(),
                            kind: "heading".into(),
                            line: number,
                        });
                    }
                }
            }
            "shell" | "fish" | "powershell" => {
                for prefix in ["function ", "fn ", "func "] {
                    if let Some(rest) = trimmed.strip_prefix(prefix) {
                        let name = rest
                            .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-'))
                            .next()
                            .unwrap_or("");
                        if !name.is_empty() {
                            symbols.push(Symbol {
                                name: name.to_string(),
                                kind: "function".into(),
                                line: number,
                            });
                        }
                    }
                }
            }
            "sql" => {
                let upper = trimmed.to_ascii_uppercase();
                if upper.starts_with("CREATE TABLE") || upper.starts_with("CREATE VIEW") {
                    if let Some(name) = trimmed.split_whitespace().nth(2) {
                        symbols.push(Symbol {
                            name: name
                                .trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
                                .to_string(),
                            kind: if upper.starts_with("CREATE VIEW") {
                                "view"
                            } else {
                                "table"
                            }
                            .into(),
                            line: number,
                        });
                    }
                }
            }
            _ => {}
        }
        if symbols.len() >= 50_000 {
            break;
        }
    }
    symbols
}

fn rust_symbol(line: &str, number: usize, out: &mut Vec<Symbol>) {
    let mut rest = line;
    // Visibility and qualifiers.
    for prefix in [
        "pub(crate) ",
        "pub(super) ",
        "pub ",
        "async ",
        "unsafe ",
        "const ",
    ] {
        while let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped;
        }
    }
    for (keyword, kind) in [
        ("fn ", "function"),
        ("struct ", "struct"),
        ("enum ", "enum"),
        ("trait ", "trait"),
        ("impl ", "impl"),
        ("mod ", "module"),
        ("type ", "type"),
        ("macro_rules! ", "macro"),
        ("union ", "union"),
    ] {
        if let Some(after) = rest.strip_prefix(keyword) {
            let name = after
                .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
                .next()
                .unwrap_or("")
                .trim();
            if !name.is_empty() && name.len() < 200 {
                out.push(Symbol {
                    name: name.to_string(),
                    kind: kind.to_string(),
                    line: number,
                });
            }
            return;
        }
    }
}

fn js_symbol(line: &str, number: usize, out: &mut Vec<Symbol>) {
    let mut rest = line;
    for prefix in [
        "export default ",
        "export async ",
        "export ",
        "async ",
        "function ",
        "class ",
        "interface ",
        "type ",
        "enum ",
        "const ",
        "let ",
        "var ",
    ] {
        while let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped;
        }
    }
    let name = rest
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
        .next()
        .unwrap_or("");
    if name.is_empty() || name.len() > 200 {
        return;
    }
    if (line.contains("function") || line.contains("=>") || line.trim_end().ends_with('{'))
        && (!line.contains('=') || line.contains("=>") || line.contains("function"))
    {
        out.push(Symbol {
            name: name.to_string(),
            kind: "declaration".into(),
            line: number,
        });
    }
}

fn python_symbol(line: &str, number: usize, out: &mut Vec<Symbol>) {
    for (prefix, kind) in [
        ("async def ", "function"),
        ("def ", "function"),
        ("class ", "class"),
    ] {
        if let Some(after) = line.strip_prefix(prefix) {
            let name = after
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or("");
            if !name.is_empty() {
                out.push(Symbol {
                    name: name.to_string(),
                    kind: kind.to_string(),
                    line: number,
                });
            }
        }
    }
}

fn go_symbol(line: &str, number: usize, out: &mut Vec<Symbol>) {
    for (prefix, kind) in [
        ("func ", "function"),
        ("type ", "type"),
        ("var ", "variable"),
        ("const ", "constant"),
    ] {
        if let Some(after) = line.strip_prefix(prefix) {
            let after = after.strip_prefix('(').unwrap_or(after);
            let name = after
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or("");
            if !name.is_empty() {
                out.push(Symbol {
                    name: name.to_string(),
                    kind: kind.to_string(),
                    line: number,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_symbols_have_lines_and_kinds() {
        let source =
            "pub struct Index;\nimpl Index {\n    pub async fn open() {}\n}\nfn main() {}\n";
        let symbols = extract_symbols("src/lib.rs", source);
        assert!(symbols
            .iter()
            .any(|s| s.name == "Index" && s.kind == "struct" && s.line == 1));
        assert!(symbols
            .iter()
            .any(|s| s.name == "Index" && s.kind == "impl" && s.line == 2));
        assert!(symbols.iter().any(|s| s.name == "open" && s.line == 3));
        assert!(symbols
            .iter()
            .any(|s| s.name == "main" && s.kind == "function"));
    }

    #[test]
    fn python_and_markdown_symbols() {
        let python = extract_symbols(
            "x.py",
            "class Foo:\n    async def bar(self):\n        pass\n",
        );
        assert!(python.iter().any(|s| s.name == "Foo" && s.kind == "class"));
        assert!(python
            .iter()
            .any(|s| s.name == "bar" && s.kind == "function"));
        let markdown = extract_symbols("README.md", "# Title\n## Section\n");
        assert_eq!(markdown.len(), 2);
        assert_eq!(markdown[1].kind, "heading");
    }

    #[test]
    fn language_detection_is_stable() {
        assert_eq!(language_for("a/b.rs"), "rust");
        assert_eq!(language_for("a/b.test.tsx"), "typescript");
        assert_eq!(language_for("Makefile"), "text");
    }
}
