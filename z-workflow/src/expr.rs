//! A small, safe condition language for `when` and `if`.
//!
//! No `eval`, no shell, no code execution. Grammar:
//!
//! ```text
//! expr    := or
//! or      := and ("||" and)*
//! and     := unary ("&&" unary)*
//! unary   := "!" unary | "exists" path | primary (compare primary)?
//! primary := "(" expr ")" | string | number | true | false | path
//! path    := ident ("." ident)*   e.g. steps.test.exit_code
//! compare := "==" | "!=" | ">" | ">=" | "<" | "<=" | "contains"
//! ```

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Scalar {
    Bool(bool),
    Number(f64),
    Str(String),
    Missing,
}

impl Scalar {
    pub fn truthy(&self) -> bool {
        match self {
            Self::Bool(value) => *value,
            Self::Number(value) => *value != 0.0,
            Self::Str(value) => !value.is_empty(),
            Self::Missing => false,
        }
    }

    fn display(&self) -> String {
        match self {
            Self::Bool(value) => value.to_string(),
            Self::Number(value) => value.to_string(),
            Self::Str(value) => value.clone(),
            Self::Missing => "<missing>".into(),
        }
    }
}

/// Values visible to condition evaluation. Built by the workflow engine.
#[derive(Debug, Clone, Default)]
pub struct Vars {
    pub params: BTreeMap<String, String>,
    pub steps: BTreeMap<String, StepVars>,
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct StepVars {
    pub status: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub approved: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExprError(pub String);

impl fmt::Display for ExprError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ExprError {}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Number(f64),
    Str(String),
    True,
    False,
    LParen,
    RParen,
    Not,
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    Exists,
}

fn tokenize(input: &str) -> Result<Vec<Token>, ExprError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch.is_whitespace() {
            index += 1;
            continue;
        }
        match ch {
            '(' => {
                tokens.push(Token::LParen);
                index += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                index += 1;
            }
            '!' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::Ne);
                    index += 2;
                } else {
                    tokens.push(Token::Not);
                    index += 1;
                }
            }
            '=' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::Eq);
                    index += 2;
                } else {
                    return Err(ExprError("use `==` for comparison".into()));
                }
            }
            '&' => {
                if chars.get(index + 1) == Some(&'&') {
                    tokens.push(Token::And);
                    index += 2;
                } else {
                    return Err(ExprError("use `&&` for boolean and".into()));
                }
            }
            '|' => {
                if chars.get(index + 1) == Some(&'|') {
                    tokens.push(Token::Or);
                    index += 2;
                } else {
                    return Err(ExprError("use `||` for boolean or".into()));
                }
            }
            '<' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::Le);
                    index += 2;
                } else {
                    tokens.push(Token::Lt);
                    index += 1;
                }
            }
            '>' => {
                if chars.get(index + 1) == Some(&'=') {
                    tokens.push(Token::Ge);
                    index += 2;
                } else {
                    tokens.push(Token::Gt);
                    index += 1;
                }
            }
            '"' | '\'' => {
                let quote = ch;
                index += 1;
                let mut value = String::new();
                let mut closed = false;
                while index < chars.len() {
                    let c = chars[index];
                    if c == quote {
                        closed = true;
                        index += 1;
                        break;
                    }
                    if c == '\\' && index + 1 < chars.len() {
                        index += 1;
                        value.push(chars[index]);
                        index += 1;
                        continue;
                    }
                    value.push(c);
                    index += 1;
                }
                if !closed {
                    return Err(ExprError("unterminated string".into()));
                }
                tokens.push(Token::Str(value));
            }
            _ if ch.is_ascii_digit() => {
                let start = index;
                while index < chars.len() && (chars[index].is_ascii_digit() || chars[index] == '.')
                {
                    index += 1;
                }
                let text: String = chars[start..index].iter().collect();
                let value = text
                    .parse::<f64>()
                    .map_err(|_| ExprError(format!("invalid number `{text}`")))?;
                tokens.push(Token::Number(value));
            }
            _ if ch.is_alphanumeric() || ch == '_' => {
                let start = index;
                while index < chars.len()
                    && (chars[index].is_alphanumeric()
                        || chars[index] == '_'
                        || chars[index] == '.'
                        || chars[index] == '-')
                {
                    index += 1;
                }
                let text: String = chars[start..index].iter().collect();
                tokens.push(match text.as_str() {
                    "true" => Token::True,
                    "false" => Token::False,
                    "and" => Token::And,
                    "or" => Token::Or,
                    "not" => Token::Not,
                    "contains" => Token::Contains,
                    "exists" => Token::Exists,
                    _ => Token::Ident(text),
                });
            }
            other => {
                return Err(ExprError(format!("unexpected character `{other}`")));
            }
        }
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    position: usize,
    vars: &'a Vars,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<Token> {
        self.tokens.get(self.position).cloned()
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.position).cloned();
        self.position += 1;
        token
    }

    fn parse_or(&mut self) -> Result<Scalar, ExprError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.next();
            let right = self.parse_and()?;
            left = Scalar::Bool(left.truthy() || right.truthy());
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Scalar, ExprError> {
        let mut left = self.parse_unary()?;
        while matches!(self.peek(), Some(Token::And)) {
            self.next();
            let right = self.parse_unary()?;
            left = Scalar::Bool(left.truthy() && right.truthy());
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Scalar, ExprError> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.next();
            let value = self.parse_unary()?;
            return Ok(Scalar::Bool(!value.truthy()));
        }
        if matches!(self.peek(), Some(Token::Exists)) {
            self.next();
            let path = match self.next() {
                Some(Token::Ident(path)) => path,
                _ => return Err(ExprError("`exists` needs a path".into())),
            };
            return Ok(Scalar::Bool(self.lookup(&path) != Scalar::Missing));
        }
        let left = self.parse_primary()?;
        let Some(operator) = self.peek() else {
            return Ok(left);
        };
        let operator = match &operator {
            Token::Eq => "==",
            Token::Ne => "!=",
            Token::Lt => "<",
            Token::Le => "<=",
            Token::Gt => ">",
            Token::Ge => ">=",
            Token::Contains => "contains",
            Token::And | Token::Or | Token::RParen => return Ok(left),
            other => return Err(ExprError(format!("unexpected token {other:?}"))),
        };
        self.next();
        let right = self.parse_primary()?;
        Ok(Scalar::Bool(compare(left, operator, right)))
    }

    fn parse_primary(&mut self) -> Result<Scalar, ExprError> {
        match self.next() {
            Some(Token::True) => Ok(Scalar::Bool(true)),
            Some(Token::False) => Ok(Scalar::Bool(false)),
            Some(Token::Number(value)) => Ok(Scalar::Number(value)),
            Some(Token::Str(value)) => Ok(Scalar::Str(value)),
            Some(Token::Ident(path)) => Ok(self.lookup(&path)),
            Some(Token::LParen) => {
                let value = self.parse_or()?;
                match self.next() {
                    Some(Token::RParen) => Ok(value),
                    _ => Err(ExprError("missing `)`".into())),
                }
            }
            Some(other) => Err(ExprError(format!("unexpected token {other:?}"))),
            None => Err(ExprError("unexpected end of expression".into())),
        }
    }

    fn lookup(&self, path: &str) -> Scalar {
        let mut parts = path.split('.');
        match parts.next() {
            Some("params") => {
                let Some(name) = parts.next() else {
                    return Scalar::Missing;
                };
                self.vars
                    .params
                    .get(name)
                    .map(|value| Scalar::Str(value.clone()))
                    .unwrap_or(Scalar::Missing)
            }
            Some("env") => {
                let Some(name) = parts.next() else {
                    return Scalar::Missing;
                };
                self.vars
                    .env
                    .get(name)
                    .map(|value| Scalar::Str(value.clone()))
                    .unwrap_or(Scalar::Missing)
            }
            Some("steps") => {
                let Some(id) = parts.next() else {
                    return Scalar::Missing;
                };
                let Some(step) = self.vars.steps.get(id) else {
                    return Scalar::Missing;
                };
                match parts.next() {
                    None => Scalar::Bool(true),
                    Some("status") => Scalar::Str(step.status.clone()),
                    Some("exit_code") => step
                        .exit_code
                        .map(|code| Scalar::Number(code as f64))
                        .unwrap_or(Scalar::Missing),
                    Some("stdout") => Scalar::Str(step.stdout.clone()),
                    Some("stderr") => Scalar::Str(step.stderr.clone()),
                    Some("approved") => Scalar::Bool(step.approved),
                    Some("error") => step
                        .error
                        .clone()
                        .map(Scalar::Str)
                        .unwrap_or(Scalar::Missing),
                    Some("succeeded") => {
                        Scalar::Bool(step.status == "succeeded" || step.exit_code == Some(0))
                    }
                    Some("failed") => Scalar::Bool(step.status == "failed"),
                    _ => Scalar::Missing,
                }
            }
            Some(_) | None => Scalar::Missing,
        }
    }
}

fn compare(left: Scalar, operator: &str, right: Scalar) -> bool {
    if operator == "contains" {
        return match (&left, &right) {
            (Scalar::Str(text), Scalar::Str(needle)) => text.contains(needle),
            (Scalar::Str(text), other) => text.contains(&other.display()),
            _ => false,
        };
    }
    let (a, b) = match (&left, &right) {
        (Scalar::Number(a), Scalar::Number(b)) => (*a, *b),
        (Scalar::Str(a), Scalar::Number(b)) => {
            let Ok(a) = a.parse::<f64>() else {
                return false;
            };
            (a, *b)
        }
        (Scalar::Number(a), Scalar::Str(b)) => {
            let Ok(b) = b.parse::<f64>() else {
                return false;
            };
            (*a, b)
        }
        (Scalar::Bool(a), Scalar::Bool(b)) => (*a as u8 as f64, *b as u8 as f64),
        (Scalar::Missing, _) | (_, Scalar::Missing) => return operator == "!=" && left != right,
        (a, b) => match operator {
            "==" => return a.display() == b.display(),
            "!=" => return a.display() != b.display(),
            _ => return false,
        },
    };
    match operator {
        "==" => (a - b).abs() < f64::EPSILON,
        "!=" => (a - b).abs() >= f64::EPSILON,
        "<" => a < b,
        "<=" => a <= b,
        ">" => a > b,
        ">=" => a >= b,
        _ => false,
    }
}

/// Evaluate a condition. The result is the expression's truthiness.
pub fn eval(expr: &str, vars: &Vars) -> Result<bool, ExprError> {
    let tokens = tokenize(expr)?;
    if tokens.is_empty() {
        return Err(ExprError("empty expression".into()));
    }
    let mut parser = Parser {
        tokens: &tokens,
        position: 0,
        vars,
    };
    let value = parser.parse_or()?;
    if parser.position != tokens.len() {
        return Err(ExprError(format!(
            "unexpected trailing tokens at position {}",
            parser.position
        )));
    }
    Ok(value.truthy())
}

/// Validate syntax without running anything.
pub fn validate(expr: &str) -> Result<(), ExprError> {
    eval(expr, &Vars::default()).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> Vars {
        let mut vars = Vars::default();
        vars.params.insert("version".into(), "1.2.3".into());
        vars.params.insert("dry".into(), "false".into());
        vars.steps.insert(
            "test".into(),
            StepVars {
                status: "succeeded".into(),
                exit_code: Some(0),
                stdout: "42 passed".into(),
                ..Default::default()
            },
        );
        vars.steps.insert(
            "approve".into(),
            StepVars {
                status: "succeeded".into(),
                approved: true,
                ..Default::default()
            },
        );
        vars.steps.insert(
            "fail".into(),
            StepVars {
                status: "failed".into(),
                exit_code: Some(101),
                ..Default::default()
            },
        );
        vars
    }

    #[test]
    fn evaluates_paths_and_comparisons() {
        let vars = vars();
        assert!(eval("steps.approve.approved", &vars).unwrap());
        assert!(eval("steps.test.exit_code == 0", &vars).unwrap());
        assert!(!eval("steps.fail.exit_code == 0", &vars).unwrap());
        assert!(eval("steps.fail.exit_code != 0", &vars).unwrap());
        assert!(eval("params.version == \"1.2.3\"", &vars).unwrap());
        assert!(eval("steps.test.stdout contains \"passed\"", &vars).unwrap());
        assert!(eval("steps.test.stdout contains '42'", &vars).unwrap());
    }

    #[test]
    fn boolean_operators_short_circuit_semantically() {
        let vars = vars();
        assert!(eval("steps.approve.approved && steps.test.exit_code == 0", &vars).unwrap());
        assert!(eval("steps.fail.failed || steps.approve.approved", &vars).unwrap());
        assert!(eval("!(steps.fail.exit_code == 0)", &vars).unwrap());
        assert!(
            eval("steps.missing.exit_code == 0", &vars).is_err()
                || !eval("steps.missing.exit_code == 0", &vars).unwrap()
        );
    }

    #[test]
    fn exists_and_parentheses() {
        let vars = vars();
        assert!(eval("exists steps.test", &vars).unwrap());
        assert!(!eval("exists steps.nope", &vars).unwrap());
        assert!(eval(
            "(steps.test.exit_code == 0) && !(steps.fail.exit_code > 0 && false)",
            &vars
        )
        .unwrap());
    }

    #[test]
    fn malformed_expressions_are_errors() {
        assert!(validate("steps.test.exit_code ==").is_err());
        assert!(validate("steps.test.exit_code = 0").is_err());
        assert!(validate("(steps.test").is_err());
        assert!(validate("").is_err());
        assert!(validate("a & b").is_err());
    }

    #[test]
    fn no_code_execution() {
        assert!(validate("$(rm -rf /)").is_err());
        assert!(validate("`id`").is_err());
        assert!(validate("system('id')").is_err());
    }
}
