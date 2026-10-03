//! Layer merge: higher layer may only narrow (09 §9.3).
//! Effective lists = intersection when both layers specify non-empty;
//! if higher omits (empty), lower stands. Booleans: higher false wins.

use crate::model::*;

fn glob_match(pattern: &str, path: &str) -> bool {
    let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
    let path = path.strip_prefix("./").unwrap_or(path);
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = path.chars().collect();
    fn m(p: &[char], t: &[char]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        if p[0] == '*' {
            if p.len() > 1 && p[1] == '*' {
                for i in 0..=t.len() {
                    if m(&p[2..], &t[i..]) {
                        return true;
                    }
                }
                return false;
            }
            for i in 0..=t.len() {
                if i > 0 && t[i - 1] == '/' {
                    break;
                }
                if m(&p[1..], &t[i..]) {
                    return true;
                }
            }
            return false;
        }
        if t.is_empty() {
            return false;
        }
        if p[0] == '?' || p[0] == t[0] {
            return m(&p[1..], &t[1..]);
        }
        false
    }
    m(&pat, &txt)
}

/// Intersect two scope lists so the result can only NARROW.
/// A lower-layer scope survives only if the higher layer's scope covers it
/// (glob-aware), so `./**` narrowed by `./src/**` yields `./src/**`.
fn intersect(lower: &[String], higher: &[String]) -> Vec<String> {
    // `lower` is the permissive baseline (start with built-in defaults).
    // `higher` is the project/user layer that may narrow it.
    //
    // - higher empty  => domain unspecified by higher; lower stands.
    // - lower empty   => the baseline granted nothing for this domain, but a
    //                    layer above explicitly asks for something. Since the
    //                    built-in default is itself a *floor* (not an
    //                    authoritative denial), the higher layer's grant is
    //                    the effective scope. Denial is enforced by the
    //                    absence of any grant, not by intersection with an
    //                    empty default.
    if higher.is_empty() {
        return lower.to_vec();
    }
    if lower.is_empty() {
        return higher.to_vec();
    }

    // Both present: keep the narrower (more specific) scope.
    let mut out: Vec<String> = Vec::new();
    for lo in lower {
        for hi in higher {
            if glob_match(lo, hi) {
                out.push(hi.clone());
            } else if glob_match(hi, lo) {
                out.push(lo.clone());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Merge `higher` (narrower authority) over `lower`.
pub fn merge(lower: &Policy, higher: &Policy) -> Policy {
    let mut out = lower.clone();
    out.metadata = higher.metadata.clone();

    out.filesystem.read = intersect(&lower.filesystem.read, &higher.filesystem.read);
    out.filesystem.write = intersect(&lower.filesystem.write, &higher.filesystem.write);
    out.filesystem.delete = intersect(&lower.filesystem.delete, &higher.filesystem.delete);

    out.network.allow = intersect(&lower.network.allow, &higher.network.allow);
    out.network.listen = intersect(&lower.network.listen, &higher.network.listen);

    out.secrets.read = lower.secrets.read && higher.secrets.read;
    out.secrets.write = lower.secrets.write && higher.secrets.write;
    out.system.admin = lower.system.admin && higher.system.admin;

    out.process.spawn = intersect(&lower.process.spawn, &higher.process.spawn);
    out.tools.allow = intersect(&lower.tools.allow, &higher.tools.allow);
    out.tools.install = lower.tools.install && higher.tools.install;
    out
}
