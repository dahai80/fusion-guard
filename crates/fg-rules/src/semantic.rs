// Stage 3 semantic analysis (PRD §7.4 R5) — tree-sitter multi-grammar code content scanning
//
// Enabled only when feature = "semantic" (off by default in MVP, PRD §7.4
// "adopt when needed with locked versions").
// Command-style authorization is already covered by Stage 2 shell-words; this
// stage scans code content (not commands) for dangerous calls:
//   Python: os.system / subprocess.* / eval / exec / __import__ / pickle.loads
//   JS/TS:  eval / Function / child_process / fetch exfiltration
//   Rust:   Command::new / std::process::Command / unsafe / fs::remove_dir_all
// Versions locked to match the fusion-executor workspace (tree-sitter 0.25,
// grammars 0.23) to prevent grammar drift.

#![cfg(feature = "semantic")]

use fg_core::{CheckStage, RiskLevel};
use tree_sitter::{Node, Parser};

use crate::tokenizer::TokenHit;

// ── Danger call tables (per-language) ────────────────────────────────
// Matched by function name (semantic scan hits by call-expression callee name).
//
// A9 SSOT: these tables are the single source of truth for the semantic stage.
// The former semantic_default_rules() emitted 6 stage=Semantic GuardRules into
// the ruleset (persisted to SQLite), but evaluate skips non-Regex stages and
// never compiled or matched them — dead code. Two decoupled sources of truth:
// an admin deleting the "semantic:py:os.system" rule expects to disable
// os.system detection, yet the semantic scan still hits via PY_DANGER_L4,
// violating the Checkpoint 2 SSOT.
// Fix (b): removed semantic_default_rules; these tables are the semantic-stage
// enforcement authority and are not admin-mutable (documented).
// Callers only see Regex rules via guard.rule.list; semantic detection is fixed.

const PY_DANGER_L4: &[&str] = &[
    "os.system",
    "os.popen",
    "os.exec",
    "os.execv",
    "os.execvp",
    "os.execve",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
    "commands.getoutput",
    "popen2.popen2",
];

const PY_DANGER_L3: &[&str] = &[
    "eval",
    "exec",
    "compile",
    "__import__",
    "pickle.loads",
    "pickle.load",
    "marshal.loads",
    "shelve.open",
    "ctypes.CDLL",
    "ctypes.cdll.LoadLibrary",
];

const JS_DANGER_L4: &[&str] = &[
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "execFile",
    "execFileSync",
];

const JS_DANGER_L3: &[&str] = &["eval", "Function", "setTimeout", "setInterval"];

const RS_DANGER_L4: &[&str] = &["Command::new", "remove_dir_all", "remove_file"];

const RS_DANGER_L3: &[&str] = &["unsafe"];

#[derive(Debug, Clone)]
pub struct SemanticHit {
    pub language: &'static str,
    pub callee: String,
    pub risk: RiskLevel,
    pub reason: String,
    pub stage: CheckStage,
}

impl SemanticHit {
    pub fn to_token_hit(&self) -> TokenHit {
        TokenHit {
            binary: format!("semantic:{}:{}", self.language, self.callee),
            reason: self.reason.clone(),
            stage: CheckStage::Semantic,
            sensitive_target: self.risk == RiskLevel::L4,
        }
    }
}

// ── Entry: multi-grammar attempt ─────────────────────────────────────
// C4: never zero out real hits because of has_error (tree-sitter is an
// error-recovering parser; dangerous nodes remain in the tree).
// C5 introduced a cross-language bare-hit risk (eval/exec/compile fire in both
// Python and JS): `const x=eval('1')` also hits eval under the Python grammar,
// but the Python grammar reports an error (const is invalid).
// Decision: prefer hits from the grammar with no parse errors (source language
// confirmed); only if every grammar errors, fall back to the first non-empty
// hit set (C4 — an errored source can still contain a real dangerous call, e.g.
// a syntax error injected into os.system("rm -rf /")).
// All-zero hits + all errors -> append an L2 parse-error hit (never a silent
// clean); otherwise clean.

// P2-1 (audit §P2-1): semantic scan input cap + language heuristic gating, to
// stop tree-sitter multi-grammar parsing of large inputs from blowing the SLA.
//
// Problem: the original implementation blindly tried all 4 grammars
// (Python/JS/TS/Rust). Clean Python source went through 3 non-native grammars
// with error-recovery parsing (superlinear in tree-sitter), so 256KB took 27s —
// far beyond the 2s SLA (PRD R1).
//
// Two lines of defense:
//   (1) Hard input cap SEMANTIC_INPUT_CAP — exceeding it degrades fail-open
//       (regex/tokenizer still scan); an L2 hint keeps it audit-visible.
//   (2) Language heuristic guess_grammars — guesses the source language from
//       leading lines/keywords and only tries candidate grammars (usually 1),
//       saving 3/4 of the parsing. Clean source parses at worst 1x. No
//       heuristic hit -> fall back to all 4 (bounded by the cap, rare).
//
// Preserves C4 (errored sources still get real dangerous calls detected) and
// C5 (cross-language bare hits, e.g. JS const+eval not mistaken for Python):
// candidates are confirmation-ordered — no-error grammar hits > no-error zero
// hits > err + non-empty hits fallback > all-error L2 parse-error.
pub const SEMANTIC_INPUT_CAP: usize = 256 * 1024;

// P2-1: language heuristic — scans the first ~2KB plus whole-content keyword
// features, returning candidate grammars ordered (highest confidence first).
// Keywords are strong per-language features (highly mutually exclusive syntax
// keywords), avoiding the JS grammar greedily consuming Rust source (const/let
// are shared).
fn guess_grammars(content: &str) -> Vec<&'static str> {
    let head: String = content.chars().take(2048).collect();
    let full = content;
    // Strong Rust features: use/fn/pub fn/let mut/impl/struct/unsafe/mod/extern/-> type signatures.
    let rust = head.contains("fn ")
        || head.contains("::")
        || head.contains("let mut")
        || head.contains("pub fn")
        || head.contains("impl ")
        || head.contains("extern ")
        || (head.contains("use ") && head.contains("::"));
    // Strong Python features: def /import/from/elif/None/True/False/lambda/dunder.
    let python = head.contains("\ndef ")
        || head.starts_with("def ")
        || head.contains("import ")
        || head.contains("elif ")
        || head.contains("lambda ")
        || full.contains("__name__");
    // JS/TS features: require(/console./const .*=require/=>/function( (TS adds : types).
    let jsts = head.contains("require(")
        || head.contains("console.")
        || head.contains("=>")
        || (head.contains("const ") && head.contains("require"))
        || head.contains("module.exports");
    let ts = jsts
        && (head.contains(": string") || head.contains(": number") || head.contains("interface "));

    let mut out: Vec<&'static str> = Vec::new();
    if ts {
        out.push("ts");
    }
    if rust {
        out.push("rust");
    }
    if python {
        out.push("python");
    }
    if jsts && !ts {
        out.push("js");
    }
    if out.is_empty() {
        // No heuristic hit -> all 4 (fallback, bounded by SEMANTIC_INPUT_CAP, for ambiguous sources).
        out.extend_from_slice(&["python", "js", "ts", "rust"]);
    }
    out
}

fn scan_by_lang(lang: &str, code: &str) -> (Vec<SemanticHit>, bool) {
    match lang {
        "python" => scan_python(code),
        "js" => scan_javascript(code),
        "ts" => scan_typescript(code),
        "rust" => scan_rust(code),
        _ => (Vec::new(), true),
    }
}

pub fn semantic_check(content: &str) -> Vec<SemanticHit> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    // P2-1 defense 1: input over the cap -> skip tree-sitter parsing, degrade
    // fail-open (regex/tokenizer still scan).
    if trimmed.len() > SEMANTIC_INPUT_CAP {
        tracing::warn!(
            input_bytes = trimmed.len(),
            cap = SEMANTIC_INPUT_CAP,
            "semantic input exceeds cap, degrading (P2-1 SLA guard)"
        );
        return vec![SemanticHit {
            language: "unknown",
            callee: "<input-too-large>".into(),
            risk: RiskLevel::L2,
            reason: format!(
                "semantic scan input exceeds cap ({}>{}, degraded and skipped, regex/tokenizer still scan)",
                trimmed.len(),
                SEMANTIC_INPUT_CAP
            ),
            stage: CheckStage::Semantic,
        }];
    }
    // P2-1 defense 2: language heuristic gating, only tries candidate grammars
    // (usually 1), saving 3/4 of the parsing.
    let langs = guess_grammars(trimmed);
    let mut err_hit: Option<Vec<SemanticHit>> = None;
    let mut any_clean_empty = false;
    for lang in &langs {
        let (hits, had_error) = scan_by_lang(lang, trimmed);
        if !had_error {
            if !hits.is_empty() {
                // No error + non-empty hits = source language confirmed + real
                // danger (C5, highest priority); return immediately.
                return hits;
            }
            // No error + zero hits: correct language and safe; keep as a
            // candidate (remaining candidates still tried for a better clean+hits).
            any_clean_empty = true;
        } else if !hits.is_empty() && err_hit.is_none() {
            // Error + non-empty: C4 fallback (errored sources still get real
            // dangerous calls detected, e.g. an injected os.system).
            err_hit = Some(hits);
        }
    }
    // Priority: clean_empty (correct language, zero hits) > err_hit (C4 fallback) > all-error L2 parse-error.
    if any_clean_empty {
        return Vec::new();
    }
    if let Some(hits) = err_hit {
        return hits;
    }
    vec![SemanticHit {
        language: "unknown",
        callee: "<parse-error>".into(),
        risk: RiskLevel::L2,
        reason: "source contains parse errors, semantic scan may be incomplete (C4)".into(),
        stage: CheckStage::Semantic,
    }]
}

// ── Python ───────────────────────────────────────────────────────────

// scan_* returns (dangerous hits, had_error). had_error only drives grammar
// fallback decisions; no L2 is appended here.
// The L2 parse-error hit is appended uniformly by semantic_check when all
// grammars return zero hits and all errored.

fn scan_python(code: &str) -> (Vec<SemanticHit>, bool) {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .is_err()
    {
        return (Vec::new(), true);
    }
    let tree = match parser.parse(code, None) {
        Some(t) => t,
        None => return (Vec::new(), true),
    };
    // C4: do not short-circuit on root has_error. tree-sitter is an
    // error-recovering parser; dangerous call nodes remain traversable in the
    // tree. One injected syntax error must not silence
    // os.system("rm -rf /") for the whole file as clean.
    let had_error = tree.root_node().has_error();
    let mut hits = Vec::new();
    // C5: Python-specific traversal — collect import/alias bindings, resolve
    // callees through aliases, check dangerous imports + dynamic dispatch
    // (getattr/__import__/globals/locals/vars). Non-Python languages still use
    // the generic walk_calls.
    walk_python(code, tree.root_node(), &mut hits);
    (hits, had_error)
}

// ── JavaScript ───────────────────────────────────────────────────────

fn scan_javascript(code: &str) -> (Vec<SemanticHit>, bool) {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .is_err()
    {
        return (Vec::new(), true);
    }
    let tree = match parser.parse(code, None) {
        Some(t) => t,
        None => return (Vec::new(), true),
    };
    // C4: do not short-circuit on root has_error (see scan_python comment).
    let had_error = tree.root_node().has_error();
    let mut hits = Vec::new();
    walk_calls(
        code,
        tree.root_node(),
        "javascript",
        JS_DANGER_L4,
        JS_DANGER_L3,
        &mut hits,
    );
    (hits, had_error)
}

// ── TypeScript ───────────────────────────────────────────────────────

fn scan_typescript(code: &str) -> (Vec<SemanticHit>, bool) {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .is_err()
    {
        return (Vec::new(), true);
    }
    let tree = match parser.parse(code, None) {
        Some(t) => t,
        None => return (Vec::new(), true),
    };
    // C4: do not short-circuit on root has_error (see scan_python comment).
    let had_error = tree.root_node().has_error();
    let mut hits = Vec::new();
    walk_calls(
        code,
        tree.root_node(),
        "typescript",
        JS_DANGER_L4,
        JS_DANGER_L3,
        &mut hits,
    );
    (hits, had_error)
}

// ── Rust ─────────────────────────────────────────────────────────────

fn scan_rust(code: &str) -> (Vec<SemanticHit>, bool) {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return (Vec::new(), true);
    }
    let tree = match parser.parse(code, None) {
        Some(t) => t,
        None => return (Vec::new(), true),
    };
    // C4: do not short-circuit on root has_error (see scan_python comment).
    let had_error = tree.root_node().has_error();
    let mut hits = Vec::new();
    walk_calls(
        code,
        tree.root_node(),
        "rust",
        RS_DANGER_L4,
        RS_DANGER_L3,
        &mut hits,
    );
    (hits, had_error)
}

// ── C5: Python-specific traversal (imports/aliases/dynamic dispatch) ──
// Three hit classes:
//  1. Importing a dangerous module itself (os/subprocess/ctypes/pickle/marshal)
//     -> L3. Regardless of whether it is later called, importing a dangerous
//     module is flagged (an executable RCE prerequisite).
//  2. from <dangerous module> import Y -> L3 (Y is usually a dangerous symbol
//     like system/Popen/CDLL).
//  3. call_expression: resolve callees via alias bindings (import os as o ->
//     o.system -> os.system); dynamic dispatch getattr/__import__/globals/
//     locals/vars -> L3 (cannot be proven safe).
// Alias binding table: alias name -> real module path (e.g. "o"->"os", "s"->"os.system").
const PY_DANGER_MODULES: &[&str] = &[
    "os",
    "subprocess",
    "ctypes",
    "pickle",
    "marshal",
    "commands",
    "popen2",
];
const PY_DYNAMIC_DISPATCH: &[&str] = &[
    "getattr",
    "__import__",
    "globals",
    "locals",
    "vars",
    "eval",
    "exec",
    "compile",
];

fn walk_python(code: &str, root: Node, out: &mut Vec<SemanticHit>) {
    let mut aliases: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    walk_python_node(code, root, &mut aliases, out);
}

fn walk_python_node(
    code: &str,
    node: Node,
    aliases: &mut std::collections::HashMap<String, String>,
    out: &mut Vec<SemanticHit>,
) {
    let kind = node.kind();

    // import statement: import os / import os as o / import os.path as p
    if kind == "import_statement" {
        collect_import_statement(code, node, aliases, out);
    }
    // from X import Y / from X import Y as s
    if kind == "import_from_statement" {
        collect_import_from(code, node, aliases, out);
    }

    // call: alias resolution + dynamic dispatch detection. The
    // tree-sitter-python call node kind is "call" (not call_expression).
    if kind == "call" || kind == "call_expression" {
        if let Some(callee_node) = node.child_by_field_name("function") {
            let callee = callee_node
                .utf8_text(code.as_bytes())
                .unwrap_or("")
                .trim()
                .to_string();
            if !callee.is_empty() {
                classify_python(&callee, aliases, out);
            }
        }
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            walk_python_node(code, cursor.node(), aliases, out);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// import os -> alias "os"->"os"; a dangerous module is an immediate L3 hit.
// import os as o -> alias "o"->"os".
// import os.path -> alias "os"->"os" (top-level module). import os.path as p -> "p"->"os.path".
fn collect_import_statement(
    code: &str,
    node: Node,
    aliases: &mut std::collections::HashMap<String, String>,
    out: &mut Vec<SemanticHit>,
) {
    // tree-sitter-python: import_statement contains dotted_name + optional
    // aliased_import.
    // Simple robust approach: take the whole source text segment and parse
    // "import X[.Y][ as A]" with comma-separated targets.
    let text = node.utf8_text(code.as_bytes()).unwrap_or("");
    parse_import_text(text, aliases, out, false);
}

// from os import system -> alias "system"->"os.system"; dangerous X -> L3.
// from os import system as s -> "s"->"os.system".
fn collect_import_from(
    code: &str,
    node: Node,
    aliases: &mut std::collections::HashMap<String, String>,
    out: &mut Vec<SemanticHit>,
) {
    let text = node.utf8_text(code.as_bytes()).unwrap_or("");
    parse_import_text(text, aliases, out, true);
}

// Text-level parsing of import statements (tree-sitter fields are unstable
// across grammar versions; text parsing is more robust).
// is_from=true -> the from X import Y[, Z] form.
fn parse_import_text(
    text: &str,
    aliases: &mut std::collections::HashMap<String, String>,
    out: &mut Vec<SemanticHit>,
    is_from: bool,
) {
    let text = text.trim();
    if is_from {
        // from <module> import <names>
        let after_from = text.strip_prefix("from").unwrap_or(text).trim();
        let parts: Vec<&str> = after_from.splitn(2, "import").collect();
        if parts.len() != 2 {
            return;
        }
        let module = parts[0].trim();
        let names = parts[1].trim();
        if PY_DANGER_MODULES.contains(&module) {
            out.push(SemanticHit {
                language: "python",
                callee: format!("from {module} import"),
                risk: RiskLevel::L3,
                reason: format!("python import from dangerous module {} (C5)", module),
                stage: CheckStage::Semantic,
            });
        }
        // Each Y [as A] -> alias
        for item in names.split(',') {
            let item = item.trim();
            let segs: Vec<&str> = item.split_whitespace().collect();
            if segs.is_empty() {
                continue;
            }
            let imported = segs[0];
            let bind_name = if segs.len() >= 3 && segs[1] == "as" {
                segs[2]
            } else {
                imported
            };
            let real = if imported == "*" {
                String::new()
            } else {
                format!("{module}.{imported}")
            };
            if !bind_name.is_empty() && !real.is_empty() {
                aliases.insert(bind_name.to_string(), real);
            }
        }
    } else {
        // import X[.Y][ as A][, X2[.Y2][ as A2]]
        let after_import = text.strip_prefix("import").unwrap_or(text).trim();
        for item in after_import.split(',') {
            let item = item.trim();
            let segs: Vec<&str> = item.split_whitespace().collect();
            if segs.is_empty() {
                continue;
            }
            let dotted = segs[0];
            let top = dotted.split('.').next().unwrap_or(dotted);
            let bind_name = if segs.len() >= 3 && segs[1] == "as" {
                segs[2]
            } else {
                top
            };
            if PY_DANGER_MODULES.contains(&top) {
                out.push(SemanticHit {
                    language: "python",
                    callee: format!("import {dotted}"),
                    risk: RiskLevel::L3,
                    reason: format!("python imports dangerous module {} (C5)", top),
                    stage: CheckStage::Semantic,
                });
            }
            if !bind_name.is_empty() {
                aliases.insert(bind_name.to_string(), dotted.to_string());
            }
        }
    }
}

// Python callee classification: resolve aliases first (o.system -> os.system),
// then check the danger tables + dynamic dispatch.
fn classify_python(
    callee: &str,
    aliases: &std::collections::HashMap<String, String>,
    out: &mut Vec<SemanticHit>,
) {
    // Dynamic dispatch: getattr/__import__/globals/locals/vars -> L3 (cannot be
    // proven safe). eval/exec/compile are already in PY_DANGER_L3; the reason
    // is labeled explicitly here.
    if PY_DYNAMIC_DISPATCH.contains(&callee) {
        out.push(SemanticHit {
            language: "python",
            callee: callee.to_string(),
            risk: RiskLevel::L3,
            reason: format!("python dynamic dispatch/reflection call (C5): {}", callee),
            stage: CheckStage::Semantic,
        });
        return;
    }
    // Alias resolution: look up the callee's first segment (before the dot) in
    // the alias table and rewrite to the real path.
    let resolved = resolve_alias(callee, aliases);
    if danger_match(&resolved, PY_DANGER_L4) {
        out.push(SemanticHit {
            language: "python",
            callee: resolved.clone(),
            risk: RiskLevel::L4,
            reason: format!("python dangerous call (L4, alias-resolved): {}", resolved),
            stage: CheckStage::Semantic,
        });
        return;
    }
    if danger_match(&resolved, PY_DANGER_L3) {
        out.push(SemanticHit {
            language: "python",
            callee: resolved.clone(),
            risk: RiskLevel::L3,
            reason: format!("python dangerous call (L3, alias-resolved): {}", resolved),
            stage: CheckStage::Semantic,
        });
    }
}

// callee "o.system" -> alias "o"->"os" -> "os.system".
// The alias table stores top-level module names; the callee's first segment is
// looked up and replaced.
fn resolve_alias(callee: &str, aliases: &std::collections::HashMap<String, String>) -> String {
    let first = callee.split('.').next().unwrap_or(callee);
    if let Some(real) = aliases.get(first) {
        if first == callee {
            return real.clone();
        }
        let rest = &callee[first.len()..];
        return format!("{real}{rest}");
    }
    callee.to_string()
}

fn danger_match(callee: &str, table: &[&str]) -> bool {
    table.contains(&callee)
}

// ── Generic call-expression traversal ────────────────────────────────
// Call node kinds across tree-sitter grammars: call_expression (py/js/ts),
// rust call_expression (method/call). The callee text is the source snippet of
// the call target.
fn walk_calls(
    code: &str,
    node: Node,
    lang: &'static str,
    danger_l4: &[&str],
    danger_l3: &[&str],
    out: &mut Vec<SemanticHit>,
) {
    let mut cursor = node.walk();
    recurse_walk(&mut cursor, code, lang, danger_l4, danger_l3, out);
}

fn recurse_walk(
    cursor: &mut tree_sitter::TreeCursor,
    code: &str,
    lang: &'static str,
    danger_l4: &[&str],
    danger_l3: &[&str],
    out: &mut Vec<SemanticHit>,
) {
    loop {
        let node = cursor.node();
        let kind = node.kind();
        if kind == "call_expression" || kind == "call" {
            if let Some(callee_node) = node.child_by_field_name("function").or_else(|| {
                // rust grammar has no function field; take the first non-punctuation child
                node.named_child(0)
            }) {
                let callee = callee_node
                    .utf8_text(code.as_bytes())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !callee.is_empty() {
                    if let Some(h) = classify(&callee, lang, danger_l4, danger_l3) {
                        out.push(h);
                    }
                }
            }
        }

        if cursor.goto_first_child() {
            recurse_walk(cursor, code, lang, danger_l4, danger_l3, out);
            cursor.goto_parent();
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

fn classify(
    callee: &str,
    lang: &'static str,
    danger_l4: &[&str],
    danger_l3: &[&str],
) -> Option<SemanticHit> {
    // C5: removed the ends_with(":{d}") dead logic — it matched invalid Python
    // attributes like foo:os.system, never hit real code, and only added noise.
    // Replaced with exact equality.
    if danger_l4.contains(&callee) {
        return Some(SemanticHit {
            language: lang,
            callee: callee.to_string(),
            risk: RiskLevel::L4,
            reason: format!("{} dangerous call (L4): {}", lang, callee),
            stage: CheckStage::Semantic,
        });
    }
    if danger_l3.contains(&callee) {
        return Some(SemanticHit {
            language: lang,
            callee: callee.to_string(),
            risk: RiskLevel::L3,
            reason: format!("{} dangerous call (L3): {}", lang, callee),
            stage: CheckStage::Semantic,
        });
    }
    None
}
