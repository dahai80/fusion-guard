// Stage 3 semantic analysis (PRD §7.4 R5) — tree-sitter multi-grammar code content scan tests
// Only enabled with feature=semantic; skipped by default compilation (MVP keeps tree-sitter off)

#![cfg(feature = "semantic")]

use fg_core::{CheckStage, ContentType, RiskLevel, SafetyAction};
use fg_rules::{semantic, verdict_from_hits, RuleEngine};

// P0-2: code content must pass ContentType::Code to reach the semantic stage
// (Shell by default only runs the tokenizer; code content `os.system(...)`
// would be false-positived by the tokenizer as a non-whitelisted binary at
// Ast L4, not semantic).
fn sem_hits(eng: &RuleEngine, content: &str) -> Vec<fg_rules::RuleHit> {
    eng.evaluate_full_typed(content, ContentType::Code)
        .into_iter()
        .filter(|h| h.stage == CheckStage::Semantic)
        .collect()
}

// ── Python ───────────────────────────────────────────────────────────

#[test]
fn python_os_system_blocks_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let code = "import os\nos.system('rm -rf /tmp/x')\n";
    let hits = sem_hits(&eng, code);
    let top = hits
        .iter()
        .find(|h| h.rule.name.contains("os.system"))
        .expect("os.system must be detected");
    assert_eq!(top.rule.risk_level, RiskLevel::L4);
    assert_eq!(top.rule.action, SafetyAction::Block);
    assert_eq!(top.stage, CheckStage::Semantic);
}

#[test]
fn python_subprocess_blocks_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let code = "import subprocess\nsubprocess.Popen(['nc', '-l', '4444'])\n";
    let hits = sem_hits(&eng, code);
    assert!(hits.iter().any(|h| h.rule.name.contains("subprocess")));
}

#[test]
fn python_eval_l3() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let code = "x = eval(input())\n";
    let hits = sem_hits(&eng, code);
    assert!(hits
        .iter()
        .any(|h| h.rule.name.contains("eval") && h.rule.risk_level == RiskLevel::L3));
}

#[test]
fn python_clean_no_hit() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let code = "def add(a, b):\n    return a + b\n";
    let hits = sem_hits(&eng, code);
    assert!(
        hits.is_empty(),
        "clean python code must not trigger semantic hit"
    );
}

// ── JavaScript ───────────────────────────────────────────────────────

#[test]
fn js_eval_l3() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let code = "const x = eval('1+1');\n";
    let hits = sem_hits(&eng, code);
    assert!(hits
        .iter()
        .any(|h| h.rule.name.contains("javascript") && h.rule.name.contains("eval")));
}

#[test]
fn js_child_process_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    // child_process.exec is a member-expression call — the tree-sitter callee text contains child_process
    let code = "const { exec } = require('child_process');\nexec('rm -rf /tmp/x');\n";
    let hits = sem_hits(&eng, code);
    assert!(hits.iter().any(|h| h.rule.name.contains("exec")));
}

// ── Rust ─────────────────────────────────────────────────────────────

#[test]
fn rust_command_new_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let code = "use std::process::Command;\nlet _ = Command::new(\"rm\").output();\n";
    let hits = sem_hits(&eng, code);
    assert!(hits.iter().any(|h| h.rule.name.contains("rust")));
}

#[test]
fn rust_clean_no_hit() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let code = "fn main() { let x = 1 + 2; println!(\"{}\", x); }\n";
    let hits = sem_hits(&eng, code);
    assert!(hits.is_empty());
}

// ── verdict_from_hits merge ──────────────────────────────────────────

// Note: the payload must let the semantic L4 win the L11 rank and not collide
// with the default regex blocklist (rm-rf).
// P0-2: content_type=Code -> tokenizer skipped (code content does not run
// shell_words, avoiding os.system false-positived as a non-whitelisted binary
// at Ast). `os.system('id')` is chosen: only the semantic os.system L4 hits,
// with no regex/tokenizer interference -> verdict.stage = Semantic.
#[test]
fn semantic_verdict_block() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let code = "os.system('id')\n";
    let hits = eng.evaluate_full_typed(code, ContentType::Code);
    let v = verdict_from_hits(&hits, 1);
    assert_eq!(v.action, SafetyAction::Block);
    assert!(matches!(v.risk_level, RiskLevel::L4));
    assert_eq!(v.stage, CheckStage::Semantic);
    assert!(v.seatbelt_required);
}

// ── Direct semantic_check API (not via evaluate_full) ────────────────

#[test]
fn semantic_check_python_direct() {
    let hits = semantic::semantic_check("os.system('id')");
    assert!(hits.iter().any(|h| h.callee.contains("os.system")));
}

#[test]
fn semantic_check_empty() {
    assert!(semantic::semantic_check("").is_empty());
    assert!(semantic::semantic_check("   ").is_empty());
}

// ── P2-1 (audit §P2-1): semantic scan input cap + perf baseline ──────

// P2-1: input over SEMANTIC_INPUT_CAP -> skip tree-sitter parsing, return an
// L2 degradation hint (not a silent clean). fail-open (regex/tokenizer still
// scan), but the degradation stays audit-visible — prevents large inputs from
// blowing the 2s SLA.
#[test]
fn semantic_check_oversized_input_degrades() {
    let cap = semantic::SEMANTIC_INPUT_CAP;
    let huge = "x".repeat(cap + 1);
    let hits = semantic::semantic_check(&huge);
    assert_eq!(
        hits.len(),
        1,
        "P2-1: over the cap must return a single degradation hit"
    );
    assert_eq!(hits[0].risk, RiskLevel::L2);
    assert_eq!(hits[0].callee, "<input-too-large>");
    assert_eq!(hits[0].stage, CheckStage::Semantic);
}

// P2-1: at the cap, parsing proceeds normally with no degradation.
#[test]
fn semantic_check_at_cap_parses_normally() {
    let cap = semantic::SEMANTIC_INPUT_CAP;
    // Within the cap, a real dangerous call -> normal semantic hit (not degraded).
    let pad = "x".repeat(cap - 64);
    let code = format!("os.system('id')\n{}", pad);
    let hits = semantic::semantic_check(&code);
    assert!(
        hits.iter().any(|h| h.callee.contains("os.system")),
        "P2-1: within the cap, os.system must be hit normally"
    );
}

// P2-1: perf baseline — a large in-cap code block under language heuristic
// gating (clean Python -> 1-grammar parse) must stay within the SLA.
// PRD R1: regex/AST p99<10ms, 2s hard timeout; semantic is allowed slack but
// large inputs must not break through. Quantifies the semantic path p99.
// The heuristic guesses python (def keyword) -> only the Python grammar is
// tried -> 1x parse, no 3 non-native grammar error-recovery triggered.
#[test]
fn semantic_check_perf_baseline_under_cap() {
    let cap = semantic::SEMANTIC_INPUT_CAP;
    let unit = "def f():\n    return 1 + 2\n";
    let mut code = String::new();
    while code.len() + unit.len() <= cap {
        code.push_str(unit);
    }
    let start = std::time::Instant::now();
    let hits = semantic::semantic_check(&code);
    let elapsed = start.elapsed();
    assert!(hits.is_empty(), "P2-1: clean code must have no hits");
    // SLA: heuristic 1-grammar parse < 500ms (256KB Python single grammar,
    // leaving ample margin against the 2s hard timeout).
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "P2-1: in-cap heuristic 1-grammar parse must be < 500ms (SLA guard), got {:?}",
        elapsed
    );
}
