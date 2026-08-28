// Stage 3 语义分析 (PRD §7.4 R5) — tree-sitter 多 grammar 代码内容扫描测试
// 仅 feature=semantic 启用; 默认编译跳过本文件 (MVP 关 tree-sitter)

#![cfg(feature = "semantic")]

use fg_core::{CheckStage, ContentType, RiskLevel, SafetyAction};
use fg_rules::{semantic, verdict_from_hits, RuleEngine};

// P0-2: 代码内容须传 ContentType::Code 走 semantic 阶段 (Shell 默认只跑 tokenizer,
// 代码内容 `os.system(...)` 会被 tokenizer 当非白名单 binary 假阳 Ast L4, 非 semantic)。
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
    // child_process.exec 是 member-expression call — tree-sitter callee 文本含 child_process
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

// ── verdict_from_hits 合并 ────────────────────────────────────────────

// 注意: payload 须让 semantic L4 在 L11 rank 中胜出, 不撞默认 regex 黑名单 (rm-rf)。
// P0-2: content_type=Code → 跳 tokenizer (代码内容不跑 shell_words, 避免 os.system 当
// 非白名单 binary 假阳 Ast)。选 `os.system('id')`: 仅 semantic os.system L4 命中,
// 无 regex/tokenizer 干扰 → verdict.stage = Semantic。
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

// ── 直接 semantic_check API (不经 evaluate_full) ─────────────────────

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
