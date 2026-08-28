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

// ── P2-1 (audit §P2-1): 语义扫描输入上限 + 性能基线 ──────────────────────

// P2-1: 输入超 SEMANTIC_INPUT_CAP → 跳过 tree-sitter 解析, 返 L2 降级提示 (非静默 clean)。
// fail-open (regex/tokenizer 仍扫), 但审计可见降级 —— 防大输入突破 2s SLA。
#[test]
fn semantic_check_oversized_input_degrades() {
    let cap = semantic::SEMANTIC_INPUT_CAP;
    let huge = "x".repeat(cap + 1);
    let hits = semantic::semantic_check(&huge);
    assert_eq!(hits.len(), 1, "P2-1: 超上限须返单条降级 hit");
    assert_eq!(hits[0].risk, RiskLevel::L2);
    assert_eq!(hits[0].callee, "<input-too-large>");
    assert_eq!(hits[0].stage, CheckStage::Semantic);
}

// P2-1: 上限内 (cap) 正常解析, 不降级。
#[test]
fn semantic_check_at_cap_parses_normally() {
    let cap = semantic::SEMANTIC_INPUT_CAP;
    // cap 内含真实危险调用 → 正常语义命中 (非降级)。
    let pad = "x".repeat(cap - 64);
    let code = format!("os.system('id')\n{}", pad);
    let hits = semantic::semantic_check(&code);
    assert!(
        hits.iter().any(|h| h.callee.contains("os.system")),
        "P2-1: 上限内须正常语义命中 os.system"
    );
}

// P2-1: 性能基线 —— 上限内大代码块经语言启发式门控 (clean Python → 1 grammar 解析) 须在 SLA 内。
// PRD R1: regex/AST p99<10ms, 2s 硬超时; 语义允松但大输入不突破。量化语义路径 p99。
// 启发式猜 python (def 关键字) → 只试 Python grammar → 1× 解析, 不触发 3 非原生 grammar 错恢复。
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
    assert!(hits.is_empty(), "P2-1: clean code 无命中");
    // SLA: 启发式 1-grammar 解析 < 500ms (256KB Python 单 grammar, 2s 硬超时留充裕余量)。
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "P2-1: 上限内启发式 1-grammar 解析须 < 500ms (SLA guard), got {:?}",
        elapsed
    );
}
