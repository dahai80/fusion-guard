use fg_redact::Redactor;

// M4: Redactor::new() 返 Result, 测试用 expect (静态模式编译应永不失败)。
fn make() -> Redactor {
    Redactor::new().expect("redactor regex compile (static patterns)")
}

#[test]
fn irreversible_uses_last4() {
    let r = make();
    let out = r.redact_irreversible("api key sk-abcdefghijklmnopqrstuvwx");
    assert!(out.contains("[REDACTED:api_key#"));
    assert!(!out.contains("sk-abcdefghijklmnopqrstuvwx"));
}

#[test]
fn reversible_returns_tokens() {
    let r = make();
    let (out, matches) = r.redact_reversible("password=hunter2pass");
    assert_eq!(matches.len(), 1);
    // C19: 仅脱敏值, 保留可见标签前缀 (DLP 惯例: 字段名可见, 机密脱敏)。
    assert!(out.starts_with("password=[REDACTED:password#tok_"));
    assert!(!out.contains("hunter2pass"), "value must be redacted");
    // 存原始值 (仅值, 非全匹配) 供 reveal 还原。
    assert_eq!(matches[0].original, "hunter2pass");
}

#[test]
fn reversible_multiple_fields() {
    let r = make();
    let input = "sk-abcdefghijklmnopqrstuvwx and password=secret123";
    let (out, matches) = r.redact_reversible(input);
    assert_eq!(matches.len(), 2, "api_key + password both matched");
    assert!(out.contains("[REDACTED:api_key#tok_"));
    assert!(out.contains("[REDACTED:password#tok_"));
}

#[test]
fn extract_placeholders_round_trips() {
    let r = make();
    let input = "id 110101199003077654 here";
    let (redacted, matches) = r.redact_reversible(input);
    let placeholders = r.extract_placeholders(&redacted);
    assert_eq!(placeholders.len(), 1);
    assert_eq!(placeholders[0].1, matches[0].token_id);
}

#[test]
fn no_sensitive_unchanged() {
    let r = make();
    let (out, matches) = r.redact_reversible("hello world");
    assert_eq!(out, "hello world");
    assert!(matches.is_empty());
}

#[test]
fn has_sensitive_detects() {
    let r = make();
    assert!(r.has_sensitive("sk-abcdefghijklmnopqrstuvwx"));
    assert!(!r.has_sensitive("plain text"));
}

// L6 span 追踪: id_number 不腐蚀先前占位符。原顺序 replace_all 让 id_number 在
// tok_<32hex> (含 17 位数字子串) 上二次匹配 → 破占位符 → extract_placeholders 找不到 →
// reveal 撞 H6 → 可逆降级不可逆。span 追踪在原内容单趟收集拒重叠, 占位符永不写回原内容。
#[test]
fn l6_id_number_does_not_corrupt_placeholder() {
    let r = make();
    // sk- 值尾随 17 位数字 (110101199003077654) —— api_key 命中全值, id_number 勿二次吞尾。
    let input = "api key sk-abcdefghijklmnopqrstuvwx110101199003077654";
    let (redacted, matches) = r.redact_reversible(input);
    let placeholders = r.extract_placeholders(&redacted);
    assert_eq!(
        placeholders.len(),
        matches.len(),
        "占位符数须 == matches 数 (无腐蚀); redacted={redacted}"
    );
    assert!(
        !redacted.contains("110101199003077654"),
        "id 值须脱敏非裸留"
    );
}

// L6 span 追踪: 重叠命中首模式优先, 次模式跳过 (id_number 落在 password 值内不二次吞)。
#[test]
fn l6_overlap_first_pattern_wins() {
    let r = make();
    // password 值含 17 位数字 —— password 命中值 (含数字), id_number span 重叠 → 跳过。
    let input = "password=secret110101199003077654";
    let (redacted, matches) = r.redact_reversible(input);
    let placeholders = r.extract_placeholders(&redacted);
    assert_eq!(placeholders.len(), matches.len(), "重叠勿双脱敏");
    assert_eq!(
        matches.len(),
        1,
        "password 值整体一个占位符, id_number 勿分裂"
    );
    assert!(redacted.starts_with("password=[REDACTED:password#tok_"));
}

// P0-8 (audit §2.7): CJK 内容触发 last4 字节切片 panic。中文密码 (3字节/字) 的 len()
// 是字节数, s[n-4..] 切到字符中间 → slice panic。审计复现: 5 个中文字符 (15 字节),
// last4 切 s[11..], 11 不是 char boundary (落在 '试' 内) → panic。修复按字符边界取末4字。
#[test]
fn p0_8_cjk_last4_no_panic() {
    let r = make();
    // 纯中文密码 (5 字符 = 15 字节): n=15, 旧码切 s[11..] → 11 落在字符内 panic。
    let out = r.redact_irreversible("password: 密码测试值");
    assert!(
        out.contains("[REDACTED:password#"),
        "CJK password must redact, not panic: {out}"
    );
    assert!(!out.contains("密码测试值"), "value must be redacted");
    // 末4字符 = "码测试值" (按字符, 非字节), 含占位符即可验证未 panic。
    assert!(
        out.ends_with("码测试值]"),
        "last4 must be last 4 CHARS not bytes: {out}"
    );
}

// P0-8: emoji (4字节/字) 同理。原字节切片在 emoji 上 panic。
#[test]
fn p0_8_emoji_last4_no_panic() {
    let r = make();
    let out = r.redact_irreversible("password: secret😀🔒");
    assert!(
        out.contains("[REDACTED:password#"),
        "emoji password must redact, not panic: {out}"
    );
}

// P1-1 (audit §1.10): DLP 脱敏盲区扩展 —— 9 类新凭据覆盖。

#[test]
fn p1_1_jwt_redacted() {
    let r = make();
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let (out, matches) = r.redact_reversible(jwt);
    assert_eq!(matches.len(), 1, "JWT one token: {out}");
    assert!(out.contains("[REDACTED:jwt#tok_"), "JWT must redact: {out}");
    assert!(!out.contains("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
}

#[test]
fn p1_1_oauth_bearer_redacted() {
    let r = make();
    let (out, matches) = r.redact_reversible("Authorization: Bearer dGhpcyBpcyBhIHRlc3QgdG9rZW4");
    assert_eq!(matches.len(), 1, "bearer one token: {out}");
    assert!(out.contains("Bearer "), "prefix retained: {out}");
    assert!(out.contains("[REDACTED:oauth_bearer#tok_"));
    assert!(!out.contains("dGhpcyBpcyBhIHRlc3QgdG9rZW4"));
}

#[test]
fn p1_1_aws_secret_redacted() {
    let r = make();
    // 标准 AWS Secret Access Key 示例 (40 字符, 多样性)。
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let (out, matches) = r.redact_reversible(secret);
    assert_eq!(matches.len(), 1, "AWS secret one token: {out}");
    assert!(out.contains("[REDACTED:aws_secret#tok_"));
    assert!(!out.contains(secret));
}

#[test]
fn p1_1_aws_secret_rejects_homogeneous() {
    let r = make();
    // 40 全同字符 → 字符多样性 < 6 → validator 拒, 不脱敏 (假阳性防御)。
    let (out, matches) = r.redact_reversible("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(
        matches.is_empty(),
        "homogeneous 40-char not a secret: {out}"
    );
    assert_eq!(out, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

#[test]
fn p1_1_credit_card_luhn_redacted() {
    let r = make();
    // 通过 Luhn 的测试卡号 (Visa 4242…)。
    let (out, matches) = r.redact_reversible("card 4242424242424242 here");
    assert_eq!(matches.len(), 1, "Luhn-valid card one token: {out}");
    assert!(out.contains("[REDACTED:credit_card#tok_"));
    assert!(!out.contains("4242424242424242"));
}

#[test]
fn p1_1_credit_card_rejects_non_luhn() {
    let r = make();
    // 16 位但不过 Luhn → validator 拒。
    let (out, matches) = r.redact_reversible("ref 1234567890123456 end");
    assert!(matches.is_empty(), "non-Luhn 16-digit not a card: {out}");
    assert!(!out.contains("REDACTED"));
}

#[test]
fn p1_1_credit_card_boundary_not_substring_of_id() {
    let r = make();
    // 18 位身份证号含 16 位子串, 但边界校验拒子段 (前后有数字) → 仅 id_number 脱敏, card 不二次吞。
    let (out, matches) = r.redact_reversible("id 110101199003077654 end");
    let kinds: Vec<&str> = matches
        .iter()
        .map(|m| m.placeholder.split('#').next().unwrap())
        .collect();
    // id_number 命中 (无标签, 落 id_number 模式); credit_card 须被边界 validator 拒 (前/后有数字)。
    assert!(
        !kinds.iter().any(|k| k.starts_with("[REDACTED:credit_card")),
        "card must not eat id substring: {out}"
    );
}

#[test]
fn p1_1_phone_redacted() {
    let r = make();
    let (out, matches) = r.redact_reversible("call 13800138000 now");
    assert_eq!(matches.len(), 1, "phone one token: {out}");
    assert!(out.contains("[REDACTED:phone#tok_"));
    assert!(!out.contains("13800138000"));
}

#[test]
fn p1_1_conn_string_redacted() {
    let r = make();
    let (out, matches) = r.redact_reversible("postgres://admin:s3cr3tpw@db.host:5432/prod");
    assert_eq!(matches.len(), 1, "conn_string one token: {out}");
    assert!(
        out.contains("postgres://admin:"),
        "protocol+user retained: {out}"
    );
    assert!(out.contains("@db.host:5432"), "host retained: {out}");
    assert!(out.contains("[REDACTED:conn_string#tok_"));
    assert!(!out.contains("s3cr3tpw"));
}

#[test]
fn p1_1_stripe_key_redacted() {
    let r = make();
    let (out, matches) = r.redact_reversible("key sk_live_26PHvmFk9Oz6y4Kq5g5Q5Q5Q5Q5Q5Q5Q");
    assert_eq!(matches.len(), 1, "stripe key one token: {out}");
    assert!(out.contains("[REDACTED:api_key#tok_"));
}

#[test]
fn p1_1_secret_kv_redacted() {
    let r = make();
    let (out, matches) = r.redact_reversible(r#"{"token": "ghp_abcdefABCDEF1234567890abcdef"}"#);
    // token= 键值命中; 也可能 ghp_ 前缀 api_key 命中 (重叠, 先到先拒)。
    assert!(
        !matches.is_empty(),
        "secret_kv or api_key must match: {out}"
    );
    assert!(out.contains("REDACTED"));
}

#[test]
fn p1_1_env_kv_redacted() {
    let r = make();
    let (out, matches) =
        r.redact_reversible("DATABASE_URL=postgres://u:p@h\nAWS_SECRET_KEY=ABCDEF");
    assert!(!matches.is_empty(), "env KV must match: {out}");
    assert!(out.contains("REDACTED"));
}

// issue #2: PII 模式类 (phone 已有, 补 email/ipv4/bankcard 覆盖验证)。

#[test]
fn issue2_email_redacted() {
    let r = make();
    let (out, matches) = r.redact_reversible("contact user@example.com for details");
    assert_eq!(matches.len(), 1, "email one token: {out}");
    assert!(out.contains("[REDACTED:email#tok_"), "email tag: {out}");
    assert!(!out.contains("user@example.com"));
}

#[test]
fn issue2_email_irreversible_last4() {
    let r = make();
    let out = r.redact_irreversible("mail alice.test+tag@sub.domain.co.uk end");
    assert!(
        out.contains("[REDACTED:email#"),
        "email irreversible: {out}"
    );
    assert!(!out.contains("alice.test+tag@sub.domain.co.uk"));
}

#[test]
fn issue2_ipv4_redacted() {
    let r = make();
    let (out, matches) = r.redact_reversible("ssh root@10.0.0.1 then ping 8.8.8.8");
    assert_eq!(matches.len(), 2, "two ipv4 tokens: {out}");
    assert!(out.contains("[REDACTED:ipv4#tok_"), "ipv4 tag: {out}");
    assert!(!out.contains("10.0.0.1"));
    assert!(!out.contains("8.8.8.8"));
}

#[test]
fn issue2_ipv4_rejects_invalid_octet() {
    let r = make();
    // 256 超出 u8 → validator 拒, 不脱敏 (非真实 ipv4)。
    let (out, matches) = r.redact_reversible("version 256.1.1.1 bad");
    assert!(
        matches.is_empty(),
        "256.x must reject (not real ipv4): {out}"
    );
    assert!(!out.contains("REDACTED"));
}

#[test]
fn issue2_bankcard_via_credit_card_redacted() {
    let r = make();
    // 16 位 Luhn 有效卡号 (issue #2 bankcard 13-19 位) → credit_card 脱敏。
    let (out, matches) = r.redact_reversible("bankcard 4111111111111111 paid");
    assert_eq!(matches.len(), 1, "bankcard one token: {out}");
    assert!(out.contains("[REDACTED:credit_card#tok_"));
    assert!(!out.contains("4111111111111111"));
}

#[test]
fn issue2_phone_present() {
    let r = make();
    let (out, matches) = r.redact_reversible("phone 15912345678 call");
    assert_eq!(matches.len(), 1, "phone (issue #2) one token: {out}");
    assert!(out.contains("[REDACTED:phone#tok_"));
}
