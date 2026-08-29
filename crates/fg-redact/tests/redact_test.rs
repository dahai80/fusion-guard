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
    // issue #13: 用合法 GB 身份证 (110101199003077651, 校验位 '1') —— id_number 带校验 validator 后,
    // 不合法 id (如 ...77654) 被拒不脱敏, 须用合法 id 验证占位符往返。
    let input = "id 110101199003077651 here";
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
    // sk- 值尾随 18 位合法身份证 (110101199003077651, issue #13 改合法 GB) —— api_key 命中全值,
    // id_number 勿二次吞尾 (span 重叠跳过)。
    let input = "api key sk-abcdefghijklmnopqrstuvwx110101199003077651";
    let (redacted, matches) = r.redact_reversible(input);
    let placeholders = r.extract_placeholders(&redacted);
    assert_eq!(
        placeholders.len(),
        matches.len(),
        "占位符数须 == matches 数 (无腐蚀); redacted={redacted}"
    );
    assert!(
        !redacted.contains("110101199003077651"),
        "id 值须脱敏非裸留"
    );
}

// L6 span 追踪: 重叠命中首模式优先, 次模式跳过 (id_number 落在 password 值内不二次吞)。
#[test]
fn l6_overlap_first_pattern_wins() {
    let r = make();
    // password 值含 18 位合法身份证 (110101199003077651) —— password 命中值 (含数字),
    // id_number span 重叠 → 跳过。
    let input = "password=secret110101199003077651";
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
    // issue #13: 18 位合法身份证 (110101199003077651) —— id_number (GB 校验通过, 且排 credit_card
    // 之前) 先吃, credit_card span 重叠被跳 (不再吞 17 位前导数字剩悬空 X, 缺陷 1 修复)。
    let (out, matches) = r.redact_reversible("id 110101199003077651 end");
    let kinds: Vec<&str> = matches
        .iter()
        .map(|m| m.placeholder.split('#').next().unwrap())
        .collect();
    // id_number 命中 (合法 GB, 先于 credit_card); credit_card 须被重叠拒 (id_number 已吃)。
    assert!(
        kinds.iter().any(|k| k.starts_with("[REDACTED:id_number")),
        "id_number (valid GB) must redact: {out}"
    );
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

// issue #10: redact_credentials() 仅脱凭据子集, 跳过 PII。
// 消费方 (fusion-memory) 自带更准 PII 逻辑, 只需 fg-redact 补凭据覆盖。

#[test]
fn issue10_credentials_redacts_jwt_and_password() {
    let r = make();
    let input = "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c and password=hunter2pass";
    let out = r.redact_credentials(input);
    assert!(
        out.contains("[REDACTED:jwt]"),
        "jwt (credential) redacted: {out}"
    );
    assert!(
        out.contains("[REDACTED:password]"),
        "password (credential) redacted: {out}"
    );
    assert!(!out.contains("hunter2pass"), "credential value stripped");
    assert!(
        !out.contains("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        "jwt value stripped"
    );
}

#[test]
fn issue10_credentials_skips_idcard() {
    // issue #13: 合法 GB 身份证 (11010119900307889X, 校验位 X) —— redact_credentials() 跳 PII
    // → 原样保留 (消费方按需选类)。issue #13 修复后 full redact() 会脱敏为 id_number, 本测验证
    // credentials-only 子集正确跳过 PII (与 full redact 分歧)。
    let r = make();
    let out = r.redact_credentials("身份证 11010119900307889X 复印件");
    assert_eq!(
        out, "身份证 11010119900307889X 复印件",
        "id-card untouched by credentials-only: {out}"
    );
    assert!(!out.contains("REDACTED"), "no PII redaction: {out}");
}

#[test]
fn issue10_credentials_skips_long_non_luhn_digits() {
    // issue #13: 18 位非 PII 数字串 (订单号 999999999999999999) —— GB 校验不通过 → full redact()
    // 也不脱敏 (缺陷 2 修复), credentials-only 同样跳过 → 原样保留。
    let r = make();
    let out = r.redact_credentials("order 999999999999999999 timestamp");
    assert_eq!(
        out, "order 999999999999999999 timestamp",
        "non-PII long digits untouched: {out}"
    );
    assert!(!out.contains("REDACTED"), "no PII redaction: {out}");
}

#[test]
fn issue10_credentials_skips_phone_email_ipv4() {
    let r = make();
    let out = r.redact_credentials("call 13800138000 mail user@example.com ip 10.0.0.1");
    assert_eq!(
        out, "call 13800138000 mail user@example.com ip 10.0.0.1",
        "phone/email/ipv4 (PII) untouched: {out}"
    );
    assert!(!out.contains("REDACTED"), "no PII redaction: {out}");
}

#[test]
fn issue10_redact_with_patterns_subset() {
    // 通用原语: 仅跑 private_key + jwt, 跳过其余 (含 password)。
    let r = make();
    let input = "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c and password=hunter2pass";
    let out = r.redact_with_patterns(input, &["private_key", "jwt"]);
    assert!(
        out.contains("[REDACTED:jwt]"),
        "jwt in subset redacted: {out}"
    );
    // password 不在传入子集 → 不脱 (值裸留)。
    assert!(
        out.contains("password=hunter2pass"),
        "password outside subset untouched: {out}"
    );
}

#[test]
fn issue10_redact_with_patterns_unknown_name_ignored() {
    let r = make();
    let out = r.redact_with_patterns("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", &["nonexistent"]);
    assert_eq!(
        out,
        "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "unknown name ignored, no redaction: {out}"
    );
}

#[test]
fn issue10_credentials_full_set_matches_redact_on_credential_only_input() {
    // 纯凭据输入: redact_credentials() 与 redact() 产出一致 (无 PII 可分歧)。
    let r = make();
    let input = "key sk-abcdefghijklmnopqrstuvwx and password=secret123";
    assert_eq!(
        r.redact_credentials(input),
        r.redact(input),
        "credential-only input: credentials == full redact"
    );
}

// issue #13: PII 3 缺陷修复 —— idcard 被 credit_card 错吞 / id_number 误吞长数字 / +86 phone 被拒。

// 缺陷 1: 合法 GB 身份证 (尾 X) 须脱敏为 id_number, 非 credit_card, 无悬空 X。
#[test]
fn issue13_idcard_not_eaten_by_credit_card() {
    let r = make();
    // 11010119900307889X = 合法 GB (校验位 X)。原: credit_card 吃 17 位前导数字 → "...credit_card]X"
    // (悬空 X)。修复: id_number (GB 校验, 排 credit_card 之前) 先吃全 18 字符 → id_number 标签, 无悬空。
    let out = r.redact("身份证 11010119900307889X 复印件");
    assert!(
        out.contains("[REDACTED:id_number]"),
        "valid id-card must tag id_number not credit_card: {out}"
    );
    assert!(
        !out.contains("credit_card"),
        "id-card must not be misclassified as credit_card: {out}"
    );
    assert!(
        !out.contains("]X") && !out.contains("]x"),
        "no dangling X after redaction: {out}"
    );
}

// 缺陷 1 附加: 合法身份证 (尾数字) 同样正确, id_number 排序吃前。
#[test]
fn issue13_idcard_digit_tail_correct() {
    let r = make();
    // 110101199003077651 = 合法 GB (校验位 '1')。
    let out = r.redact("id 110101199003077651 end");
    assert!(
        out.contains("[REDACTED:id_number]"),
        "valid id-card (digit tail) must tag id_number: {out}"
    );
    assert!(!out.contains("credit_card"), "not credit_card: {out}");
}

// 缺陷 2: 非 PII 长 18 位数字串 (订单号) 须被 GB 校验拒, 不脱敏。
#[test]
fn issue13_id_number_rejects_non_pii_long_digits() {
    let r = make();
    // 999999999999999999 = 订单号样, GB 校验不通过 (sum=900, rem=9, 期望 '3' ≠ '9')。
    let out = r.redact("order 999999999999999999 timestamp");
    assert_eq!(
        out, "order 999999999999999999 timestamp",
        "non-PII long digits must not be redacted (GB rejects): {out}"
    );
    assert!(
        !out.contains("REDACTED"),
        "no false id_number redaction: {out}"
    );
}

// 缺陷 3: +86 国际前缀手机号须被 phone 脱敏。
#[test]
fn issue13_phone_accepts_plus86_prefix() {
    let r = make();
    let out = r.redact("call +8613912345678 now");
    assert!(
        out.contains("[REDACTED:phone]"),
        "+86 phone must be redacted: {out}"
    );
    assert!(!out.contains("13912345678"), "phone value stripped: {out}");
}

// 缺陷 3 附加: 0086 前缀同样接受。
#[test]
fn issue13_phone_accepts_0086_prefix() {
    let r = make();
    let out = r.redact("call 008613912345678 now");
    assert!(
        out.contains("[REDACTED:phone]"),
        "0086 phone must be redacted: {out}"
    );
}

// 缺陷 3 边界: 裸号 (无前缀) 仍正确; 更长数字子段前的 +86 不误吞。
#[test]
fn issue13_phone_bare_and_boundary() {
    let r = make();
    // 裸号仍脱敏。
    assert!(
        r.redact("call 13800138000 now")
            .contains("[REDACTED:phone]"),
        "bare phone still redacted"
    );
    // 2008613912345678 (前缀 '2') → span 从 idx1 起的 "0086...", start-1='2' 数字 → 边界拒, 不误吞。
    // 此串无合法 phone (20086… 非 1[3-9] 开头裸号), 整体不脱敏。
    let out = r.redact("x 2008613912345678 y");
    assert!(
        !out.contains("[REDACTED:phone]"),
        "digit-prefixed +86 not falsely eaten: {out}"
    );
}

// has_sensitive 对合法身份证须检出 (id_number 带 validator 后不被静默漏判)。
#[test]
fn issue13_has_sensitive_detects_valid_id() {
    let r = make();
    assert!(
        r.has_sensitive("id 11010119900307889X here"),
        "valid id-card must be detected as sensitive"
    );
    assert!(
        !r.has_sensitive("order 999999999999999999 here"),
        "non-PII long digits must not be sensitive"
    );
}
