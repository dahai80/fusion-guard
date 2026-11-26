use fg_redact::Redactor;

// M4: Redactor::new() returns Result; tests use expect (static pattern compilation should never fail).
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
    // C19: only the value is redacted, the visible label prefix is retained (DLP convention:
    // field name visible, secret redacted).
    assert!(out.starts_with("password=[REDACTED:password#tok_"));
    assert!(!out.contains("hunter2pass"), "value must be redacted");
    // Stores the original value (value only, not the full match) for reveal restoration.
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
    // issue #13: use a valid GB ID (110101199003077651, check char '1') — after id_number gained
    // its checksum validator, invalid ids (e.g. ...77654) are rejected and not redacted, so the
    // placeholder round trip must be verified with a valid id.
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

// L6 span tracking: id_number must not corrupt earlier placeholders. The original sequential
// replace_all let id_number match again on tok_<32hex> (containing 17-digit substrings) →
// corrupted the placeholder → extract_placeholders found nothing → reveal hit H6 → reversible
// degraded to irreversible. Span tracking collects on the original content in one pass with
// overlap rejection; placeholders are never written back into the original content.
#[test]
fn l6_id_number_does_not_corrupt_placeholder() {
    let r = make();
    // The sk- value trails an 18-digit valid ID (110101199003077651, valid GB per issue #13) —
    // api_key takes the full value; id_number must not swallow the tail a second time (span
    // overlap skipped).
    let input = "api key sk-abcdefghijklmnopqrstuvwx110101199003077651";
    let (redacted, matches) = r.redact_reversible(input);
    let placeholders = r.extract_placeholders(&redacted);
    assert_eq!(
        placeholders.len(),
        matches.len(),
        "placeholder count must == matches count (no corruption); redacted={redacted}"
    );
    assert!(
        !redacted.contains("110101199003077651"),
        "id value must be redacted, not left bare"
    );
}

// L6 span tracking: on overlap the first pattern wins and the later one is skipped (id_number
// landing inside a password value does not swallow it a second time).
#[test]
fn l6_overlap_first_pattern_wins() {
    let r = make();
    // The password value contains an 18-digit valid ID (110101199003077651) — password takes the
    // value (digits included); id_number's span overlaps → skipped.
    let input = "password=secret110101199003077651";
    let (redacted, matches) = r.redact_reversible(input);
    let placeholders = r.extract_placeholders(&redacted);
    assert_eq!(
        placeholders.len(),
        matches.len(),
        "overlap must not double-redact"
    );
    assert_eq!(
        matches.len(),
        1,
        "password value is one placeholder as a whole; id_number must not split it"
    );
    assert!(redacted.starts_with("password=[REDACTED:password#tok_"));
}

// P0-8 (audit §2.7): CJK content triggered the last4 byte-slice panic. For a Chinese password
// (3 bytes/char) len() is the byte count, so s[n-4..] cut into the middle of a char → slice
// panic. Audit repro: 5 Chinese chars (15 bytes); last4 cut s[11..], and 11 is not a char
// boundary (it lands inside a char) → panic. Fix: take the last 4 chars on char boundaries.
// NOTE: the Chinese fixture is intentionally kept — this is product-data test coverage for CJK
// input; an ASCII fixture would pass even with the old byte-slicing code.
#[test]
fn p0_8_cjk_last4_no_panic() {
    let r = make();
    // Pure Chinese password (5 chars = 15 bytes): n=15, old code cut s[11..] → 11 lands inside a
    // char → panic.
    // i18n: user-facing — CJK product-data fixture, load-bearing for the char-boundary test
    let out = r.redact_irreversible("password: 密码测试值");
    assert!(
        out.contains("[REDACTED:password#"),
        "CJK password must redact, not panic: {out}"
    );
    // i18n: user-facing — fixture assertion
    assert!(!out.contains("密码测试值"), "value must be redacted");
    // The last 4 chars are the last 4 CHARS of the CJK fixture (by char, not byte); asserting the
    // suffixed placeholder verifies no panic.
    assert!(
        // i18n: user-facing — fixture assertion
        out.ends_with("码测试值]"),
        "last4 must be last 4 CHARS not bytes: {out}"
    );
}

// P0-8: emoji (4 bytes/char) behaves the same. The original byte slicing panicked on emoji.
#[test]
fn p0_8_emoji_last4_no_panic() {
    let r = make();
    let out = r.redact_irreversible("password: secret😀🔒");
    assert!(
        out.contains("[REDACTED:password#"),
        "emoji password must redact, not panic: {out}"
    );
}

// P1-1 (audit §1.10): DLP redaction blind-spot expansion — 9 new credential classes covered.

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
    // Standard AWS Secret Access Key example (40 chars, diverse).
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let (out, matches) = r.redact_reversible(secret);
    assert_eq!(matches.len(), 1, "AWS secret one token: {out}");
    assert!(out.contains("[REDACTED:aws_secret#tok_"));
    assert!(!out.contains(secret));
}

#[test]
fn p1_1_aws_secret_rejects_homogeneous() {
    let r = make();
    // 40 identical chars → char diversity < 6 → validator rejects, no redaction (false-positive
    // defense).
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
    // Test card number that passes Luhn (Visa 4242…).
    let (out, matches) = r.redact_reversible("card 4242424242424242 here");
    assert_eq!(matches.len(), 1, "Luhn-valid card one token: {out}");
    assert!(out.contains("[REDACTED:credit_card#tok_"));
    assert!(!out.contains("4242424242424242"));
}

#[test]
fn p1_1_credit_card_rejects_non_luhn() {
    let r = make();
    // 16 digits but fails Luhn → validator rejects.
    let (out, matches) = r.redact_reversible("ref 1234567890123456 end");
    assert!(matches.is_empty(), "non-Luhn 16-digit not a card: {out}");
    assert!(!out.contains("REDACTED"));
}

#[test]
fn p1_1_credit_card_boundary_not_substring_of_id() {
    let r = make();
    // issue #13: 18-digit valid ID (110101199003077651) — id_number (GB check passes, and it is
    // ordered before credit_card) consumes it first; credit_card's span overlaps and is skipped
    // (no longer eats the 17-digit leading part leaving a dangling X; defect 1 fixed).
    let (out, matches) = r.redact_reversible("id 110101199003077651 end");
    let kinds: Vec<&str> = matches
        .iter()
        .map(|m| m.placeholder.split('#').next().unwrap())
        .collect();
    // id_number hit (valid GB, before credit_card); credit_card must be rejected by overlap
    // (id_number already consumed it).
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
    // token= key-value hit; the ghp_ prefixed api_key may also hit (overlap, first accepted wins).
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

// issue #2: PII pattern classes (phone already existed; adds email/ipv4/bankcard coverage).

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
    // 256 exceeds u8 → validator rejects, no redaction (not a real ipv4).
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
    // 16-digit Luhn-valid card (issue #2 bankcard 13-19 digits) → redacted by credit_card.
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

// issue #10: redact_credentials() redacts only the credential subset, skipping PII.
// Consumers (fusion-memory) bring their own more accurate PII logic; they only need fg-redact for
// credential coverage.

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
    // issue #13: valid GB ID (11010119900307889X, check char X) — redact_credentials() skips PII
    // → left as-is (consumers pick classes as needed). After the issue #13 fixes, full redact()
    // would redact it as id_number; this test verifies the credentials-only subset correctly
    // skips PII (diverging from full redact).
    let r = make();
    let out = r.redact_credentials("id card 11010119900307889X copy");
    assert_eq!(
        out, "id card 11010119900307889X copy",
        "id-card untouched by credentials-only: {out}"
    );
    assert!(!out.contains("REDACTED"), "no PII redaction: {out}");
}

#[test]
fn issue10_credentials_skips_long_non_luhn_digits() {
    // issue #13: 18-digit non-PII digit string (order number 999999999999999999) — fails the GB
    // check → full redact() does not redact it either (defect 2 fix); credentials-only skips it
    // the same way → left as-is.
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
    // Generic primitive: runs only private_key + jwt, skipping the rest (password included).
    let r = make();
    let input = "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c and password=hunter2pass";
    let out = r.redact_with_patterns(input, &["private_key", "jwt"]);
    assert!(
        out.contains("[REDACTED:jwt]"),
        "jwt in subset redacted: {out}"
    );
    // password is not in the given subset → not redacted (value left bare).
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
    // Credential-only input: redact_credentials() and redact() produce identical output (no PII
    // to diverge on).
    let r = make();
    let input = "key sk-abcdefghijklmnopqrstuvwx and password=secret123";
    assert_eq!(
        r.redact_credentials(input),
        r.redact(input),
        "credential-only input: credentials == full redact"
    );
}

// issue #13: 3 PII defect fixes — idcard wrongly swallowed by credit_card / id_number swallowing
// long digit strings / +86 phone rejected.

// Defect 1: a valid GB ID (trailing X) must be redacted as id_number, not credit_card, with no
// dangling X.
#[test]
fn issue13_idcard_not_eaten_by_credit_card() {
    let r = make();
    // 11010119900307889X = valid GB (check char X). Before: credit_card ate the 17-digit leading
    // part → "...credit_card]X" (dangling X). Fix: id_number (GB check, ordered before
    // credit_card) consumes the full 18 chars first → id_number tag, no dangling tail.
    let out = r.redact("id card 11010119900307889X copy");
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

// Defect 1 addendum: a valid ID (digit tail) is handled correctly too; id_number's ordering wins.
#[test]
fn issue13_idcard_digit_tail_correct() {
    let r = make();
    // 110101199003077651 = valid GB (check char '1').
    let out = r.redact("id 110101199003077651 end");
    assert!(
        out.contains("[REDACTED:id_number]"),
        "valid id-card (digit tail) must tag id_number: {out}"
    );
    assert!(!out.contains("credit_card"), "not credit_card: {out}");
}

// Defect 2: a non-PII 18-digit string (order number) must be rejected by the GB check, not
// redacted.
#[test]
fn issue13_id_number_rejects_non_pii_long_digits() {
    let r = make();
    // 999999999999999999 = order-number-like, fails the GB check (sum=900, rem=9, expected '3' ≠ '9').
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

// Defect 3: a +86 international-prefixed phone number must be redacted by phone.
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

// Defect 3 addendum: the 0086 prefix is accepted the same way.
#[test]
fn issue13_phone_accepts_0086_prefix() {
    let r = make();
    let out = r.redact("call 008613912345678 now");
    assert!(
        out.contains("[REDACTED:phone]"),
        "0086 phone must be redacted: {out}"
    );
}

// Defect 3 boundary: a bare number (no prefix) still works; a +86 preceded by a longer digit
// segment is not falsely swallowed.
#[test]
fn issue13_phone_bare_and_boundary() {
    let r = make();
    // Bare number still redacted.
    assert!(
        r.redact("call 13800138000 now")
            .contains("[REDACTED:phone]"),
        "bare phone still redacted"
    );
    // 2008613912345678 (prefix '2') → span would start at idx1 with "0086...", start-1='2' is a
    // digit → boundary rejects, no false swallow.
    // This string contains no valid phone (20086… is not a bare 1[3-9] number), so nothing is
    // redacted.
    let out = r.redact("x 2008613912345678 y");
    assert!(
        !out.contains("[REDACTED:phone]"),
        "digit-prefixed +86 not falsely eaten: {out}"
    );
}

// has_sensitive must detect a valid ID (not silently missed after id_number gained its validator).
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
