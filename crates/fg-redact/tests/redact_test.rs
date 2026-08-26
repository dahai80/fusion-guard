use fg_redact::Redactor;

#[test]
fn irreversible_uses_last4() {
    let r = Redactor::new();
    let out = r.redact_irreversible("api key sk-abcdefghijklmnopqrstuvwx");
    assert!(out.contains("[REDACTED:api_key#"));
    assert!(!out.contains("sk-abcdefghijklmnopqrstuvwx"));
}

#[test]
fn reversible_returns_tokens() {
    let r = Redactor::new();
    let (out, matches) = r.redact_reversible("password=hunter2pass");
    assert_eq!(matches.len(), 1);
    assert!(out.starts_with("[REDACTED:password#tok_"));
    assert_eq!(matches[0].original, "password=hunter2pass");
}

#[test]
fn reversible_multiple_fields() {
    let r = Redactor::new();
    let input = "sk-abcdefghijklmnopqrstuvwx and password=secret123";
    let (out, matches) = r.redact_reversible(input);
    assert_eq!(matches.len(), 2, "api_key + password both matched");
    assert!(out.contains("[REDACTED:api_key#tok_"));
    assert!(out.contains("[REDACTED:password#tok_"));
}

#[test]
fn extract_placeholders_round_trips() {
    let r = Redactor::new();
    let input = "id 110101199003077654 here";
    let (redacted, matches) = r.redact_reversible(input);
    let placeholders = r.extract_placeholders(&redacted);
    assert_eq!(placeholders.len(), 1);
    assert_eq!(placeholders[0].1, matches[0].token_id);
}

#[test]
fn no_sensitive_unchanged() {
    let r = Redactor::new();
    let (out, matches) = r.redact_reversible("hello world");
    assert_eq!(out, "hello world");
    assert!(matches.is_empty());
}

#[test]
fn has_sensitive_detects() {
    let r = Redactor::new();
    assert!(r.has_sensitive("sk-abcdefghijklmnopqrstuvwx"));
    assert!(!r.has_sensitive("plain text"));
}
