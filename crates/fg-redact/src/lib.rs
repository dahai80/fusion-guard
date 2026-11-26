use regex::Regex;
use serde::Serialize;
use std::cmp::Reverse;
use std::sync::OnceLock;
use uuid::Uuid;

// issue #10/#13: credential pattern subset names (non-PII). Consumers configure this constant via
// redact_credentials() or redact_with_patterns(), avoiding drift of hardcoded names as defs evolve.
// PII subset = email/ipv4/credit_card/phone/id_number — after the issue #13 fixes (id_number GB
// validation/priority + phone accepting +86), PII behavior is correct and consumers can route PII
// through fg-redact; redact_credentials() remains for scenarios needing only the credential subset.
pub const CREDENTIAL_PATTERNS: &[&str] = &[
    "private_key",
    "jwt",
    "oauth_bearer",
    "api_key",
    "conn_string",
    "password",
    "secret_kv",
    "env_kv",
    "netrc",
    "aws_secret",
];

// M4: compile failure no longer panics (was 4x .unwrap()); returns Result so AuditEngine::new
// decides (fail-closed).
// P2: redact_counted returns (String, hit_count) in a single pass — evaluate skips the separate
// has_sensitive second scan.
// P1-1 (audit §1.10): DLP redaction blind-spot expansion — adds AWS Secret/JWT/OAuth bearer/credit
// card (Luhn)/phone/GCP/Azure/Stripe key/credentials embedded in connection strings/.env-style
// generic KEY=value. Patterns carry an optional validator (rule 5: deterministic checks like
// Luhn/charset use code, not a model); candidate spans where the validator returns false are skipped.
pub struct Redactor {
    patterns: Vec<PatternDef>,
}

struct PatternDef {
    name: &'static str,
    re: Regex,
    // P1-1 (rule 5): validator receives (content, span start, span end) — the regex crate has no
    // lookaround, so boundaries (adjacent chars not of the same class) + Luhn + character
    // diversity are checked in code, not via model or regex.
    validator: Option<ValidatorFn>,
    // issue #7: serializable tag for the validator (explicitly labeled per rule 5, not a fn-pointer
    // map). Exposed by the IPC dump to downstream consumers (fusion-gateway PII SSOT subscribers);
    // consumers re-implement the validator from the tag (the algorithms are small and documented).
    validator_tag: ValidatorTag,
    // issue #7: original pattern string (re is a non-serializable Regex); the dump exposes the raw string.
    pattern_str: &'static str,
}

type ValidatorFn = fn(&str, usize, usize) -> bool;

// issue #7: serializable dump of redaction pattern definitions (returned by guard.redact.patterns.dump).
// Consumers (fusion-gateway) fetch + cache it instead of vendoring, eliminating manual lockstep updates.
#[derive(Debug, Clone, Serialize)]
pub struct PatternDefDump {
    pub name: &'static str,
    pub regex: &'static str,
    pub validator: ValidatorTag,
}

// issue #7: validator tag enum (serde snake_case = issue contract "none"|"ipv4"|"aws_secret"|"luhn"|"phone"|"id_card").
// Not fn pointers — the IPC payload must be serializable; consumers re-implement from the tag.
// issue #13 adds IdCard (GB 11643 ID-card checksum).
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorTag {
    None,
    Ipv4,
    AwsSecret,
    Luhn,
    Phone,
    IdCard,
}

pub struct ReversibleMatch {
    pub placeholder: String,
    pub token_id: String,
    pub original: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RedactError {
    #[error("redact regex compile failed: {0}")]
    Regex(#[from] regex::Error),
}

struct AcceptedMatch {
    start: usize,
    end: usize,
    name_tag: &'static str,
    value: String,
}

impl Redactor {
    // C19: redaction regexes cover real key encodings, not toy inputs.
    // P1-1 (audit §1.10): expand DLP coverage — AWS Secret/JWT/OAuth bearer/credit card (Luhn)/
    //   phone/GCP/Azure/Stripe/credentials embedded in connection strings/.env generic KEY=value.
    // Order is critical: long credentials + overlapping digit patterns must precede id_number
    //   (\d{17}[\dXx]) — otherwise a 40-char AWS Secret or a 13-19 digit credit card gets swallowed
    //   by a 17-digit substring of id_number. First accepted wins on overlap (collect_spans
    //   semantics), so the more specific/longer a pattern is, the earlier it goes.
    // Per pattern, group 1 (if present) = sensitive value; without group 1 (PEM blocks/OpenSSH/
    //   JWT/bearer/credit card/phone) the full match is the value.
    // Generic key-value patterns redact only the value, keeping the field name (DLP convention:
    //   label stays visible, secret is redacted).
    // M4: returns Result so compile failure can fail-closed (not a process panic).
    // Rule 5: Luhn (credit card) + base64 charset diversity (AWS Secret) use code validators,
    //   not regex and not a model.
    pub fn new() -> std::result::Result<Self, RedactError> {
        // (name, pattern, optional_validator, validator_tag, pattern_str)
        // issue #7: adds validator_tag + pattern_str — the dump exposes serializable definitions,
        // with no change to redaction behavior.
        let defs: [(
            &'static str,
            &str,
            Option<ValidatorFn>,
            ValidatorTag,
            &'static str,
        ); 15] = [
            // PEM blocks / OpenSSH / JWK — multi-line, highest priority, no overlap with short patterns.
            (
                "private_key",
                r#"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----|ssh-(?:rsa|ed25519|ecdsa) [A-Za-z0-9+/=]+|"(?:d|p|q|k|n)":\s*"[^"]+""#,
                None,
                ValidatorTag::None,
                r#"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----|ssh-(?:rsa|ed25519|ecdsa) [A-Za-z0-9+/=]+|"(?:d|p|q|k|n)":\s*"[^"]+""#,
            ),
            // JWT three-segment form (eyJ… . eyJ… . …) — base64url, full match. Precedes bare digit
            // patterns (prevents accidental swallowing of 17+ digit substrings).
            (
                "jwt",
                r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                None,
                ValidatorTag::None,
                r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            ),
            // OAuth bearer token (Authorization: Bearer …) — group 1 = token value, the "Bearer "
            // prefix stays visible.
            (
                "oauth_bearer",
                r"(?i)bearer\s+([A-Za-z0-9_\-\.=~:/+]+)",
                None,
                ValidatorTag::None,
                r"(?i)bearer\s+([A-Za-z0-9_\-\.=~:/+]+)",
            ),
            // GCP ya29 / Azure AIza / Stripe sk_live/sk_test plus original API key variants.
            (
                "api_key",
                r"(?i)(sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,}|ya29\.[A-Za-z0-9_\-]{20,}|api[_-]?key\s*[:=]\s*(\S+))",
                None,
                ValidatorTag::None,
                r"(?i)(sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,}|ya29\.[A-Za-z0-9_\-]{20,}|api[_-]?key\s*[:=]\s*(\S+))",
            ),
            // Credentials embedded in connection strings (postgres://user:pass@host,
            // mongodb://user:pass@, redis://:pass@).
            // Group 1 = user:pass (the secret); protocol + @host stay visible.
            (
                "conn_string",
                r"(?i)(?:postgres(?:ql)?|mongodb(?:\+srv)?|redis|mysql|amqp|ftp|sftp)://[^/\s:@]+:([^@/\s]+)@",
                None,
                ValidatorTag::None,
                r"(?i)(?:postgres(?:ql)?|mongodb(?:\+srv)?|redis|mysql|amqp|ftp|sftp)://[^/\s:@]+:([^@/\s]+)@",
            ),
            // Credential key-value patterns — explicit labels (password=/secret=/KEY=val) prove
            // secret intent; they take priority over bare digits.
            // password/passwd/pwd key-value — group 1 = value (the value may contain digits, so it
            // must precede id_number/credit_card to avoid being swallowed).
            (
                "password",
                r#"(?i)(?:password|passwd|pwd)\s*["']?\s*[:=]\s*["']?([^\s"']+)"#,
                None,
                ValidatorTag::None,
                r#"(?i)(?:password|passwd|pwd)\s*["']?\s*[:=]\s*["']?([^\s"']+)"#,
            ),
            // secret/token generic key-value (JSON/ENV/config) — group 1 = value. Generalizes the
            // PRD §8 "sensitive field" semantics.
            (
                "secret_kv",
                r#"(?i)(?:secret|token|access[_-]?token)["']?\s*[:=]\s*["']?([^\s"']{6,})"#,
                None,
                ValidatorTag::None,
                r#"(?i)(?:secret|token|access[_-]?token)["']?\s*[:=]\s*["']?([^\s"']{6,})"#,
            ),
            // .env-style generic KEY=value (uppercase underscore key names = config/credential
            // convention) — group 1 = value, key name stays visible.
            (
                "env_kv",
                r"(?m)^[A-Z][A-Z0-9_]{2,}=(\S+)",
                None,
                ValidatorTag::None,
                r"(?m)^[A-Z][A-Z0-9_]{2,}=(\S+)",
            ),
            // .netrc-style `password XXX` — group 1 = value.
            (
                "netrc",
                r"(?i)password\s+(\S+)",
                None,
                ValidatorTag::None,
                r"(?i)password\s+(\S+)",
            ),
            // PII: email (issue #2) — placed after credential patterns: the pass@host part of a
            //   connection string user:pass@host would be swallowed by email, so conn_string must
            //   consume it first (first accepted wins on overlap). Non-digit, no overlap with
            //   downstream id_number/phone.
            (
                "email",
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                None,
                ValidatorTag::None,
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            ),
            // PII: ipv4 (issue #2) — \b word boundaries + validator (each octet ≤255, boundary not
            // digit/dot).
            (
                "ipv4",
                r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
                Some(valid_ipv4),
                ValidatorTag::Ipv4,
                r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            ),
            // AWS Secret Access Key — 40 chars from the base64 set (A-Za-z0-9/+=), no AKIA prefix
            // (that is the access key id, already covered by api_key). The validator rejects
            // all-identical characters (aaaa…) to prevent false positives + boundary checks (the
            // regex crate has no lookaround; valid_aws_secret(content,s,e) checks that the
            // surrounding chars are not base64).
            (
                "aws_secret",
                r"[A-Za-z0-9/+=]{40}",
                Some(valid_aws_secret),
                ValidatorTag::AwsSecret,
                r"[A-Za-z0-9/+=]{40}",
            ),
            // ID number \d{17}[\dXx] — issue #13 defect 1+2 fix: adds GB 11643-1999 mod-11
            // validation (valid_id_card) and moves it before credit_card (first accepted wins on
            // overlap). Previously it was last + unvalidated, so (defect 2) any 18-digit string
            // (order numbers/timestamps) was swallowed; (defect 1) credit_card \d{13,19}+Luhn ate
            // the 17-digit leading part first, leaving a dangling X (...credit_card]X). Now entries
            // passing the GB check consume the full 18 chars first under the id_number tag — no
            // dangling tail.
            (
                "id_number",
                r"\d{17}[\dXx]",
                Some(valid_id_card),
                ValidatorTag::IdCard,
                r"\d{17}[\dXx]",
            ),
            // Credit card number \d{13,19} — validator runs Luhn + boundary checks (the regex crate
            // has no lookaround; valid_luhn(content,s,e) checks that surrounding chars are not
            // digits, preventing swallowing of id_number/phone substrings).
            // issue #13: id_number now precedes it, so a valid ID (18 chars, GB pass) is consumed
            // by id_number first and credit_card no longer eats its 17-digit leading part
            // (overlap rejected) — removing the dangling X tail. Luhn boundary rejection still
            // prevents misjudging standalone 16-17 digit strings.
            (
                "credit_card",
                r"\d{13,19}",
                Some(valid_luhn),
                ValidatorTag::Luhn,
                r"\d{13,19}",
            ),
            // Phone number (mainland China; issue #13 accepts +86/0086 international prefixes) —
            // validator boundary checks (surrounding chars not digits).
            // The original 1[3-9]\d{9} rejected +86/0086 prefixes (defect 3); now the optional
            // (?:\+86|0086)? prefix is included. The new span includes the prefix, and valid_phone
            // checks the char before the span (the char before '+' of +86 / '0' of 0086) — if the
            // char before the prefix is a digit (e.g. "20086139…", span starts at idx1 '0086',
            // start-1='2' is a digit), the boundary check rejects it, avoiding swallowing a longer
            // digit segment by mistake.
            (
                "phone",
                r"(?:\+86|0086)?1[3-9]\d{9}",
                Some(valid_phone),
                ValidatorTag::Phone,
                r"(?:\+86|0086)?1[3-9]\d{9}",
            ),
        ];
        let mut patterns = Vec::with_capacity(defs.len());
        for (name, pat, validator, validator_tag, pattern_str) in defs {
            patterns.push(PatternDef {
                name,
                re: Regex::new(pat)?,
                validator,
                validator_tag,
                pattern_str,
            });
        }
        Ok(Self { patterns })
    }

    // issue #7: exposes a serializable dump of the 15 redaction pattern definitions
    // (guard.redact.patterns.dump). Consumers (fusion-gateway PII SSOT) fetch it instead of
    // vendoring, eliminating manual lockstep. Ordered by defs priority (first accepted wins on
    // overlap, long credentials before id_number), name+regex verbatim, validator tags as enums.
    // Read-only; no change to redaction behavior.
    pub fn pattern_defs(&self) -> Vec<PatternDefDump> {
        self.patterns
            .iter()
            .map(|pd| PatternDefDump {
                name: pd.name,
                regex: pd.pattern_str,
                validator: pd.validator_tag,
            })
            .collect()
    }

    // P0-8: take the last 4 characters on char boundaries, not byte slicing. The original
    // s[n-4..] panicked on CJK (3 bytes/char) and emoji (4 bytes) (byte index not char boundary)
    // → redact_irreversible panic → worker crash.
    fn last4(s: &str) -> String {
        let chars: Vec<char> = s.chars().collect();
        let n = chars.len();
        if n <= 4 {
            s.to_string()
        } else {
            chars[n - 4..].iter().collect()
        }
    }

    // C19: group 1 (if present) = sensitive value, preceded by a visible label prefix
    // (password:/api_key=).
    // Redaction replaces only the value, keeping the prefix (DLP convention: field name visible,
    // secret redacted).
    // Without group 1 (PEM blocks/OpenSSH/JWK) → empty prefix, value = full match.
    fn split_value(c: &regex::Captures) -> (String, String) {
        let full = c.get(0).map(|m| m.as_str()).unwrap_or("").to_string();
        if full.is_empty() {
            return (String::new(), String::new());
        }
        match c.get(1) {
            Some(val_m) if !val_m.as_str().is_empty() => {
                let rel = val_m.start() - c.get(0).unwrap().start();
                let prefix = full[..rel].to_string();
                let value = val_m.as_str().to_string();
                (prefix, value)
            }
            _ => (String::new(), full),
        }
    }

    // L6 span-tracking core: collect all pattern hits on the original content in one pass (with
    // byte offsets), reject overlapping spans, rebuild end-to-start in a single pass. The original
    // sequential replace_all ran over already-redacted text — id_number matched 17-digit
    // substrings inside tok_<32hex> placeholders written by earlier patterns → corrupted the
    // original placeholder → extract_placeholders found nothing → reveal hit H6 → reversible
    // redaction silently degraded to irreversible. Span tracking removes this (placeholders are
    // never written back into the original content; single-pass rebuild).
    // Accepted span set; a new hit overlapping any accepted span is skipped (first pattern wins,
    // preventing id_number from swallowing api_key).
    // issue #10: pred filters by pattern name (true = full set = original redact semantics;
    // credential subset = redact_credentials).
    // Order (defs priority) is unchanged — the subset only skips non-matching patterns; the
    // first-accept overlap logic is the same.
    fn collect_spans_filtered<P: Fn(&str) -> bool>(
        &self,
        content: &str,
        pred: P,
    ) -> Vec<AcceptedMatch> {
        let mut accepted: Vec<AcceptedMatch> = Vec::new();
        for pd in &self.patterns {
            if !pred(pd.name) {
                continue;
            }
            let name_tag = pd.name;
            for c in pd.re.captures_iter(content) {
                let full = match c.get(0) {
                    Some(m) => m,
                    None => continue,
                };
                let (_prefix, value) = Self::split_value(&c);
                // Hit span = value (group 1) range; without group 1 → full-match range. Redaction
                // replaces only the value; the prefix stays in place.
                let (s, e) = match c.get(1) {
                    Some(vm) if !vm.as_str().is_empty() => (vm.start(), vm.end()),
                    _ => (full.start(), full.end()),
                };
                if s >= e {
                    continue;
                }
                // P1-1: validator (Luhn/char diversity/digit boundaries) rejects false-positive
                // candidates. The validator receives (content, span start, span end) — boundary
                // checks need the chars adjacent to the span in the original text (regex has no
                // lookaround).
                if let Some(check) = pd.validator {
                    if !check(content, s, e) {
                        continue;
                    }
                }
                // Reject overlap: skip this hit if any accepted span intersects [s,e).
                let overlaps = accepted.iter().any(|a| s < a.end && e > a.start);
                if overlaps {
                    continue;
                }
                accepted.push(AcceptedMatch {
                    start: s,
                    end: e,
                    name_tag,
                    value,
                });
            }
        }
        accepted
    }

    // Original semantics: collect across all patterns (pred always true). Preserves behavior for
    // all existing call sites (redact/redact_counted/redact_irreversible/redact_reversible/
    // has_sensitive go through this or equivalent inlined logic).
    fn collect_spans(&self, content: &str) -> Vec<AcceptedMatch> {
        self.collect_spans_filtered(content, |_| true)
    }

    pub fn redact(&self, content: &str) -> String {
        let spans = self.collect_spans(content);
        if spans.is_empty() {
            return content.to_string();
        }
        // Sort end-to-start: rebuild replaces from high offsets first, so lower offset positions
        // are unaffected.
        let mut ordered = spans;
        ordered.sort_by_key(|m| Reverse(m.start));
        let mut out = content.to_string();
        for m in &ordered {
            // span = group 1 (value) range; the prefix (group0..group1) is already preserved in
            // place, only the value is replaced.
            let repl = format!("[REDACTED:{}]", m.name_tag);
            out.replace_range(m.start..m.end, &repl);
        }
        out
    }

    // issue #10/#13: redact only the credential subset (CREDENTIAL_PATTERNS), skipping PII
    // (email/ipv4/credit_card/phone/id_number). Before issue #13, consumers (fusion-memory) kept
    // their own local PII redaction and took only the credential subset because of the 3 fg-redact
    // PII defects (idcard wrongly swallowed by credit_card / id_number swallowing long digit
    // strings / +86 phone rejected).
    // After the issue #13 fixes PII behavior is correct; consumers can retire their local PII
    // logic and route through fg-redact. This method remains for scenarios needing only the
    // credential subset. Same collect_spans priority + overlap semantics; the subset only skips
    // PII patterns. No change to redact() behavior.
    pub fn redact_credentials(&self, content: &str) -> String {
        self.redact_with_patterns(content, CREDENTIAL_PATTERNS)
    }

    // issue #10: generic primitive — runs only the named subset patterns (names from
    // pattern_defs()). Unknown names are ignored; the order still follows defs priority (first
    // accepted wins on overlap), not the caller's order. Lets consumers pick classes as needed.
    pub fn redact_with_patterns(&self, content: &str, names: &[&str]) -> String {
        let spans = self.collect_spans_filtered(content, |n| names.contains(&n));
        if spans.is_empty() {
            return content.to_string();
        }
        let mut ordered = spans;
        ordered.sort_by_key(|m| Reverse(m.start));
        let mut out = content.to_string();
        for m in &ordered {
            let repl = format!("[REDACTED:{}]", m.name_tag);
            out.replace_range(m.start..m.end, &repl);
        }
        out
    }

    // P2: redact also counts hits; evaluate does one pass instead of a has_sensitive+redact
    // double scan.
    // Returns (redacted content, hit count); hit count > 0 → sensitive content present.
    // Semantically equivalent to redact+has_sensitive but in a single pass.
    pub fn redact_counted(&self, content: &str) -> (String, usize) {
        let spans = self.collect_spans(content);
        let total = spans.len();
        if spans.is_empty() {
            return (content.to_string(), 0);
        }
        let mut ordered = spans;
        ordered.sort_by_key(|m| Reverse(m.start));
        let mut out = content.to_string();
        for m in &ordered {
            let repl = format!("[REDACTED:{}]", m.name_tag);
            out.replace_range(m.start..m.end, &repl);
        }
        (out, total)
    }

    pub fn redact_irreversible(&self, content: &str) -> String {
        let spans = self.collect_spans(content);
        if spans.is_empty() {
            return content.to_string();
        }
        let mut ordered = spans;
        ordered.sort_by_key(|m| Reverse(m.start));
        let mut out = content.to_string();
        for m in &ordered {
            let repl = format!("[REDACTED:{}#{}]", m.name_tag, Self::last4(&m.value));
            out.replace_range(m.start..m.end, &repl);
        }
        out
    }

    pub fn redact_reversible(&self, content: &str) -> (String, Vec<ReversibleMatch>) {
        let spans = self.collect_spans(content);
        if spans.is_empty() {
            return (content.to_string(), Vec::new());
        }
        // matches in text order (caller stores the first token as token_map_id); rebuild from
        // high offsets first.
        let mut by_pos: Vec<&AcceptedMatch> = spans.iter().collect();
        by_pos.sort_by_key(|m| m.start);
        let mut matches = Vec::with_capacity(by_pos.len());
        for m in &by_pos {
            let token_id = format!("tok_{}", Uuid::new_v4().simple());
            let placeholder = format!("[REDACTED:{}#{}]", m.name_tag, token_id);
            matches.push(ReversibleMatch {
                placeholder: placeholder.clone(),
                token_id: token_id.clone(),
                original: m.value.clone(),
            });
        }
        // Rebuild needs spans in descending order; take the matching token by by_pos index
        // (guarantees correct token↔span binding).
        let mut idx_desc: Vec<usize> = (0..by_pos.len()).collect();
        idx_desc.sort_by_key(|&i| Reverse(by_pos[i].start));
        let mut out = content.to_string();
        for i in idx_desc {
            let m = by_pos[i];
            let repl = format!("[REDACTED:{}#{}]", m.name_tag, matches[i].token_id);
            out.replace_range(m.start..m.end, &repl);
        }
        (out, matches)
    }

    pub fn has_sensitive(&self, content: &str) -> bool {
        // Aligned with collect_spans semantics: candidates rejected by a validator (Luhn/diversity/
        // boundary) do not count as sensitive.
        self.patterns.iter().any(|pd| {
            pd.re.captures_iter(content).any(|c| {
                let full = match c.get(0) {
                    Some(m) => m,
                    None => return false,
                };
                let (s, e) = match c.get(1) {
                    Some(vm) if !vm.as_str().is_empty() => (vm.start(), vm.end()),
                    _ => (full.start(), full.end()),
                };
                if s >= e {
                    return false;
                }
                match pd.validator {
                    Some(check) => check(content, s, e),
                    None => true,
                }
            })
        })
    }

    pub fn extract_placeholders(&self, content: &str) -> Vec<(String, String)> {
        // M4: OnceLock cache, not Regex::new().unwrap() per call (compile-failure panic + repeated
        // compile overhead).
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r"\[REDACTED:([a-z_]+)#(tok_[0-9a-f]+)\]")
                .expect("placeholder regex (static)")
        });
        re.captures_iter(content)
            .filter_map(|c| {
                let kind = c.get(1)?.as_str().to_string();
                let token_id = c.get(2)?.as_str().to_string();
                Some((kind, token_id))
            })
            .collect()
    }
}

// P1-1 (audit §1.10, rule 5): credit card Luhn check + digit boundaries — the regex only matches
// 13-19 digits; the validator (a) checks that the chars around the span are not digits (regex has
// no lookaround, boundaries in code), preventing swallowing of id_number/phone substrings;
// (b) confirms via the Luhn algorithm that it is a real card number, not an arbitrary digit string
// (reduces false positives: 13-19 digit strings occur frequently outside payment contexts).
fn valid_luhn(content: &str, start: usize, end: usize) -> bool {
    let bytes = content.as_bytes();
    if start > 0 && bytes[start - 1].is_ascii_digit() {
        return false;
    }
    if end < bytes.len() && bytes[end].is_ascii_digit() {
        return false;
    }
    let s = &content[start..end];
    let digits: Vec<u64> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| (c as u64) - 48)
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum: u64 = 0;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut x = if double { d * 2 } else { d };
        if x > 9 {
            x -= 9;
        }
        sum += x;
        double = !double;
    }
    sum.is_multiple_of(10)
}

// issue #13 defects 1+2 (rule 5: deterministic checks in code): ID number GB 11643-1999 mod-11
// checksum + digit boundaries.
// Reason: \d{17}[\dXx] with no validator → any 18-digit string (order numbers/timestamps) wrongly
// swallowed (defect 2); and when placed after credit_card, \d{13,19}+Luhn ate the 17-digit leading
// part leaving a dangling X (defect 1). The checksum algorithm confirms a real ID.
// GB 11643-1999: multiply each of the first 17 digits by weights [7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2]
// and sum; sum%11 maps to the check chars ['1','0','X','9','8','7','6','5','4','3','2']; the last
// char (0-9, or X/x=10) must match.
// Examples (verified in Python): 110101199003077651 → prefix 11010119900307765, sum=242,
//     242%11=0 → '1' == '1' ✓ valid;
//     11010119900307889X → prefix 11010119900307889, sum=266, 266%11=2 → 'X' == 'X' ✓ valid (trailing X);
//     110101199003077658 → sum=242 → '1' ≠ '8' reject; 110101199003077654 → '1' ≠ '4' reject (old test id).
//     Order number 999999999999999999 → sum=900, 900%11=9 → '3' ≠ '9' reject (defect 2 fix).
fn valid_id_card(content: &str, start: usize, end: usize) -> bool {
    let bytes = content.as_bytes();
    if start > 0 && bytes[start - 1].is_ascii_digit() {
        return false;
    }
    if end < bytes.len() && bytes[end].is_ascii_digit() {
        return false;
    }
    let s = &content[start..end];
    let chars: Vec<char> = s.chars().collect();
    if chars.len() != 18 {
        return false;
    }
    const WEIGHTS: [u64; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECK: [char; 11] = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];
    let mut sum: u64 = 0;
    for (i, c) in chars[..17].iter().enumerate() {
        let d = match c {
            '0'..='9' => (*c as u64) - 48,
            _ => return false,
        };
        sum += d * WEIGHTS[i];
    }
    let expected = CHECK[(sum % 11) as usize];
    let last = chars[17];
    let actual = match last {
        '0'..='9' => last,
        'X' | 'x' => 'X',
        _ => return false,
    };
    actual == expected
}

// P1-1 (audit §1.10, rule 5): AWS Secret Access Key false-positive defense — 40 chars from the
// base64 set. The validator (a) requires the chars around the span to be non-base64 (boundary, so
// the 40 chars are not a substring of a longer string); (b) requires character diversity
// (≥6 distinct, excluding "aaaa…"/"////…" all-identical static strings — real keys always have
// diversity).
fn valid_aws_secret(content: &str, start: usize, end: usize) -> bool {
    let is_base64 = |b: u8| b.is_ascii_alphanumeric() || b == b'/' || b == b'+' || b == b'=';
    let bytes = content.as_bytes();
    if start > 0 && is_base64(bytes[start - 1]) {
        return false;
    }
    if end < bytes.len() && is_base64(bytes[end]) {
        return false;
    }
    let s = &content[start..end];
    if s.len() != 40 {
        return false;
    }
    let mut distinct = std::collections::HashSet::new();
    for b in s.bytes() {
        distinct.insert(b);
    }
    distinct.len() >= 6
}

// P1-1 (audit §1.10): phone boundary check — chars around the span must not be digits, preventing
// swallowing by longer digit segments such as id_number.
fn valid_phone(content: &str, start: usize, end: usize) -> bool {
    let bytes = content.as_bytes();
    if start > 0 && bytes[start - 1].is_ascii_digit() {
        return false;
    }
    if end < bytes.len() && bytes[end].is_ascii_digit() {
        return false;
    }
    true
}

// issue #2: ipv4 octets ≤ 255 (the regex only limits to 1-3 digits; the validator rejects 256+
// false positives such as 999.1.1.1).
fn valid_ipv4(content: &str, start: usize, end: usize) -> bool {
    let bytes = content.as_bytes();
    if start > 0 && (bytes[start - 1].is_ascii_digit() || bytes[start - 1] == b'.') {
        return false;
    }
    if end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
        return false;
    }
    content[start..end]
        .split('.')
        .all(|seg| seg.parse::<u8>().is_ok())
}

impl Default for Redactor {
    fn default() -> Self {
        // M4: new() returns Result; Default falls back to panic (static pattern compilation should
        // never fail; tests only).
        Self::new().expect("redactor default: static regex compile failed")
    }
}
