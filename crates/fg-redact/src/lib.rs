use regex::Regex;
use uuid::Uuid;

pub struct Redactor {
    patterns: Vec<(&'static str, Regex)>,
}

pub struct ReversibleMatch {
    pub placeholder: String,
    pub token_id: String,
    pub original: String,
}

impl Redactor {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                ("api_key", Regex::new(r"(?i)sk-[A-Za-z0-9]{20,}").unwrap()),
                (
                    "password",
                    Regex::new(r"(?i)password\s*[:=]\s*\S+").unwrap(),
                ),
                ("id_number", Regex::new(r"\b\d{15,18}[Xx]?\b").unwrap()),
                (
                    "private_key",
                    Regex::new(r"-----BEGIN [A-Z ]+PRIVATE KEY-----").unwrap(),
                ),
            ],
        }
    }

    fn last4(s: &str) -> String {
        let n = s.len();
        if n <= 4 {
            s.to_string()
        } else {
            s[n - 4..].to_string()
        }
    }

    pub fn redact(&self, content: &str) -> String {
        let mut out = content.to_string();
        for (name, re) in &self.patterns {
            let replacer = format!("[REDACTED:{}]", name);
            out = re.replace_all(&out, replacer.as_str()).to_string();
        }
        out
    }

    pub fn redact_irreversible(&self, content: &str) -> String {
        let mut out = content.to_string();
        for (name, re) in &self.patterns {
            out = re
                .replace_all(&out, |c: &regex::Captures| {
                    let m = c.get(0).map(|m| m.as_str()).unwrap_or("");
                    format!("[REDACTED:{}#{}]", name, Self::last4(m))
                })
                .to_string();
        }
        out
    }

    pub fn redact_reversible(&self, content: &str) -> (String, Vec<ReversibleMatch>) {
        let mut out = content.to_string();
        let mut matches = Vec::new();
        for (name, re) in &self.patterns {
            let mut local_matches = Vec::new();
            out = re
                .replace_all(&out, |c: &regex::Captures| {
                    let original = c.get(0).map(|m| m.as_str()).unwrap_or("").to_string();
                    let token_id = format!("tok_{}", Uuid::new_v4().simple());
                    let placeholder = format!("[REDACTED:{}#{}]", name, token_id);
                    local_matches.push(ReversibleMatch {
                        placeholder: placeholder.clone(),
                        token_id: token_id.clone(),
                        original,
                    });
                    placeholder
                })
                .to_string();
            matches.append(&mut local_matches);
        }
        (out, matches)
    }

    pub fn has_sensitive(&self, content: &str) -> bool {
        self.patterns.iter().any(|(_, re)| re.is_match(content))
    }

    pub fn extract_placeholders(&self, content: &str) -> Vec<(String, String)> {
        let re = Regex::new(r"\[REDACTED:([a-z_]+)#(tok_[0-9a-f]+)\]").unwrap();
        re.captures_iter(content)
            .filter_map(|c| {
                let kind = c.get(1)?.as_str().to_string();
                let token_id = c.get(2)?.as_str().to_string();
                Some((kind, token_id))
            })
            .collect()
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}
