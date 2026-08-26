use regex::Regex;

pub struct Redactor {
    patterns: Vec<(&'static str, Regex)>,
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

    pub fn redact(&self, content: &str) -> String {
        let mut out = content.to_string();
        for (name, re) in &self.patterns {
            out = re
                .replace_all(&out, format!("[REDACTED:{}]", name))
                .to_string();
        }
        out
    }

    pub fn has_sensitive(&self, content: &str) -> bool {
        self.patterns.iter().any(|(_, re)| re.is_match(content))
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}
