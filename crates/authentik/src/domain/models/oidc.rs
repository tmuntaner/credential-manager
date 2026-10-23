use std::fmt;

/// The OAuth authorization code from a successful login.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthCode(String);

impl AuthCode {
    pub fn new(code: impl Into<String>) -> Self {
        Self(code.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for AuthCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthCode(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_code_is_not_printed() {
        assert_eq!(
            format!("{:?}", AuthCode::new("abc")),
            "AuthCode(<redacted>)"
        );
    }
}
