use std::fmt;

/// The OAuth authorization code that the identity provider hands out after a login.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthCode(String);

impl AuthCode {
    pub fn new(code: impl Into<String>) -> Self {
        Self(code.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuthCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthCode(<redacted>)")
    }
}

/// The token of a login session at Rancher. Not given to the user.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken(String);

impl SessionToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_not_printed() {
        assert_eq!(
            format!("{:?}", AuthCode::new("abc")),
            "AuthCode(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", SessionToken::new("session:secret")),
            "SessionToken(<redacted>)"
        );
    }
}
