use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret value whose in-memory representation is zeroized on drop and redacted in debug formatting.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SafeSecret(String);

impl SafeSecret {
    /// Wraps a secret.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// Borrows the secret. Avoid copying it, since copies are not zeroized.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Moves the secret out. The returned `String` is no longer zeroized, so hand it straight to
    /// whatever consumes it.
    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl std::fmt::Debug for SafeSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SafeSecret").field(&"[REDACTED]").finish()
    }
}

impl From<String> for SafeSecret {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SafeSecret {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_is_not_printed() {
        let secret = SafeSecret::new("hunter2");

        assert!(!format!("{secret:?}").contains("hunter2"));
        assert!(!format!("{secret:#?}").contains("hunter2"));
    }
}
