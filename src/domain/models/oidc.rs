use std::error::Error;
use thiserror::Error;

/// Why the identity provider did not hand out an authorization code.
#[derive(Debug, Error)]
pub enum OidcError {
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_message_and_the_cause_of_the_adapter_error() {
        let cause = std::io::Error::other("boom");
        let err = OidcError::Failed(Box::new(cause));

        assert_eq!(err.to_string(), "boom");
        let OidcError::Failed(inner) = err;
        assert!(inner.downcast_ref::<std::io::Error>().is_some());
    }
}
