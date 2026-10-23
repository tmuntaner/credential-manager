use crate::domain::ports::state::{StateError, StateSource};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Makes the OAuth state from the random source of the operating system.
#[derive(Debug, Default)]
pub struct RandomState;

impl RandomState {
    pub fn new() -> Self {
        RandomState
    }
}

impl StateSource for RandomState {
    fn state(&self) -> Result<String, StateError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|e| {
            StateError::Failed(format!("could not generate a random state: {e}").into())
        })?;

        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hands_out_a_new_url_safe_state_every_time() {
        let first = RandomState::new().state().unwrap();
        let second = RandomState::new().state().unwrap();

        assert_eq!(first.len(), 22);
        assert!(first
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(first, second);
    }
}
