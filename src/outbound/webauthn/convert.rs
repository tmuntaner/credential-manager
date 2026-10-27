use crate::domain::ports::user_interaction::InteractionError;
use webauthn::PinError;

impl From<InteractionError> for PinError {
    fn from(e: InteractionError) -> Self {
        match e {
            InteractionError::Cancelled => PinError::Cancelled,
            e => PinError::Failed(Box::new(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancelled_prompt_is_a_cancelled_pin() {
        let err = PinError::from(InteractionError::Cancelled);

        assert!(matches!(err, PinError::Cancelled));
    }

    #[test]
    fn other_failures_keep_their_message() {
        let err = PinError::from(InteractionError::Unavailable);

        assert!(matches!(err, PinError::Failed(_)));
        assert_eq!(err.to_string(), "user interaction is unavailable");
    }
}
