use crate::domain::models::user_interaction::{NoticeLevel, SecretPrompt, UserNotice};
use crate::domain::ports::notifier::Notifier;
use crate::domain::ports::user_interaction::UserInteraction;
use async_trait::async_trait;
use std::sync::Arc;
use webauthn::{KeyEvent, PinError, PinRequest, SecurityKeyPin, SecurityKeyUi};

const TITLE: &str = "c9s: security key";

pub struct UserInteractionKeyUi<U, N> {
    interaction: Arc<U>,
    notifier: Arc<N>,
}

impl<U, N> UserInteractionKeyUi<U, N> {
    pub fn new(interaction: Arc<U>, notifier: Arc<N>) -> Self {
        Self {
            interaction,
            notifier,
        }
    }
}

#[async_trait(?Send)]
impl<U: UserInteraction, N: Notifier> SecurityKeyUi for UserInteractionKeyUi<U, N> {
    async fn request_pin(&self, request: &PinRequest) -> Result<SecurityKeyPin, PinError> {
        let mut prompt = SecretPrompt::new(TITLE, "Security key PIN").with_description(
            "Enter the PIN of your security key. Then touch the key when it blinks.",
        );
        if let Some(message) = request.retry_message() {
            prompt = prompt.with_error(message);
        }

        let pin = self.interaction.ask_secret(prompt).await?;

        Ok(SecurityKeyPin::new(pin.into_inner()))
    }

    async fn notify(&self, event: KeyEvent) {
        let level = if event.is_error() {
            NoticeLevel::Error
        } else {
            NoticeLevel::Info
        };

        // Nothing to do when the notice cannot be shown.
        let _ = self
            .notifier
            .notify(&UserNotice::new(level, event.to_string()))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::secret::SafeSecret;
    use crate::domain::ports::notifier::MockNotifier;
    use crate::domain::ports::user_interaction::{InteractionError, MockUserInteraction};

    fn key_ui(
        interaction: MockUserInteraction,
        notifier: MockNotifier,
    ) -> UserInteractionKeyUi<MockUserInteraction, MockNotifier> {
        UserInteractionKeyUi::new(Arc::new(interaction), Arc::new(notifier))
    }

    #[tokio::test]
    async fn asks_for_the_pin() {
        let mut interaction = MockUserInteraction::new();
        interaction
            .expect_ask_secret()
            .times(1)
            .withf(|prompt| prompt.label == "Security key PIN" && prompt.error.is_none())
            .returning(|_| Ok(SafeSecret::new("1234")));

        let pin = key_ui(interaction, MockNotifier::new())
            .request_pin(&PinRequest::new(false, None))
            .await
            .unwrap();

        assert_eq!(pin.as_str(), "1234");
    }

    #[tokio::test]
    async fn a_retry_shows_the_attempts_left() {
        let mut interaction = MockUserInteraction::new();
        interaction
            .expect_ask_secret()
            .times(1)
            .withf(|prompt| prompt.error.as_deref() == Some("Wrong PIN, 2 attempts left."))
            .returning(|_| Ok(SafeSecret::new("1234")));

        key_ui(interaction, MockNotifier::new())
            .request_pin(&PinRequest::new(true, Some(2)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_dismissed_prompt_cancels() {
        let mut interaction = MockUserInteraction::new();
        interaction
            .expect_ask_secret()
            .returning(|_| Err(InteractionError::Cancelled));

        let err = key_ui(interaction, MockNotifier::new())
            .request_pin(&PinRequest::new(false, None))
            .await
            .unwrap_err();

        assert!(matches!(err, PinError::Cancelled));
    }

    #[tokio::test]
    async fn hints_are_info_and_blocked_keys_are_errors() {
        let mut notifier = MockNotifier::new();
        notifier
            .expect_notify()
            .times(1)
            .withf(|notice| {
                notice.level == NoticeLevel::Info
                    && notice.message == "Touch your security key to continue..."
            })
            .returning(|_| Ok(()));
        notifier
            .expect_notify()
            .times(1)
            .withf(|notice| notice.level == NoticeLevel::Error)
            .returning(|_| Ok(()));

        let ui = key_ui(MockUserInteraction::new(), notifier);
        ui.notify(KeyEvent::TouchRequired).await;
        ui.notify(KeyEvent::PinBlocked).await;
    }
}
