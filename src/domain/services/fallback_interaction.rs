use crate::domain::models::secret::SafeSecret;
use crate::domain::models::user_interaction::{ChoicePrompt, ConfirmPrompt, SecretPrompt};
use crate::domain::ports::user_interaction::{InteractionError, UserInteraction};
use async_trait::async_trait;
use std::sync::Arc;

/// A [`UserInteraction`] that prompts the user for information with fallback to other
/// UserInteractions if necessary.
pub struct FallbackInteraction {
    adapters: Vec<Arc<dyn UserInteraction>>,
}

impl FallbackInteraction {
    /// Creates the chain. The first adapter has the highest priority.
    pub fn new(adapters: Vec<Arc<dyn UserInteraction>>) -> Self {
        Self { adapters }
    }
}

impl FallbackInteraction {
    /// Runs `ask` on each adapter in order and returns the first result that is not `Unavailable`.
    async fn first_available<T>(
        &self,
        ask: impl AsyncFn(&dyn UserInteraction) -> Result<T, InteractionError>,
    ) -> Result<T, InteractionError> {
        for adapter in &self.adapters {
            match ask(adapter.as_ref()).await {
                Err(InteractionError::Unavailable) => continue,
                result => return result,
            }
        }
        Err(InteractionError::Unavailable)
    }
}

#[async_trait(?Send)]
impl UserInteraction for FallbackInteraction {
    async fn ask_secret(&self, prompt: SecretPrompt) -> Result<SafeSecret, InteractionError> {
        self.first_available(async |a| a.ask_secret(prompt.clone()).await)
            .await
    }

    async fn confirm(&self, prompt: ConfirmPrompt) -> Result<bool, InteractionError> {
        self.first_available(async |a| a.confirm(prompt.clone()).await)
            .await
    }

    async fn choose(&self, prompt: &ChoicePrompt) -> Result<usize, InteractionError> {
        self.first_available(async |a| a.choose(prompt).await).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ports::user_interaction::MockUserInteraction;

    fn chain(mocks: Vec<MockUserInteraction>) -> FallbackInteraction {
        FallbackInteraction::new(
            mocks
                .into_iter()
                .map(|m| Arc::new(m) as Arc<dyn UserInteraction>)
                .collect(),
        )
    }

    fn prompt() -> SecretPrompt {
        SecretPrompt::new("title", "PIN")
    }

    fn unavailable() -> MockUserInteraction {
        let mut m = MockUserInteraction::new();
        m.expect_ask_secret()
            .times(1)
            .returning(|_| Err(InteractionError::Unavailable));
        m
    }

    #[tokio::test]
    async fn first_adapter_answers_and_the_rest_are_not_asked() {
        let mut first = MockUserInteraction::new();
        first
            .expect_ask_secret()
            .times(1)
            .returning(|_| Ok(SafeSecret::new("one")));
        let mut second = MockUserInteraction::new();
        second.expect_ask_secret().never();

        let secret = chain(vec![first, second])
            .ask_secret(prompt())
            .await
            .unwrap();
        assert_eq!(secret.expose_secret(), "one");
    }

    #[tokio::test]
    async fn unavailable_falls_through_to_the_next_adapter() {
        let mut second = MockUserInteraction::new();
        second
            .expect_ask_secret()
            .times(1)
            .withf(|p| *p == prompt())
            .returning(|_| Ok(SafeSecret::new("two")));

        let secret = chain(vec![unavailable(), second])
            .ask_secret(prompt())
            .await
            .unwrap();
        assert_eq!(secret.expose_secret(), "two");
    }

    #[tokio::test]
    async fn cancelled_stops_the_chain() {
        let mut first = MockUserInteraction::new();
        first
            .expect_ask_secret()
            .times(1)
            .returning(|_| Err(InteractionError::Cancelled));
        let mut second = MockUserInteraction::new();
        second.expect_ask_secret().never();

        let err = chain(vec![first, second])
            .ask_secret(prompt())
            .await
            .unwrap_err();
        assert!(matches!(err, InteractionError::Cancelled));
    }

    #[tokio::test]
    async fn failed_stops_the_chain() {
        let mut first = MockUserInteraction::new();
        first
            .expect_confirm()
            .times(1)
            .returning(|_| Err(InteractionError::failed("boom")));
        let mut second = MockUserInteraction::new();
        second.expect_confirm().never();

        let err = chain(vec![first, second])
            .confirm(ConfirmPrompt::new("t", "d"))
            .await
            .unwrap_err();
        assert!(matches!(err, InteractionError::Failed(_)));
    }

    #[tokio::test]
    async fn all_unavailable_is_unavailable() {
        let err = chain(vec![unavailable(), unavailable()])
            .ask_secret(prompt())
            .await
            .unwrap_err();
        assert!(matches!(err, InteractionError::Unavailable));
    }

    #[tokio::test]
    async fn empty_chain_is_unavailable() {
        let err = chain(vec![]).ask_secret(prompt()).await.unwrap_err();
        assert!(matches!(err, InteractionError::Unavailable));
    }

    #[tokio::test]
    async fn choose_uses_the_first_adapter_that_is_available() {
        let mut gui = MockUserInteraction::new();
        gui.expect_choose()
            .times(1)
            .returning(|_| Err(InteractionError::Unavailable));
        let mut terminal = MockUserInteraction::new();
        terminal.expect_choose().times(1).returning(|_| Ok(1));

        let choice = ChoicePrompt::new("t", "d", ["a", "b"]);
        assert_eq!(chain(vec![gui, terminal]).choose(&choice).await.unwrap(), 1);
    }
}
