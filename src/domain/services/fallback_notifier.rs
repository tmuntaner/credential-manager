use crate::domain::models::user_interaction::UserNotice;
use crate::domain::ports::notifier::{Notifier, NotifyError};
use async_trait::async_trait;
use std::sync::Arc;

/// A [`Notifier`] that tries several others in priority order.
///
/// A notifier that cannot show the notice returns [`NotifyError::Unavailable`] and the next one is
/// tried. Every other result is final, so a notice is never shown twice.
pub struct FallbackNotifier {
    notifiers: Vec<Arc<dyn Notifier>>,
}

impl FallbackNotifier {
    /// Creates the chain. The first notifier has the highest priority.
    pub fn new(notifiers: Vec<Arc<dyn Notifier>>) -> Self {
        Self { notifiers }
    }
}

#[async_trait(?Send)]
impl Notifier for FallbackNotifier {
    async fn notify(&self, notice: &UserNotice) -> Result<(), NotifyError> {
        for notifier in &self.notifiers {
            match notifier.notify(notice).await {
                Err(NotifyError::Unavailable) => continue,
                result => return result,
            }
        }
        Err(NotifyError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ports::notifier::MockNotifier;

    fn chain(mocks: Vec<MockNotifier>) -> FallbackNotifier {
        FallbackNotifier::new(
            mocks
                .into_iter()
                .map(|m| Arc::new(m) as Arc<dyn Notifier>)
                .collect(),
        )
    }

    fn unavailable() -> MockNotifier {
        let mut m = MockNotifier::new();
        m.expect_notify()
            .times(1)
            .returning(|_| Err(NotifyError::Unavailable));
        m
    }

    #[tokio::test]
    async fn first_available_notifier_shows_the_notice() {
        let mut terminal = MockNotifier::new();
        terminal.expect_notify().times(1).returning(|_| Ok(()));
        let mut last = MockNotifier::new();
        last.expect_notify().never();

        chain(vec![unavailable(), terminal, last])
            .notify(&UserNotice::info("hi"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn failed_stops_the_chain() {
        let mut first = MockNotifier::new();
        first
            .expect_notify()
            .times(1)
            .returning(|_| Err(NotifyError::failed("boom")));
        let mut second = MockNotifier::new();
        second.expect_notify().never();

        let err = chain(vec![first, second])
            .notify(&UserNotice::info("hi"))
            .await
            .unwrap_err();
        assert!(matches!(err, NotifyError::Failed(_)));
    }

    #[tokio::test]
    async fn all_unavailable_is_unavailable() {
        let err = chain(vec![unavailable(), unavailable()])
            .notify(&UserNotice::info("hi"))
            .await
            .unwrap_err();
        assert!(matches!(err, NotifyError::Unavailable));
    }
}
