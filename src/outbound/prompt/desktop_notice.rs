use crate::domain::models::user_interaction::{NoticeLevel, UserNotice};
use crate::domain::ports::notifier::{Notifier, NotifyError};
use async_trait::async_trait;
use notify_rust::{Notification, Timeout};
use std::time::Duration;

const TITLE: &str = "c9s";

/// How long the desktop keeps the popup notice up.
const EXPIRE: Duration = Duration::from_secs(15);

/// How long to try sending a popup notice.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Sends a popup notice to the user within the desktop.
#[derive(Debug, Default)]
pub struct DesktopNotice;

impl DesktopNotice {
    fn notification(notice: &UserNotice) -> Notification {
        let mut notification = Notification::new();

        notification
            .appname(TITLE)
            .summary(TITLE)
            .body(&notice.message)
            .timeout(match notice.level {
                // Errors stay until the user dismisses them.
                NoticeLevel::Error => Timeout::Never,
                NoticeLevel::Info | NoticeLevel::Warning => {
                    Timeout::Milliseconds(EXPIRE.as_millis().try_into().unwrap_or(u32::MAX))
                }
            });

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            notification.urgency(match notice.level {
                NoticeLevel::Error => notify_rust::Urgency::Critical,
                NoticeLevel::Info | NoticeLevel::Warning => notify_rust::Urgency::Normal,
            });

            // Informational popups, like requesting to touch a security key, are useless after
            // the user sees it. There is no need to keep it in the notification history.
            // Errors should stay in the history.
            if notice.level != NoticeLevel::Error {
                notification.hint(notify_rust::Hint::Transient(true));
            }
        }

        notification
    }
}

#[async_trait(?Send)]
impl Notifier for DesktopNotice {
    async fn notify(&self, notice: &UserNotice) -> Result<(), NotifyError> {
        let notification = Self::notification(notice);

        // Showing blocks on the desktop's answer, so keep it off the async threads.
        let shown = tokio::task::spawn_blocking(move || notification.show().map(drop));

        match tokio::time::timeout(TIMEOUT, shown).await {
            Ok(Ok(Ok(()))) => Ok(()),
            _ => Err(NotifyError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_notice_is_the_body() {
        let notification = DesktopNotice::notification(&UserNotice::info("Touch your key"));

        assert_eq!(notification.summary, "c9s");
        assert_eq!(notification.body, "Touch your key");
        assert!(matches!(
            notification.timeout,
            Timeout::Milliseconds(15_000)
        ));
    }

    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn only_errors_are_kept_in_the_history() {
        let transient = |notice| {
            DesktopNotice::notification(&notice)
                .hints
                .contains(&notify_rust::Hint::Transient(true))
        };

        assert!(transient(UserNotice::info("Touch your key")));
        assert!(transient(UserNotice::warning("bad code")));
        assert!(!transient(UserNotice::error("blocked")));
    }

    #[test]
    fn errors_stay_until_dismissed() {
        let notification = DesktopNotice::notification(&UserNotice::error("blocked"));

        assert!(matches!(notification.timeout, Timeout::Never));
    }
}
