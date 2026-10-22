use crate::{WebauthnError, WebauthnNotifier};
use notify_rust::Notification;

pub struct DesktopNotificationsFallbackNotifier {}

impl DesktopNotificationsFallbackNotifier {
    pub fn new() -> Self {
        Self {}
    }
}

impl WebauthnNotifier for DesktopNotificationsFallbackNotifier {
    fn notify_start(&self) -> Result<(), WebauthnError> {
        Notification::new()
            .summary("WebAuthn")
            .body("Please insert and activate your U2F device.")
            .show()?;

        Ok(())
    }

    fn notify_end(&self) -> Result<(), WebauthnError> {
        Ok(())
    }
}
