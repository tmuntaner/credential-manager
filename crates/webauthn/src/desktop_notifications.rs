use crate::WebauthnNotifier;
use notify_rust::Notification;

pub struct DesktopNotificationsFallbackNotifier {}

impl DesktopNotificationsFallbackNotifier {
    pub fn new() -> Self {
        Self {}
    }
}

impl WebauthnNotifier for DesktopNotificationsFallbackNotifier {
    fn notify_start(&self) -> anyhow::Result<()> {
        Notification::new()
            .summary("WebAuthn")
            .body("Please insert and activate your U2F device.")
            .show()?;

        Ok(())
    }

    fn notify_end(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
