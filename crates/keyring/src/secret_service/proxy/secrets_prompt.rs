use zbus::proxy;
use zbus::Variant;

/// https://specifications.freedesktop.org/secret-service/latest/re05.html
#[proxy(interface = "org.freedesktop.Secret.Prompt", assume_defaults = true)]
pub trait Prompt {
    fn prompt(&self, window_id: &str) -> zbus::Result<()>;

    fn dismiss(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn completed(&self, dismissed: bool, result: Variant<'_>) -> zbus::Result<()>;
}
