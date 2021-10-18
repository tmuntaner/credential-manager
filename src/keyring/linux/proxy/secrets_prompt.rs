use zbus::dbus_proxy;
use zvariant::Value;

/// https://specifications.freedesktop.org/secret-service/latest/re05.html
#[dbus_proxy(interface = "org.freedesktop.Secret.Prompt")]
trait Prompt {
    fn prompt(&self, window_id: &str) -> zbus::Result<()>;

    fn dismiss(&self) -> zbus::Result<()>;

    #[dbus_proxy(signal)]
    fn completed(&self, dismissed: bool, result: Value) -> zbus::Result<()>;
}
