use zbus::dbus_proxy;

/// https://specifications.freedesktop.org/secret-service/latest/re04.html
#[dbus_proxy(interface = "org.freedesktop.Secret.Session")]
trait Session {
    fn close(&self) -> zbus::Result<()>;
}
