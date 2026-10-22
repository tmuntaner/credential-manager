use zbus::proxy;

/// https://specifications.freedesktop.org/secret-service/latest/re04.html
#[proxy(interface = "org.freedesktop.Secret.Session", assume_defaults = true)]
pub trait Session {
    fn close(&self) -> zbus::Result<()>;
}
