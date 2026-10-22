use crate::secret_service::proxy::secrets::Secret;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zbus::proxy;
use zbus::Type;
use zbus::{ObjectPath, OwnedObjectPath};

/// https://specifications.freedesktop.org/secret-service/latest/re03.html
#[proxy(interface = "org.freedesktop.Secret.Item", assume_defaults = true)]
pub trait Item {
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;

    fn get_secret(&self, session: &ObjectPath<'_>) -> zbus::Result<Secret>;

    fn set_secret(&self, secret: SecretInput) -> zbus::Result<()>;

    #[zbus(property)]
    fn locked(&self) -> zbus::fdo::Result<bool>;

    #[zbus(property)]
    fn attributes(&self) -> zbus::fdo::Result<HashMap<String, String>>;

    #[zbus(property)]
    fn set_attributes(&self, attributes: HashMap<&str, &str>) -> zbus::fdo::Result<()>;

    #[zbus(property)]
    fn label(&self) -> zbus::fdo::Result<String>;

    #[zbus(property)]
    fn set_label(&self, new_label: &str) -> zbus::fdo::Result<()>;

    #[zbus(property)]
    fn created(&self) -> zbus::fdo::Result<u64>;

    #[zbus(property)]
    fn modified(&self) -> zbus::fdo::Result<u64>;
}

#[derive(Deserialize, Serialize, Type)]
#[allow(dead_code)]
pub struct SecretInput {
    inner: Secret,
}
