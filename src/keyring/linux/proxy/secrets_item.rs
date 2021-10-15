use crate::keyring::linux::proxy::secrets::Secret;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zbus::dbus_proxy;
use zvariant::{ObjectPath, OwnedObjectPath};
use zvariant_derive::Type;

/// https://specifications.freedesktop.org/secret-service/latest/re03.html
#[dbus_proxy(interface = "org.freedesktop.Secret.Item")]
trait Item {
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;

    fn get_secret(&self, session: &ObjectPath) -> zbus::Result<Secret>;

    fn set_secret(&self, secret: SecretInput) -> zbus::Result<()>;

    #[dbus_proxy(property)]
    fn locked(&self) -> zbus::fdo::Result<bool>;

    #[dbus_proxy(property)]
    fn attributes(&self) -> zbus::fdo::Result<HashMap<String, String>>;

    #[dbus_proxy(property)]
    fn set_attributes(&self, attributes: HashMap<&str, &str>) -> zbus::fdo::Result<()>;

    #[dbus_proxy(property)]
    fn label(&self) -> zbus::fdo::Result<String>;

    #[dbus_proxy(property)]
    fn set_label(&self, new_label: &str) -> zbus::fdo::Result<()>;

    #[dbus_proxy(property)]
    fn created(&self) -> zbus::fdo::Result<u64>;

    #[dbus_proxy(property)]
    fn modified(&self) -> zbus::fdo::Result<u64>;
}

#[derive(Deserialize, Serialize, Type)]
pub struct SecretInput {
    inner: Secret,
}
