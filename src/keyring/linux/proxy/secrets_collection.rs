use crate::keyring::linux::proxy::secrets::Secret;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zbus::dbus_proxy;
use zvariant::{ObjectPath, OwnedObjectPath, Value};
use zvariant_derive::Type;

/// https://specifications.freedesktop.org/secret-service/latest/re02.html
#[dbus_proxy(interface = "org.freedesktop.Secret.Collection")]
trait Collection {
    /// Returns prompt: ObjectPath
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;

    fn search_items(&self, attributes: HashMap<&str, &str>) -> zbus::Result<Vec<OwnedObjectPath>>;

    fn create_item(
        &self,
        properties: HashMap<&str, Value>,
        secret: Secret,
        replace: bool,
    ) -> zbus::Result<CreateItemResult>;

    #[dbus_proxy(property)]
    fn items(&self) -> zbus::fdo::Result<Vec<ObjectPath>>;

    #[dbus_proxy(property)]
    fn label(&self) -> zbus::fdo::Result<String>;

    #[dbus_proxy(property)]
    fn set_label(&self, new_label: &str) -> zbus::fdo::Result<()>;

    #[dbus_proxy(property)]
    fn locked(&self) -> zbus::fdo::Result<bool>;

    #[dbus_proxy(property)]
    fn created(&self) -> zbus::fdo::Result<u64>;

    #[dbus_proxy(property)]
    fn modified(&self) -> zbus::fdo::Result<u64>;
}

#[derive(Serialize, Deserialize, Type)]
pub struct CreateItemResult {
    item: OwnedObjectPath,
    prompt: OwnedObjectPath,
}
