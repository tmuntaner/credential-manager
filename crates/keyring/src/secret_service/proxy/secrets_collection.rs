use crate::secret_service::proxy::secrets::Secret;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zbus::proxy;
use zbus::Type;
use zbus::{OwnedObjectPath, Variant};

/// https://specifications.freedesktop.org/secret-service/latest/re02.html
#[proxy(
    interface = "org.freedesktop.Secret.Collection",
    assume_defaults = true
)]
pub trait Collection {
    /// Returns prompt: ObjectPath
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;

    fn search_items(&self, attributes: HashMap<&str, &str>) -> zbus::Result<Vec<OwnedObjectPath>>;

    fn create_item(
        &self,
        properties: HashMap<&str, Variant<'_>>,
        secret: Secret,
        replace: bool,
    ) -> zbus::Result<CreateItemResult>;

    #[zbus(property)]
    fn items(&self) -> zbus::fdo::Result<Vec<OwnedObjectPath>>;

    #[zbus(property)]
    fn label(&self) -> zbus::fdo::Result<String>;

    #[zbus(property)]
    fn set_label(&self, new_label: &str) -> zbus::fdo::Result<()>;

    #[zbus(property)]
    fn locked(&self) -> zbus::fdo::Result<bool>;

    #[zbus(property)]
    fn created(&self) -> zbus::fdo::Result<u64>;

    #[zbus(property)]
    fn modified(&self) -> zbus::fdo::Result<u64>;
}

#[derive(Serialize, Deserialize, Type)]
pub struct CreateItemResult {
    item: OwnedObjectPath,
    prompt: OwnedObjectPath,
}
