use crate::keyring::linux::item::Item;
use crate::keyring::linux::proxy::secrets::Secret;
use crate::keyring::linux::proxy::secrets_collection::CollectionProxy;
use crate::keyring::linux::session::SERVICE_NAME;
use anyhow::Result;
use std::collections::HashMap;
use zbus::Connection;
use zvariant::{Dict, OwnedObjectPath, Value};

pub const ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
pub const ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";

pub struct Collection<'a> {
    proxy: CollectionProxy<'a>,
    connection: Connection,
    session_path: OwnedObjectPath,
    aes_key: Vec<u8>,
}

impl Collection<'_> {
    pub fn new<'a>(
        connection: Connection,
        session_path: OwnedObjectPath,
        aes_key: Vec<u8>,
        path: String,
    ) -> Result<Collection<'a>> {
        let proxy =
            CollectionProxy::new_for_owned(connection.clone(), SERVICE_NAME.to_string(), path)?;

        Ok(Collection {
            proxy,
            connection,
            aes_key,
            session_path,
        })
    }

    pub fn create_item(
        &self,
        secret: String,
        label: String,
        attributes: HashMap<&str, &str>,
    ) -> Result<()> {
        let mut properties: HashMap<&str, Value> = HashMap::new();
        let attributes: Dict = attributes.into();

        properties.insert(ITEM_LABEL, label.into());
        properties.insert(ITEM_ATTRIBUTES, attributes.into());
        let secret = Secret::new(
            self.session_path.clone(),
            self.aes_key.clone(),
            secret,
            String::from("text/plain"),
        )?;

        let _created_item = self.proxy.create_item(properties, secret, true)?;

        Ok(())
    }

    pub fn search(&self, attributes: HashMap<&str, &str>) -> Result<Vec<Secret>> {
        let item_paths = self.proxy.search_items(attributes)?;

        let items: Result<Vec<Item>> = item_paths
            .into_iter()
            .map(|item| {
                let path = item.as_str().to_string();
                Item::new(self.connection.clone(), self.session_path.clone(), path)
            })
            .collect();

        let secrets: Result<Vec<Secret>> = items?.into_iter().map(|item| item.secret()).collect();

        secrets
    }
}
