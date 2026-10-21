/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use crate::secret_service::item::Item;
use crate::secret_service::proxy::secrets::Secret;
use crate::secret_service::proxy::secrets_collection::CollectionProxyBlocking;
use crate::secret_service::session::SERVICE_NAME;
use anyhow::Result;
use std::collections::HashMap;
use zbus::blocking::Connection;
use zvariant::{Dict, OwnedObjectPath, Value};

pub const ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
pub const ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";

pub struct Collection<'a> {
    proxy: CollectionProxyBlocking<'a>,
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
        let proxy = CollectionProxyBlocking::builder(&connection)
            .destination(SERVICE_NAME.to_string())?
            .path(path)?
            .build()?;

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

        item_paths
            .into_iter()
            .map(|item| {
                let path = item.as_str().to_string();
                Item::new(self.connection.clone(), self.session_path.clone(), path)
            })
            .map(|item| item?.secret())
            .collect()
    }
}
