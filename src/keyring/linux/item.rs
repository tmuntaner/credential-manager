use crate::keyring::linux::proxy::secrets::Secret;
use crate::keyring::linux::proxy::secrets_item::ItemProxy;
use crate::keyring::linux::session::SERVICE_NAME;
use anyhow::{anyhow, Result};
use zbus::Connection;
use zvariant::OwnedObjectPath;

pub struct Item<'a> {
    proxy: ItemProxy<'a>,
    session_path: OwnedObjectPath,
}

impl Item<'_> {
    pub fn new<'a>(
        connection: Connection,
        session_path: OwnedObjectPath,
        path: String,
    ) -> Result<Item<'a>> {
        let proxy = ItemProxy::new_for_owned(connection, SERVICE_NAME.to_string(), path)?;

        Ok(Item {
            proxy,
            session_path,
        })
    }

    pub fn secret(&self) -> Result<Secret> {
        self.proxy
            .get_secret(&self.session_path)
            .map_err(|_| anyhow!("failed to get secret"))
    }
}
