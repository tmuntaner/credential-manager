/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use crate::secret_service::proxy::secrets::Secret;
use crate::secret_service::proxy::secrets_item::ItemProxyBlocking;
use crate::secret_service::session::SERVICE_NAME;
use anyhow::{anyhow, Result};
use zbus::blocking::Connection;
use zvariant::OwnedObjectPath;

pub struct Item<'a> {
    proxy: ItemProxyBlocking<'a>,
    session_path: OwnedObjectPath,
}

impl Item<'_> {
    pub fn new<'a>(
        connection: Connection,
        session_path: OwnedObjectPath,
        path: String,
    ) -> Result<Item<'a>> {
        let proxy = ItemProxyBlocking::builder(&connection)
            .destination(SERVICE_NAME.to_string())?
            .path(path)?
            .build()?;

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
