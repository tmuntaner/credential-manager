/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use crate::secret_service::collection::Collection;
use crate::secret_service::session::Session;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

pub struct Keyring<'a> {
    username: &'a str,
    service: &'a str,
    application: &'a str,
    session: Session<'a>,
}

impl<'a> Keyring<'a> {
    pub fn new(username: &'a str, service: &'a str, application: &'a str) -> Result<Self> {
        let session = Session::new()?;

        Ok(Self {
            username,
            service,
            application,
            session,
        })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        let collection = self.default_collection()?;

        let mut attributes: HashMap<&str, &str> = HashMap::new();
        attributes.insert("application", self.application);
        attributes.insert("service", self.service);
        let label = format!("Password for {}: {}", self.service, self.username);
        collection.create_item(password, label, attributes)?;

        Ok(())
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        let collection = self.default_collection()?;

        let mut attributes: HashMap<&str, &str> = HashMap::new();
        attributes.insert("application", self.application);
        attributes.insert("service", self.service);
        let collection = collection.search(attributes.clone())?;
        if collection.is_empty() {
            return Ok(None);
        }

        let secret = collection
            .get(0)
            .ok_or_else(|| anyhow!("could not get secret"))?
            .secret(self.session.aes_key())?;

        Ok(Some(secret))
    }

    fn default_collection(&self) -> Result<Collection> {
        let path = self.session.secrets_proxy().read_alias("default")?;
        let path_str = path.as_str().to_string();
        let connection = self.session.connection();
        let collection_client = Collection::new(
            connection,
            self.session.session_path(),
            self.session.aes_key(),
            path_str,
        )?;

        Ok(collection_client)
    }
}
