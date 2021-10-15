use crate::keyring::linux::collection::Collection;
use crate::keyring::linux::session::Session;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

pub struct KeyringClient<'a> {
    username: String,
    service: String,
    session: Session<'a>,
}

impl KeyringClient<'_> {
    pub fn new(username: String, service: String) -> Result<Self> {
        let session = Session::new()?;

        Ok(KeyringClient {
            username,
            service,
            session,
        })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        let collection = self.default_collection()?;

        let mut attributes: HashMap<&str, &str> = HashMap::new();
        attributes.insert("application", "rust-keyring");
        attributes.insert("service", self.service.as_str());
        let label = format!("Password for {} on {}", self.username, self.service);
        collection.create_item(password, label, attributes)?;

        Ok(())
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        let collection = self.default_collection()?;

        let mut attributes: HashMap<&str, &str> = HashMap::new();
        attributes.insert("application", "rust-keyring");
        attributes.insert("service", self.service.as_str());
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
