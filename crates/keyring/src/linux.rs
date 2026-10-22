use crate::errors::KeyringError;
use crate::secret_service::collection::Collection;
use crate::secret_service::session::Session;
use futures_executor::block_on;
use std::collections::HashMap;

pub struct Keyring<'a> {
    username: &'a str,
    service: &'a str,
    application: &'a str,
    session: Session<'a>,
}

impl<'a> Keyring<'a> {
    pub fn new(
        username: &'a str,
        service: &'a str,
        application: &'a str,
    ) -> Result<Self, KeyringError> {
        let session = block_on(Session::new())?;

        Ok(Self {
            username,
            service,
            application,
            session,
        })
    }

    pub fn set_password(&self, password: String) -> Result<(), KeyringError> {
        block_on(self.set_password_async(password))
    }

    pub fn get_password(&self) -> Result<Option<String>, KeyringError> {
        block_on(self.get_password_async())
    }

    async fn set_password_async(&self, password: String) -> Result<(), KeyringError> {
        let collection = self.default_collection().await?;

        let mut attributes: HashMap<&str, &str> = HashMap::new();
        attributes.insert("application", self.application);
        attributes.insert("service", self.service);
        let label = format!("Password for {}: {}", self.service, self.username);
        collection.create_item(password, label, attributes).await?;

        Ok(())
    }

    async fn get_password_async(&self) -> Result<Option<String>, KeyringError> {
        let collection = self.default_collection().await?;

        let mut attributes: HashMap<&str, &str> = HashMap::new();
        attributes.insert("application", self.application);
        attributes.insert("service", self.service);
        let collection = collection.search(attributes.clone()).await?;
        if collection.is_empty() {
            return Ok(None);
        }

        let secret = collection
            .first()
            .ok_or(KeyringError::NoSecret)?
            .secret(self.session.aes_key())?;

        Ok(Some(secret))
    }

    async fn default_collection(&self) -> Result<Collection<'_>, KeyringError> {
        let path = self.session.secrets_proxy().read_alias("default").await?;
        let path_str = path.as_str().to_string();
        let connection = self.session.connection();
        let collection_client = Collection::new(
            connection,
            self.session.session_path(),
            self.session.aes_key(),
            path_str,
        )
        .await?;

        Ok(collection_client)
    }
}
