use crate::secret_service::item::{Item, ItemError};
use crate::secret_service::proxy::secrets::{Secret, SecretError};
use crate::secret_service::proxy::secrets_collection::CollectionProxy;
use crate::secret_service::session::SERVICE_NAME;
use std::collections::HashMap;
use thiserror::Error;
use zbus::Connection;
use zbus::{Dict, OwnedObjectPath, Variant};

pub const ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
pub const ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";

pub struct Collection<'a> {
    proxy: CollectionProxy<'a>,
    connection: Connection,
    session_path: OwnedObjectPath,
    aes_key: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum NewCollectionError {
    #[error(transparent)]
    ZBusError(#[from] zbus::Error),
}

#[derive(Debug, Error)]
pub enum CreateSecretError {
    #[error(transparent)]
    SecretError(#[from] SecretError),

    #[error(transparent)]
    ZBusError(#[from] zbus::Error),
}

#[derive(Debug, Error)]
pub enum SearchSecretsError {
    #[error(transparent)]
    Item(#[from] ItemError),

    #[error(transparent)]
    Secret(#[from] SecretError),

    #[error(transparent)]
    ZBus(#[from] zbus::Error),
}

impl Collection<'_> {
    pub async fn new<'a>(
        connection: Connection,
        session_path: OwnedObjectPath,
        aes_key: Vec<u8>,
        path: String,
    ) -> Result<Collection<'a>, NewCollectionError> {
        let proxy = CollectionProxy::builder(&connection)
            .destination(SERVICE_NAME.to_string())
            .path(path)
            .build()
            .await?;

        Ok(Collection {
            proxy,
            connection,
            aes_key,
            session_path,
        })
    }

    pub async fn create_item(
        &self,
        secret: String,
        label: String,
        attributes: HashMap<&str, &str>,
    ) -> Result<(), CreateSecretError> {
        let mut properties: HashMap<&str, Variant> = HashMap::new();
        let attributes: Dict = attributes.into();

        properties.insert(ITEM_LABEL, label.into());
        properties.insert(ITEM_ATTRIBUTES, attributes.into());
        let secret = Secret::new(
            self.session_path.clone(),
            self.aes_key.clone(),
            secret,
            String::from("text/plain"),
        )?;

        let _created_item = self.proxy.create_item(properties, secret, true).await?;

        Ok(())
    }

    pub async fn search(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> Result<Vec<Secret>, SearchSecretsError> {
        let item_paths = self.proxy.search_items(attributes).await?;

        let mut secrets = Vec::with_capacity(item_paths.len());
        for item in item_paths {
            let path = item.as_str().to_string();
            let item = Item::new(self.connection.clone(), self.session_path.clone(), path).await?;
            secrets.push(item.secret().await?);
        }

        Ok(secrets)
    }
}
