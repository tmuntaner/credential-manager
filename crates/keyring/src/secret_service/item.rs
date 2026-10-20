use crate::secret_service::proxy::secrets::Secret;
use crate::secret_service::proxy::secrets_item::ItemProxy;
use crate::secret_service::session::SERVICE_NAME;
use thiserror::Error;
use zbus::Connection;
use zbus::OwnedObjectPath;

pub struct Item<'a> {
    proxy: ItemProxy<'a>,
    session_path: OwnedObjectPath,
}

#[derive(Debug, Error)]
pub enum ItemError {
    #[error(transparent)]
    ZBusError(#[from] zbus::Error),
}

impl Item<'_> {
    pub async fn new<'a>(
        connection: Connection,
        session_path: OwnedObjectPath,
        path: String,
    ) -> Result<Item<'a>, ItemError> {
        let proxy = ItemProxy::builder(&connection)
            .destination(SERVICE_NAME.to_string())
            .path(path)
            .build()
            .await?;

        Ok(Item {
            proxy,
            session_path,
        })
    }

    pub async fn secret(&self) -> Result<Secret, ItemError> {
        let result = self.proxy.get_secret(&self.session_path).await?;

        Ok(result)
    }
}
