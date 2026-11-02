use crate::domain::models::session::AuthentikSession;
use async_trait::async_trait;
use std::error::Error;
use thiserror::Error;

/// The cache of authentik sessions.
///
/// It should be implemented by the caller.
#[cfg_attr(test, mockall::automock)]
#[async_trait(?Send)]
pub trait SessionCache {
    /// Load the stored session of an `idp_host`. For example, `id.suse.com`.
    async fn load(&self, idp_host: &str) -> Result<Option<AuthentikSession>, SessionCacheError>;

    /// Stores a session for an `idp_host`.
    async fn store(
        &self,
        idp_host: &str,
        session: &AuthentikSession,
    ) -> Result<(), SessionCacheError>;

    /// Removes the session for an `idp_host`.
    async fn clear(&self, idp_host: &str) -> Result<(), SessionCacheError>;
}

/// The session cache errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SessionCacheError {
    #[error(transparent)]
    Failed(Box<dyn Error + Send + Sync>),
}

/// A cache that remembers nothing. Used when sessions must not be stored.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSessionCache;

#[async_trait(?Send)]
impl SessionCache for NoSessionCache {
    async fn load(&self, _idp_host: &str) -> Result<Option<AuthentikSession>, SessionCacheError> {
        Ok(None)
    }

    async fn store(
        &self,
        _idp_host: &str,
        _session: &AuthentikSession,
    ) -> Result<(), SessionCacheError> {
        Ok(())
    }

    async fn clear(&self, _idp_host: &str) -> Result<(), SessionCacheError> {
        Ok(())
    }
}
