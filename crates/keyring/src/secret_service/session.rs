use crate::secret_service::proxy::secrets::ToServerPublicKeyError;
use crate::secret_service::proxy::secrets::{OpenSessionResult, SecretsProxy};
use hkdf::Hkdf;
use openssl::bn::BigNum;
use sha2::Sha256;
use std::borrow::Borrow;
use thiserror::Error;
use zbus::Connection;
use zbus::OwnedObjectPath;

pub const SERVICE_NAME: &str = "org.freedesktop.secrets";

pub struct Session<'a> {
    secrets: SecretsProxy<'a>,
    connection: Connection,
    session_path: OwnedObjectPath,
    aes_key: Vec<u8>,
}

/// Size in bytes of the 1024 bit prime, and so of the shared secret.
const DH_SECRET_LEN: usize = 128;

pub const DH_ALGORITHM: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

#[derive(Debug, Error)]
pub enum SessionError {
    #[error(transparent)]
    OpenSSL(#[from] openssl::error::ErrorStack),

    #[error(transparent)]
    ZBus(#[from] zbus::Error),

    #[error(transparent)]
    ServerPublicKey(#[from] ToServerPublicKeyError),

    #[error("could not derive the session key: {0}")]
    Hkdf(#[from] hkdf::InvalidLength),
}

impl Session<'_> {
    pub async fn new() -> Result<Self, SessionError> {
        let generator = BigNum::from_u32(2u32)?;
        let p = BigNum::get_rfc2409_prime_1024()?;
        let dh = openssl::dh::Dh::from_pqg(p, None, generator)?;
        let key = dh.generate_key()?;
        let public_key = key.public_key();

        let connection = Connection::session().await?;
        let secrets: SecretsProxy = SecretsProxy::new(&connection).await?;
        let session: OpenSessionResult = secrets
            .open_session(DH_ALGORITHM, public_key.to_vec().as_slice().into())
            .await?;

        let server_public_key = session.server_public_key()?;
        let common_key = key.compute_key(server_public_key.borrow())?;

        // OpenSSL drops leading zero bytes of the shared secret, but the service derives its key
        // from the full 128 bytes (the size of the prime). Without the padding the keys differ
        // in about 1 of 256 sessions and the service rejects the secret.
        let mut ikm = vec![0u8; DH_SECRET_LEN.saturating_sub(common_key.len())];
        ikm.extend_from_slice(&common_key);
        let ikm = ikm.as_slice();
        let info = [];

        let mut okm = [0; 16];
        let (_, hk) = Hkdf::<Sha256>::extract(None, ikm);
        hk.expand(&info, &mut okm)?;

        let aes_key = okm.to_vec();

        Ok(Self {
            secrets,
            connection,
            aes_key,
            session_path: session.result().clone(),
        })
    }

    pub fn secrets_proxy(&self) -> &SecretsProxy<'_> {
        &self.secrets
    }

    pub fn aes_key(&self) -> Vec<u8> {
        self.aes_key.clone()
    }

    pub fn connection(&self) -> Connection {
        self.connection.clone()
    }

    pub fn session_path(&self) -> OwnedObjectPath {
        self.session_path.clone()
    }
}
