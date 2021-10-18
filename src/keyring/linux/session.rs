use crate::keyring::linux::proxy::secrets::{OpenSessionResult, SecretsProxy};
use anyhow::Result;
use hkdf::Hkdf;
use openssl::bn::BigNum;
use sha2::Sha256;
use std::borrow::Borrow;
use zbus::Connection;
use zvariant::OwnedObjectPath;

pub const SERVICE_NAME: &str = "org.freedesktop.secrets";

pub struct Session<'a> {
    secrets: SecretsProxy<'a>,
    connection: Connection,
    session_path: OwnedObjectPath,
    aes_key: Vec<u8>,
}

pub const DH_ALGORITHM: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

impl Session<'_> {
    pub fn new() -> Result<Self> {
        let generator = BigNum::from_u32(2u32)?;
        let p = BigNum::get_rfc2409_prime_1024()?;
        let dh = openssl::dh::Dh::from_pqg(p, None, generator)?;
        let key = dh.generate_key()?;
        let public_key = key.public_key();

        let connection = zbus::Connection::new_session()?;
        let secrets: SecretsProxy = SecretsProxy::new(&connection)?;
        let session: OpenSessionResult =
            secrets.open_session(DH_ALGORITHM, public_key.to_vec().as_slice().into())?;

        let server_public_key = session.server_public_key()?;
        let common_key = key.compute_key(server_public_key.borrow())?;

        let ikm = common_key.as_slice();
        let info = [];

        let mut okm = [0; 16];
        let (_, hk) = Hkdf::<Sha256>::extract(None, ikm);
        hk.expand(&info, &mut okm).expect("hkdf should not fail");

        let aes_key = okm.to_vec();

        Ok(Self {
            secrets,
            connection,
            aes_key,
            session_path: session.result().clone(),
        })
    }

    pub fn secrets_proxy(&self) -> &SecretsProxy {
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
