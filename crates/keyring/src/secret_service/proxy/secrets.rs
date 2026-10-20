use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use openssl::bn::BigNum;
use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::string::FromUtf8Error;
use thiserror::Error;
use zbus::proxy;
use zbus::Type;
use zbus::{ObjectPath, OwnedObjectPath, OwnedVariant, Variant};

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

/// https://specifications.freedesktop.org/secret-service/latest/re01.html
#[proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets",
    assume_defaults = true
)]
pub trait Secrets {
    fn open_session(&self, algorithm: &str, input: Variant<'_>) -> zbus::Result<OpenSessionResult>;

    fn create_collection(
        &self,
        properties: HashMap<&str, Variant<'_>>,
        alias: &str,
    ) -> zbus::Result<CreateCollectionResult>;

    fn search_items(&self, attributes: HashMap<&str, &str>) -> zbus::Result<SearchItemsResult>;

    fn unlock(&self, objects: Vec<&ObjectPath<'_>>) -> zbus::Result<UnlockResult>;

    fn lock(&self, objects: Vec<&ObjectPath<'_>>) -> zbus::Result<LockResult>;

    fn get_secrets(
        &self,
        objects: Vec<ObjectPath<'_>>,
    ) -> zbus::Result<HashMap<OwnedObjectPath, Secret>>;

    fn read_alias(&self, name: &str) -> zbus::Result<OwnedObjectPath>;

    fn set_alias(&self, name: &str, collection: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(property)]
    fn collections(&self) -> zbus::fdo::Result<Vec<OwnedObjectPath>>;
}

#[derive(Deserialize, Serialize, Type)]
pub struct OpenSessionResult {
    output: OwnedVariant,
    result: OwnedObjectPath,
}

#[derive(Debug, Error)]
pub enum ToServerPublicKeyError {
    #[error(transparent)]
    OpenSSLRandError(#[from] openssl::error::ErrorStack),

    #[error("to bytes error")]
    ToBytesError,
}

impl OpenSessionResult {
    pub fn server_public_key(&self) -> Result<BigNum, ToServerPublicKeyError> {
        let val: Vec<_> = self
            .output
            .clone()
            .try_into()
            .map_err(|_| ToServerPublicKeyError::ToBytesError)?;

        let result = BigNum::from_slice(val.as_slice())?;

        Ok(result)
    }

    pub fn result(&self) -> &OwnedObjectPath {
        &self.result
    }
}

#[derive(Deserialize, Serialize, Type)]
#[allow(dead_code)]
pub struct CreateCollectionResult {
    collection: OwnedObjectPath,
    prompt: OwnedObjectPath,
}

#[derive(Deserialize, Serialize, Type)]
#[allow(dead_code)]
pub struct SearchItemsResult {
    unlocked: Vec<OwnedObjectPath>,
    locked: Vec<OwnedObjectPath>,
}

#[derive(Deserialize, Serialize, Type)]
#[allow(dead_code)]
pub struct LockResult {
    object_paths: Vec<OwnedObjectPath>,
    prompt: OwnedObjectPath,
}

#[derive(Deserialize, Serialize, Type)]
#[allow(dead_code)]
pub struct UnlockResult {
    object_paths: Vec<OwnedObjectPath>,
    prompt: OwnedObjectPath,
}

/// https://specifications.freedesktop.org/secret-service/latest/ch14.html
#[derive(Deserialize, Serialize, Type)]
pub struct Secret {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

#[derive(Debug, Error)]
pub enum SecretError {
    #[error(transparent)]
    InvalidLength(#[from] crypto_common::InvalidLength),

    #[error(transparent)]
    OpenSSLRandError(#[from] openssl::error::ErrorStack),

    #[error(transparent)]
    StringError(#[from] FromUtf8Error),
}

impl Secret {
    pub fn new(
        session: OwnedObjectPath,
        aes: Vec<u8>,
        value: String,
        content_type: String,
    ) -> Result<Self, SecretError> {
        let (value, parameters) = Secret::encrypt(value, aes)?;

        Ok(Secret {
            session,
            parameters,
            value,
            content_type,
        })
    }

    pub fn secret(&self, aes: Vec<u8>) -> Result<String, SecretError> {
        let mut value = self.value.clone();
        let value = value.as_mut_slice();
        let parameter = self.parameters.clone();

        let decryptor = Aes128CbcDec::new_from_slices(aes.as_slice(), parameter.as_slice())?;
        let result = decryptor.decrypt_padded_vec::<Pkcs7>(value).unwrap();
        let secret = String::from_utf8(result)?;

        Ok(secret)
    }

    fn encrypt(secret: String, aes: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), SecretError> {
        let mut value = secret.into_bytes();
        let value = value.as_mut_slice();

        let aes_iv: &mut [u8] = &mut [0u8; 16];
        rand_bytes(aes_iv)?;
        let aes_iv = aes_iv.to_vec();

        let encryptor = Aes128CbcEnc::new_from_slices(aes.as_slice(), aes_iv.as_slice())?;
        let result = encryptor.encrypt_padded_vec::<Pkcs7>(value);

        Ok((result, aes_iv))
    }
}
