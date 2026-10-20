/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes128;
use anyhow::Result;
use cbc::{Decryptor, Encryptor};
use openssl::bn::BigNum;
use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use zbus::dbus_proxy;
use zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zvariant_derive::Type;

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

/// https://specifications.freedesktop.org/secret-service/latest/re01.html
#[dbus_proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets",
    assume_defaults = true
)]
pub trait Secrets {
    fn open_session(&self, algorithm: &str, input: Value<'_>) -> zbus::Result<OpenSessionResult>;

    fn create_collection(
        &self,
        properties: HashMap<&str, Value<'_>>,
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

    #[dbus_proxy(property)]
    fn collections(&self) -> zbus::fdo::Result<Vec<ObjectPath<'_>>>;
}

#[derive(Deserialize, Serialize, Type)]
pub struct OpenSessionResult {
    output: OwnedValue,
    result: OwnedObjectPath,
}

impl OpenSessionResult {
    pub fn server_public_key(&self) -> Result<BigNum> {
        let val: Vec<_> = self.output.clone().try_into()?;

        let result = BigNum::from_slice(val.as_slice())?;

        Ok(result)
    }

    pub fn result(&self) -> &OwnedObjectPath {
        &self.result
    }
}

#[derive(Deserialize, Serialize, Type)]
pub struct CreateCollectionResult {
    collection: OwnedObjectPath,
    prompt: OwnedObjectPath,
}

#[derive(Deserialize, Serialize, Type)]
pub struct SearchItemsResult {
    unlocked: Vec<OwnedObjectPath>,
    locked: Vec<OwnedObjectPath>,
}

#[derive(Deserialize, Serialize, Type)]
pub struct LockResult {
    object_paths: Vec<OwnedObjectPath>,
    prompt: OwnedObjectPath,
}

#[derive(Deserialize, Serialize, Type)]
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

impl Secret {
    pub fn new(
        session: OwnedObjectPath,
        aes: Vec<u8>,
        value: String,
        content_type: String,
    ) -> Result<Self> {
        let (value, parameters) = Secret::encrypt(value, aes)?;

        Ok(Secret {
            session,
            parameters,
            value,
            content_type,
        })
    }

    pub fn secret(&self, aes: Vec<u8>) -> Result<String> {
        let mut value = self.value.clone();
        let value = value.as_mut_slice();
        let parameter = self.parameters.clone();

        let decryptor = Aes128CbcDec::new_from_slices(aes.as_slice(), parameter.as_slice())?;
        let result = decryptor.decrypt_padded_vec_mut::<Pkcs7>(value).unwrap();
        let secret = String::from_utf8(result)?;

        Ok(secret)
    }

    fn encrypt(secret: String, aes: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut value = secret.into_bytes();
        let value = value.as_mut_slice();

        let aes_iv: &mut [u8] = &mut [0u8; 16];
        rand_bytes(aes_iv)?;
        let aes_iv = aes_iv.to_vec();

        let encryptor = Aes128CbcEnc::new_from_slices(aes.as_slice(), aes_iv.as_slice())?;
        let result = encryptor.encrypt_padded_vec_mut::<Pkcs7>(value);

        Ok((result, aes_iv))
    }
}
