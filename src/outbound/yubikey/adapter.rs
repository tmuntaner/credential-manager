use std::sync::{Arc, Mutex};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::domain::ports::secret_store::Secret;
use crate::domain::ports::secret_wrapper::{SecretWrapper, WrapError};

const ENVELOPE_PREFIX: &str = "c9s-yk1:";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HKDF_INFO: &[u8] = b"c9s-secret-wrap-v1";

/// Trait for deriving the 32-byte secret using FIDO2 `hmac-secret`.
pub trait HmacSecretDeriver: Send + Sync {
    fn derive(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
    ) -> Result<[u8; 32], WrapError>;
}

/// Default deriver that talks to the hardware key via `webauthn`.
#[derive(Default, Debug, Clone)]
pub struct FidoHmacSecretDeriver;

impl HmacSecretDeriver for FidoHmacSecretDeriver {
    fn derive(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
    ) -> Result<[u8; 32], WrapError> {
        webauthn::derive_hmac_secret(rp_id, credential_id, salt).map_err(WrapError::from)
    }
}

/// Enrolls a new YubiKey credential with FIDO2 `hmac-secret` and generates a random 32-byte salt.
pub fn enroll(rp_id: &str) -> Result<crate::domain::models::settings::YubikeyConfig, WrapError> {
    #[cfg(target_os = "windows")]
    {
        let _ = rp_id;
        Err(WrapError::Failed(Box::new(std::io::Error::other(
            "YubiKey wrapping is not supported on Windows",
        ))))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let enrollment = webauthn::enroll_hmac_secret(rp_id)?;
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).map_err(|e| WrapError::Failed(Box::new(e)))?;
        Ok(crate::domain::models::settings::YubikeyConfig::new(
            &enrollment.credential_id,
            rp_id,
            &salt,
        ))
    }
}

/// Outbound adapter providing envelope encryption backed by a YubiKey.
#[derive(Clone)]
pub struct YubikeyWrapper<D = FidoHmacSecretDeriver> {
    rp_id: String,
    credential_id: Vec<u8>,
    salt: [u8; 32],
    deriver: D,
    cached_key: Arc<Mutex<Option<[u8; 32]>>>,
}

impl YubikeyWrapper<FidoHmacSecretDeriver> {
    pub fn new(rp_id: impl Into<String>, credential_id: Vec<u8>, salt: [u8; 32]) -> Self {
        Self::with_deriver(rp_id, credential_id, salt, FidoHmacSecretDeriver)
    }
}

impl<D: HmacSecretDeriver> YubikeyWrapper<D> {
    pub fn with_deriver(
        rp_id: impl Into<String>,
        credential_id: Vec<u8>,
        salt: [u8; 32],
        deriver: D,
    ) -> Self {
        Self {
            rp_id: rp_id.into(),
            credential_id,
            salt,
            deriver,
            cached_key: Arc::new(Mutex::new(None)),
        }
    }

    fn get_or_derive_key(&self) -> Result<[u8; 32], WrapError> {
        // get the cached key if it exists
        let mut guard = self
            .cached_key
            .lock()
            .map_err(|e| WrapError::Failed(Box::new(std::io::Error::other(e.to_string()))))?;

        // if the cached key exists, return it
        if let Some(key) = *guard {
            return Ok(key);
        }

        // derive the key
        let hmac_secret = self
            .deriver
            .derive(&self.rp_id, &self.credential_id, &self.salt)?;

        let hkdf = Hkdf::<Sha256>::new(None, &hmac_secret);
        let mut aes_key = [0u8; 32];
        hkdf.expand(HKDF_INFO, &mut aes_key)
            .map_err(|e| WrapError::Failed(Box::new(e)))?;

        // set the cached key and return it
        *guard = Some(aes_key);
        Ok(aes_key)
    }
}

impl<D> Drop for YubikeyWrapper<D> {
    fn drop(&mut self) {
        if Arc::strong_count(&self.cached_key) == 1 {
            if let Ok(mut guard) = self.cached_key.lock() {
                if let Some(mut key) = guard.take() {
                    key.zeroize();
                }
            }
        }
    }
}

impl<D: HmacSecretDeriver> SecretWrapper for YubikeyWrapper<D> {
    fn wrap(&self, aad: &[u8], plaintext: &Secret) -> Result<Secret, WrapError> {
        // get the key
        let key = self.get_or_derive_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| WrapError::Failed(Box::new(std::io::Error::other(format!("{e:?}")))))?;

        // build a nonce
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| WrapError::Failed(Box::new(e)))?;

        // create the payload
        let payload = Payload {
            msg: plaintext.as_str().as_bytes(),
            aad,
        };

        // encrypt the payload
        let ciphertext_and_tag = cipher
            .encrypt(&Nonce::from(nonce), payload)
            .map_err(|e| WrapError::Failed(Box::new(std::io::Error::other(format!("{e:?}")))))?;

        // combine the nonce and ciphertext
        let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext_and_tag.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&ciphertext_and_tag);

        // base64 encode the combined data
        let encoded = base64::engine::general_purpose::STANDARD.encode(&combined);

        Ok(Secret::new(format!("{ENVELOPE_PREFIX}{encoded}")))
    }

    fn unwrap(&self, aad: &[u8], ciphertext: &Secret) -> Result<Secret, WrapError> {
        // get the raw text
        let raw = ciphertext.as_str();

        // see if the text starts with the envelope prefix
        // if it doesn't, it wasn't wrapped, so return it as an error
        if !raw.starts_with(ENVELOPE_PREFIX) {
            return Err(WrapError::NotWrapped);
        }

        // separate the encoded data from the envelope prefix
        // decode the base64 encoded data
        let encoded = &raw[ENVELOPE_PREFIX.len()..];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| WrapError::Corrupt)?;

        // if the decoded data is too short, it's corrupt
        if decoded.len() < NONCE_LEN + TAG_LEN {
            return Err(WrapError::Corrupt);
        }

        // separate the nonce and ciphertext/tag
        let (nonce_bytes, ct_and_tag) = decoded.split_at(NONCE_LEN);

        // get the key
        let key = self.get_or_derive_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| WrapError::Failed(Box::new(std::io::Error::other(format!("{e:?}")))))?;

        // parse the nonce
        let nonce = Nonce::try_from(nonce_bytes).map_err(|_| WrapError::Corrupt)?;

        // build the decryption payload
        let payload = Payload {
            msg: ct_and_tag,
            aad,
        };

        // decrypt the ciphertext/tag
        let decrypted_bytes = cipher
            .decrypt(&nonce, payload)
            .map_err(|_| WrapError::Corrupt)?;

        // convert from bytes to a string
        let plaintext = String::from_utf8(decrypted_bytes).map_err(|_| WrapError::Corrupt)?;

        Ok(Secret::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeDeriver {
        secret: [u8; 32],
        calls: AtomicUsize,
    }

    impl FakeDeriver {
        fn new(secret: [u8; 32]) -> Self {
            Self {
                secret,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl HmacSecretDeriver for FakeDeriver {
        fn derive(
            &self,
            _rp_id: &str,
            _credential_id: &[u8],
            _salt: &[u8; 32],
        ) -> Result<[u8; 32], WrapError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.secret)
        }
    }

    #[test]
    fn envelope_roundtrip_succeeds() {
        let deriver = FakeDeriver::new([0x42; 32]);
        let wrapper =
            YubikeyWrapper::with_deriver("example.com", vec![1, 2, 3], [0u8; 32], deriver);

        let aad = b"c9s-aad:v1:user:service:app";
        let plaintext = Secret::new("my-super-secret-password-1234");

        let wrapped = wrapper.wrap(aad, &plaintext).unwrap();
        assert!(wrapped.expose_secret().starts_with("c9s-yk1:"));

        let unwrapped = wrapper.unwrap(aad, &wrapped).unwrap();
        assert_eq!(unwrapped.expose_secret(), "my-super-secret-password-1234");
    }

    #[test]
    fn wrong_aad_fails_with_corrupt() {
        let deriver = FakeDeriver::new([0x42; 32]);
        let wrapper =
            YubikeyWrapper::with_deriver("example.com", vec![1, 2, 3], [0u8; 32], deriver);

        let aad = b"correct-aad";
        let wrong_aad = b"wrong-aad";
        let plaintext = Secret::new("password");

        let wrapped = wrapper.wrap(aad, &plaintext).unwrap();
        let err = wrapper.unwrap(wrong_aad, &wrapped).unwrap_err();

        assert!(matches!(err, WrapError::Corrupt));
    }

    #[test]
    fn tampered_ciphertext_fails_with_corrupt() {
        let deriver = FakeDeriver::new([0x42; 32]);
        let wrapper =
            YubikeyWrapper::with_deriver("example.com", vec![1, 2, 3], [0u8; 32], deriver);

        let aad = b"aad";
        let plaintext = Secret::new("password");

        let wrapped = wrapper.wrap(aad, &plaintext).unwrap();
        let raw = wrapped.expose_secret();
        let encoded = &raw[ENVELOPE_PREFIX.len()..];
        let mut decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();

        // Tamper with the last byte (part of authentication tag)
        let len = decoded.len();
        decoded[len - 1] ^= 0x01;

        let tampered_encoded = base64::engine::general_purpose::STANDARD.encode(&decoded);
        let tampered_secret = Secret::new(format!("{ENVELOPE_PREFIX}{tampered_encoded}"));

        let err = wrapper.unwrap(aad, &tampered_secret).unwrap_err();
        assert!(matches!(err, WrapError::Corrupt));
    }

    #[test]
    fn tampered_nonce_fails_with_corrupt() {
        let deriver = FakeDeriver::new([0x42; 32]);
        let wrapper =
            YubikeyWrapper::with_deriver("example.com", vec![1, 2, 3], [0u8; 32], deriver);

        let aad = b"aad";
        let plaintext = Secret::new("password");

        let wrapped = wrapper.wrap(aad, &plaintext).unwrap();
        let raw = wrapped.expose_secret();
        let encoded = &raw[ENVELOPE_PREFIX.len()..];
        let mut decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();

        // Tamper with the first byte (part of nonce)
        decoded[0] ^= 0x01;

        let tampered_encoded = base64::engine::general_purpose::STANDARD.encode(&decoded);
        let tampered_secret = Secret::new(format!("{ENVELOPE_PREFIX}{tampered_encoded}"));

        let err = wrapper.unwrap(aad, &tampered_secret).unwrap_err();
        assert!(matches!(err, WrapError::Corrupt));
    }

    #[test]
    fn not_wrapped_prefix_fails_with_not_wrapped() {
        let deriver = FakeDeriver::new([0x42; 32]);
        let wrapper =
            YubikeyWrapper::with_deriver("example.com", vec![1, 2, 3], [0u8; 32], deriver);

        let aad = b"aad";
        let plain = Secret::new("plaintext-password");

        let err = wrapper.unwrap(aad, &plain).unwrap_err();
        assert!(matches!(err, WrapError::NotWrapped));
    }

    #[test]
    fn corrupted_base64_fails_with_corrupt() {
        let deriver = FakeDeriver::new([0x42; 32]);
        let wrapper =
            YubikeyWrapper::with_deriver("example.com", vec![1, 2, 3], [0u8; 32], deriver);

        let aad = b"aad";
        let corrupt = Secret::new(format!("{ENVELOPE_PREFIX}not-valid-base64!!"));

        let err = wrapper.unwrap(aad, &corrupt).unwrap_err();
        assert!(matches!(err, WrapError::Corrupt));
    }

    #[test]
    fn truncated_payload_fails_with_corrupt() {
        let deriver = FakeDeriver::new([0x42; 32]);
        let wrapper =
            YubikeyWrapper::with_deriver("example.com", vec![1, 2, 3], [0u8; 32], deriver);

        let aad = b"aad";
        // Less than 28 bytes
        let short_data = [0u8; 10];
        let encoded = base64::engine::general_purpose::STANDARD.encode(short_data);
        let corrupt = Secret::new(format!("{ENVELOPE_PREFIX}{encoded}"));

        let err = wrapper.unwrap(aad, &corrupt).unwrap_err();
        assert!(matches!(err, WrapError::Corrupt));
    }

    #[test]
    fn nonce_uniqueness_for_same_plaintext() {
        let deriver = FakeDeriver::new([0x42; 32]);
        let wrapper =
            YubikeyWrapper::with_deriver("example.com", vec![1, 2, 3], [0u8; 32], deriver);

        let aad = b"aad";
        let plaintext = Secret::new("same-password");

        let wrap1 = wrapper.wrap(aad, &plaintext).unwrap();
        let wrap2 = wrapper.wrap(aad, &plaintext).unwrap();

        assert_ne!(wrap1.expose_secret(), wrap2.expose_secret());
    }

    #[test]
    fn in_process_key_caching_calls_deriver_only_once() {
        let deriver = FakeDeriver::new([0x42; 32]);
        let wrapper =
            YubikeyWrapper::with_deriver("example.com", vec![1, 2, 3], [0u8; 32], deriver);

        let aad = b"aad";
        let pt1 = Secret::new("pass1");
        let pt2 = Secret::new("pass2");

        let ct1 = wrapper.wrap(aad, &pt1).unwrap();
        let ct2 = wrapper.wrap(aad, &pt2).unwrap();
        let _ = wrapper.unwrap(aad, &ct1).unwrap();
        let _ = wrapper.unwrap(aad, &ct2).unwrap();

        assert_eq!(wrapper.deriver.calls.load(Ordering::SeqCst), 1);
    }
}
