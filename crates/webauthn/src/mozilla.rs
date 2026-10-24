use crate::{HmacEnrollment, WebauthnAssertion, WebauthnError, WebauthnNotifier};
use authenticator::{
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
    ctap2::server::{
        AuthenticationExtensionsClientInputs, HMACGetSecretInput, PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
        ResidentKeyRequirement, Transport, UserVerificationRequirement,
    },
    statecallback::StateCallback,
    Pin, StatusPinUv, StatusUpdate,
};
use base64::{alphabet, engine, Engine};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::sync::mpsc::{channel, Receiver, RecvError};
use std::thread;

/// Long enough to type a PIN and touch the key. The server's challenge allows 60 seconds.
const TIMEOUT_MS: u64 = 60_000;

/// Signs a WebAuthn challenge with a security key over CTAP2, falling back to CTAP1 for U2F-only keys.
/// A PIN is asked for on the terminal when the key wants one.
pub fn sign_assertion(
    challenge_str: String,
    rp_id: String,
    origin: String,
    credential_ids: Vec<String>,
    notifiers: Vec<Box<dyn WebauthnNotifier>>,
) -> Result<WebauthnAssertion, WebauthnError> {
    let client_data_json = crate::utils::assertion_client_data(&origin, &challenge_str)?;
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_json.as_bytes()).into();

    let allow_list = allow_list(&credential_ids);
    if allow_list.is_empty() {
        return Err(WebauthnError::NoUsableCredentialIds);
    }

    let mut manager = AuthenticatorService::new()?;
    manager.add_u2f_usb_hid_platform_transports();

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    let (sign_tx, sign_rx) = channel();

    for notifier in &notifiers {
        notifier.notify_start()?;
    }

    let callback = StateCallback::new(Box::new(move |rv| {
        let _ = sign_tx.send(rv);
    }));

    let status_thread = thread::spawn(move || handle_status_updates(status_rx));

    let args = SignArgs {
        client_data_hash,
        origin,
        relying_party_id: rp_id,
        allow_list: allow_list.clone(),
        user_verification_req: UserVerificationRequirement::Preferred,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: false,
    };

    manager
        .sign(TIMEOUT_MS, args, status_tx, callback)
        .map_err(WebauthnError::StartSigning)?;

    let sign_result = sign_rx.recv();

    // The manager holds the status sender; dropping it ends the status thread.
    drop(manager);
    let _ = status_thread.join();

    for notifier in &notifiers {
        notifier.notify_end()?;
    }

    let result = sign_result
        .map_err(|_| WebauthnError::ReceiveSignResult)?
        .map_err(WebauthnError::SecurityKey)?;

    let assertion = result.assertion;
    let credential_id = match (assertion.credentials, allow_list.as_slice()) {
        (Some(credential), _) => credential.id,
        (None, [only]) => only.id.clone(),
        (None, _) => return Err(WebauthnError::UnknownCredential),
    };

    Ok(WebauthnAssertion {
        credential_id,
        client_data_json: client_data_json.into_bytes(),
        authenticator_data: assertion.auth_data.to_vec(),
        signature: assertion.signature,
    })
}

/// Enrolls a new credential with the FIDO2 `hmac-secret` extension enabled.
pub fn enroll_hmac_secret(rp_id: &str) -> Result<HmacEnrollment, WebauthnError> {
    let origin = format!("https://{rp_id}");

    // build the clientDataJSON for enrollment and then hash it.
    let client_data_json = crate::utils::registration_client_data(&origin, "c9s-enroll")?;
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_json.as_bytes()).into();

    // build the authenticator service
    let mut manager = AuthenticatorService::new()?;
    manager.add_u2f_usb_hid_platform_transports();

    // set up the threads
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    let (register_tx, register_rx) = channel();

    let callback = StateCallback::new(Box::new(move |rv| {
        let _ = register_tx.send(rv);
    }));

    let status_thread = thread::spawn(move || handle_status_updates(status_rx));

    let pub_cred_params = vec![
        PublicKeyCredentialParameters::try_from(-7)?,   // ES256
        PublicKeyCredentialParameters::try_from(-8)?,   // EdDSA
        PublicKeyCredentialParameters::try_from(-257)?, // RS256
    ];

    // build the register arguments
    let args = RegisterArgs {
        client_data_hash,
        relying_party: RelyingParty {
            id: rp_id.to_string(),
            name: Some("c9s".to_string()),
        },
        origin,
        user: PublicKeyCredentialUserEntity {
            id: b"c9s-user".to_vec(),
            name: Some("c9s".to_string()),
            display_name: None,
        },
        pub_cred_params,
        exclude_list: vec![],
        user_verification_req: UserVerificationRequirement::Discouraged,
        resident_key_req: ResidentKeyRequirement::Discouraged,
        extensions: AuthenticationExtensionsClientInputs {
            hmac_create_secret: Some(true),
            ..Default::default()
        },
        pin: None,
        use_ctap1_fallback: false,
    };

    // start registration
    manager
        .register(TIMEOUT_MS, args, status_tx, callback)
        .map_err(WebauthnError::StartRegistering)?;
    let register_result = register_rx.recv();

    // drop the authenticator service and join the status thread
    drop(manager);
    let _ = status_thread.join();

    // handle the registration result
    let result = register_result
        .map_err(|_| WebauthnError::ReceiveRegisterResult)?
        .map_err(WebauthnError::SecurityKey)?;

    // if the hmac-secret extension is not supported, return an error
    if result.extensions.hmac_create_secret != Some(true) {
        return Err(WebauthnError::HmacSecretNotSupported);
    }

    // get the credential id
    let credential_id = result
        .att_obj
        .auth_data
        .credential_data
        .ok_or(WebauthnError::UnknownCredential)?
        .credential_id;

    Ok(HmacEnrollment { credential_id })
}

/// Derives a 32-byte secret from a credential using the FIDO2 `hmac-secret` extension and a 32-byte salt.
pub fn derive_hmac_secret(
    rp_id: &str,
    credential_id: &[u8],
    salt: &[u8; 32],
) -> Result<[u8; 32], WebauthnError> {
    let origin = format!("https://{rp_id}");

    // build the clientDataJSON for enrollment and then hash it.
    let client_data_json = crate::utils::assertion_client_data(&origin, "c9s-derive")?;
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_json.as_bytes()).into();

    // build the list of allowed credential ids
    let allow_list = vec![PublicKeyCredentialDescriptor {
        id: credential_id.to_vec(),
        transports: vec![Transport::USB],
    }];

    // build the authentication service
    let mut manager = AuthenticatorService::new()?;
    manager.add_u2f_usb_hid_platform_transports();

    // set up the threads
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    let (sign_tx, sign_rx) = channel();

    let callback = StateCallback::new(Box::new(move |rv| {
        let _ = sign_tx.send(rv);
    }));

    let status_thread = thread::spawn(move || handle_status_updates(status_rx));

    // create the signing request
    let args = SignArgs {
        client_data_hash,
        origin,
        relying_party_id: rp_id.to_string(),
        allow_list,
        user_verification_req: UserVerificationRequirement::Preferred,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs {
            hmac_get_secret: Some(HMACGetSecretInput {
                salt1: *salt,
                salt2: None,
            }),
            ..Default::default()
        },
        pin: None,
        use_ctap1_fallback: false,
    };

    // send the signing request
    manager
        .sign(TIMEOUT_MS, args, status_tx, callback)
        .map_err(WebauthnError::StartSigning)?;
    let sign_result = sign_rx.recv();

    // drop the manager and join the status thread
    drop(manager);
    let _ = status_thread.join();

    // handle the result
    let result = sign_result
        .map_err(|_| WebauthnError::ReceiveSignResult)?
        .map_err(WebauthnError::SecurityKey)?;

    // get the hmac secret
    let output = result
        .extensions
        .hmac_get_secret
        .ok_or(WebauthnError::HmacSecretNotSupported)?;

    Ok(output.output1)
}

/// Answers the key's status updates: asks for the PIN on the terminal, and reports blocked keys.
fn handle_status_updates(status_rx: Receiver<StatusUpdate>) {
    let mut touch_prompted = false;
    loop {
        match status_rx.recv() {
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender))) => {
                send_pin(&sender, "Security key PIN: ");
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts))) => {
                match attempts {
                    Some(attempts) => eprintln!("Wrong PIN, {attempts} attempts left."),
                    None => eprintln!("Wrong PIN."),
                }
                send_pin(&sender, "Security key PIN: ");
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked)) => {
                eprintln!("The security key is blocked after too many wrong PINs. Unplug it and plug it in again.");
            }
            Ok(StatusUpdate::PinUvError(StatusPinUv::PinBlocked)) => {
                eprintln!("The security key PIN is blocked. The key has to be reset.");
            }
            Ok(StatusUpdate::PresenceRequired) => {
                if !touch_prompted {
                    eprintln!("Touch your security key...");
                    touch_prompted = true;
                }
            }
            Ok(StatusUpdate::SelectDeviceNotice) => {
                eprintln!("Several security keys found, touch the one to use.");
            }
            Ok(_) => {}
            Err(RecvError) => return,
        }
    }
}

fn send_pin(sender: &std::sync::mpsc::Sender<Pin>, prompt: &str) {
    if let Ok(pin) = rpassword::prompt_password(prompt) {
        let _ = sender.send(Pin::new(&pin));
    }
}

/// The base64url (no padding) credential ids as descriptors. Ids that do not decode are skipped.
fn allow_list(credential_ids: &[String]) -> Vec<PublicKeyCredentialDescriptor> {
    let base64urlsafe =
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::NO_PAD);

    credential_ids
        .iter()
        .filter_map(|credential_id| {
            let id = base64urlsafe.decode(credential_id).unwrap_or_default();

            if id.is_empty() {
                None
            } else {
                // The server sends no transports; the key is on USB.
                Some(PublicKeyCredentialDescriptor {
                    id,
                    transports: vec![Transport::USB],
                })
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_decodes_base64url_without_padding() {
        // 0xfb 0xff is `-_8` in base64url, and `+/8=` in the standard alphabet.
        let handles = allow_list(&["-_8".to_string(), "AQID".to_string()]);

        assert_eq!(handles.len(), 2);
        assert_eq!(handles[0].id, vec![0xfb, 0xff]);
        assert_eq!(handles[1].id, vec![1, 2, 3]);
    }

    #[test]
    fn allow_list_skips_ids_that_do_not_decode() {
        let handles = allow_list(&["***".to_string(), "".to_string(), "AQID".to_string()]);

        assert_eq!(handles.len(), 1);
    }

    #[test]
    fn sign_assertion_needs_usable_credential_ids() {
        // Fails before any device is touched.
        let err = sign_assertion(
            "challenge".to_string(),
            "id.example.com".to_string(),
            "https://id.example.com".to_string(),
            vec!["***".to_string()],
            vec![],
        )
        .err()
        .unwrap();

        assert_eq!(
            err.to_string(),
            "the challenge has no usable credential ids"
        );
    }

    #[test]
    fn sign_assertion_rejects_an_invalid_origin() {
        let err = sign_assertion(
            "challenge".to_string(),
            "id.example.com".to_string(),
            "not a url".to_string(),
            vec!["AQID".to_string()],
            vec![],
        );

        assert!(err.is_err());
    }

    #[test]
    fn enroll_hmac_secret_rejects_an_invalid_origin() {
        let err = enroll_hmac_secret("not a valid url :// invalid");
        assert!(err.is_err());
    }

    #[test]
    fn derive_hmac_secret_rejects_an_invalid_origin() {
        let err = derive_hmac_secret("not a valid url :// invalid", b"cred", &[0u8; 32]);
        assert!(err.is_err());
    }
}
