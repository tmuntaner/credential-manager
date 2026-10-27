use crate::{
    HmacEnrollment, KeyEvent, PinRequest, SecurityKeyUi, WebauthnAssertion, WebauthnError,
    WebauthnNotifier,
};
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
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use tokio::sync::{mpsc as tokio_mpsc, oneshot};

/// Long enough to type a PIN and touch the key. The server's challenge allows 60 seconds.
const TIMEOUT_MS: u64 = 60_000;

/// Signs a WebAuthn challenge with a security key over CTAP2, falling back to CTAP1 for U2F-only keys.
/// `ui` is asked for the PIN when the key wants one.
pub async fn sign_assertion(
    challenge_str: String,
    rp_id: String,
    origin: String,
    credential_ids: Vec<String>,
    notifiers: Vec<Arc<dyn WebauthnNotifier>>,
    ui: Arc<dyn SecurityKeyUi>,
) -> Result<WebauthnAssertion, WebauthnError> {
    let client_data_json = crate::utils::assertion_client_data(&origin, &challenge_str)?;
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_json.as_bytes()).into();

    let allow_list = allow_list(&credential_ids);
    if allow_list.is_empty() {
        return Err(WebauthnError::NoUsableCredentialIds);
    }

    let mut manager = AuthenticatorService::new()?;
    manager.add_u2f_usb_hid_platform_transports();

    let (status_tx, status_rx) = status_channel();
    let (sign_tx, sign_rx) = oneshot::channel();

    for notifier in &notifiers {
        notifier.notify_start()?;
    }

    let callback = StateCallback::new(Box::new(move |rv| {
        let _ = sign_tx.send(rv);
    }));

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

    let sign_result = answer_status_updates(status_rx, sign_rx, ui.as_ref()).await;
    drop(manager);

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
pub async fn enroll_hmac_secret(
    rp_id: &str,
    ui: Arc<dyn SecurityKeyUi>,
) -> Result<HmacEnrollment, WebauthnError> {
    let origin = format!("https://{rp_id}");

    // build the clientDataJSON for enrollment and then hash it.
    let client_data_json = crate::utils::registration_client_data(&origin, "c9s-enroll")?;
    let client_data_hash: [u8; 32] = Sha256::digest(client_data_json.as_bytes()).into();

    // build the authenticator service
    let mut manager = AuthenticatorService::new()?;
    manager.add_u2f_usb_hid_platform_transports();

    // set up the channels
    let (status_tx, status_rx) = status_channel();
    let (register_tx, register_rx) = oneshot::channel();

    let callback = StateCallback::new(Box::new(move |rv| {
        let _ = register_tx.send(rv);
    }));

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

    let register_result = answer_status_updates(status_rx, register_rx, ui.as_ref()).await;
    drop(manager);

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
pub async fn derive_hmac_secret(
    rp_id: &str,
    credential_id: &[u8],
    salt: &[u8; 32],
    ui: Arc<dyn SecurityKeyUi>,
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

    // set up the channels
    let (status_tx, status_rx) = status_channel();
    let (sign_tx, sign_rx) = oneshot::channel();

    let callback = StateCallback::new(Box::new(move |rv| {
        let _ = sign_tx.send(rv);
    }));

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

    let sign_result = answer_status_updates(status_rx, sign_rx, ui.as_ref()).await;
    drop(manager);

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

/// The channel the authenticator reports its status on.
///
/// The authenticator wants a blocking sender, so a thread moves the updates onto a channel that can
/// be awaited. It ends when the authenticator drops its sender.
fn status_channel() -> (
    Sender<StatusUpdate>,
    tokio_mpsc::UnboundedReceiver<StatusUpdate>,
) {
    let (status_tx, status_rx) = channel::<StatusUpdate>();
    let (forward_tx, forward_rx) = tokio_mpsc::unbounded_channel();

    thread::spawn(move || forward(status_rx, forward_tx));

    (status_tx, forward_rx)
}

fn forward(from: Receiver<StatusUpdate>, to: tokio_mpsc::UnboundedSender<StatusUpdate>) {
    while let Ok(update) = from.recv() {
        if to.send(update).is_err() {
            break;
        }
    }
}

/// Answers the key's status updates until the key has a result.
async fn answer_status_updates<T>(
    mut status_rx: tokio_mpsc::UnboundedReceiver<StatusUpdate>,
    mut result_rx: oneshot::Receiver<T>,
    ui: &dyn SecurityKeyUi,
) -> Result<T, oneshot::error::RecvError> {
    let mut touch_prompted = false;
    loop {
        tokio::select! {
            Some(update) = status_rx.recv() => on_status(update, ui, &mut touch_prompted).await,
            result = &mut result_rx => return result,
        }
    }
}

async fn on_status(update: StatusUpdate, ui: &dyn SecurityKeyUi, touch_prompted: &mut bool) {
    match update {
        StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
            send_pin(&sender, ui, &PinRequest::new(false, None)).await;
        }
        StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts)) => {
            send_pin(&sender, ui, &PinRequest::new(true, attempts)).await;
        }
        StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked) => {
            ui.notify(KeyEvent::PinAuthBlocked).await;
        }
        StatusUpdate::PinUvError(StatusPinUv::PinBlocked) => {
            ui.notify(KeyEvent::PinBlocked).await;
        }
        StatusUpdate::PresenceRequired => {
            if !*touch_prompted {
                ui.notify(KeyEvent::TouchRequired).await;
                *touch_prompted = true;
            }
        }
        StatusUpdate::SelectDeviceNotice => ui.notify(KeyEvent::SelectDevice).await,
        _ => {}
    }
}

/// Asks the user through the UI for the security key's PIN.
async fn send_pin(sender: &Sender<Pin>, ui: &dyn SecurityKeyUi, request: &PinRequest) {
    if let Ok(pin) = ui.request_pin(request).await {
        let _ = sender.send(Pin::new(pin.as_str()));
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
    use crate::{PinError, SecurityKeyPin};
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Never asked in the tests that use it.
    struct NoUi;

    #[async_trait(?Send)]
    impl SecurityKeyUi for NoUi {
        async fn request_pin(&self, _request: &PinRequest) -> Result<SecurityKeyPin, PinError> {
            unreachable!("no PIN is asked for")
        }

        async fn notify(&self, _event: KeyEvent) {}
    }

    /// Answers with a PIN, or cancels, and records what it was asked.
    struct RecordingUi {
        pin: Option<&'static str>,
        requests: Mutex<Vec<PinRequest>>,
        events: Mutex<Vec<KeyEvent>>,
    }

    impl RecordingUi {
        fn new(pin: Option<&'static str>) -> Self {
            Self {
                pin,
                requests: Mutex::new(vec![]),
                events: Mutex::new(vec![]),
            }
        }
    }

    #[async_trait(?Send)]
    impl SecurityKeyUi for RecordingUi {
        async fn request_pin(&self, request: &PinRequest) -> Result<SecurityKeyPin, PinError> {
            self.requests.lock().unwrap().push(request.clone());

            self.pin.map(SecurityKeyPin::new).ok_or(PinError::Cancelled)
        }

        async fn notify(&self, event: KeyEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[tokio::test]
    async fn a_pin_request_is_answered_with_the_pin() {
        let ui = RecordingUi::new(Some("1234"));
        let (sender, receiver) = channel();

        on_status(
            StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)),
            &ui,
            &mut false,
        )
        .await;

        assert!(receiver.try_recv().is_ok());
        assert_eq!(
            *ui.requests.lock().unwrap(),
            vec![PinRequest::new(false, None)]
        );
    }

    #[tokio::test]
    async fn a_wrong_pin_asks_again_with_the_attempts_left() {
        let ui = RecordingUi::new(Some("1234"));
        let (sender, receiver) = channel();

        on_status(
            StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, Some(2))),
            &ui,
            &mut false,
        )
        .await;

        assert!(receiver.try_recv().is_ok());
        assert_eq!(
            *ui.requests.lock().unwrap(),
            vec![PinRequest::new(true, Some(2))]
        );
    }

    #[tokio::test]
    async fn a_cancelled_pin_request_sends_nothing() {
        let ui = RecordingUi::new(None);
        let (sender, receiver) = channel();

        on_status(
            StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)),
            &ui,
            &mut false,
        )
        .await;

        // The sender is gone without having sent a PIN.
        assert!(receiver.recv().is_err());
    }

    #[tokio::test]
    async fn blocked_keys_and_device_selection_are_passed_on() {
        let ui = RecordingUi::new(None);
        let mut touched = false;

        on_status(
            StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked),
            &ui,
            &mut touched,
        )
        .await;
        on_status(
            StatusUpdate::PinUvError(StatusPinUv::PinBlocked),
            &ui,
            &mut touched,
        )
        .await;
        on_status(StatusUpdate::SelectDeviceNotice, &ui, &mut touched).await;

        assert_eq!(
            *ui.events.lock().unwrap(),
            vec![
                KeyEvent::PinAuthBlocked,
                KeyEvent::PinBlocked,
                KeyEvent::SelectDevice
            ]
        );
    }

    #[tokio::test]
    async fn the_touch_is_asked_for_once() {
        let ui = RecordingUi::new(None);
        let mut touched = false;

        on_status(StatusUpdate::PresenceRequired, &ui, &mut touched).await;
        on_status(StatusUpdate::PresenceRequired, &ui, &mut touched).await;

        assert_eq!(*ui.events.lock().unwrap(), vec![KeyEvent::TouchRequired]);
    }

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

    #[tokio::test]
    async fn sign_assertion_needs_usable_credential_ids() {
        // Fails before any device is touched.
        let err = sign_assertion(
            "challenge".to_string(),
            "id.example.com".to_string(),
            "https://id.example.com".to_string(),
            vec!["***".to_string()],
            vec![],
            Arc::new(NoUi),
        )
        .await
        .err()
        .unwrap();

        assert_eq!(
            err.to_string(),
            "the challenge has no usable credential ids"
        );
    }

    #[tokio::test]
    async fn sign_assertion_rejects_an_invalid_origin() {
        let err = sign_assertion(
            "challenge".to_string(),
            "id.example.com".to_string(),
            "not a url".to_string(),
            vec!["AQID".to_string()],
            vec![],
            Arc::new(NoUi),
        )
        .await;

        assert!(err.is_err());
    }

    #[tokio::test]
    async fn enroll_hmac_secret_rejects_an_invalid_origin() {
        let err = enroll_hmac_secret("not a valid url :// invalid", Arc::new(NoUi)).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn derive_hmac_secret_rejects_an_invalid_origin() {
        let err = derive_hmac_secret(
            "not a valid url :// invalid",
            b"cred",
            &[0u8; 32],
            Arc::new(NoUi),
        )
        .await;
        assert!(err.is_err());
    }
}
