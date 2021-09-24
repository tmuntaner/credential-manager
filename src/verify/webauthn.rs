use authenticator::{
    authenticatorservice::AuthenticatorService, statecallback::StateCallback,
    AuthenticatorTransports, KeyHandle, SignFlags, StatusUpdate,
};

use nom::call;
use nom::do_parse;
use nom::named;
use nom::u32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::mpsc::{channel, RecvError};
use std::{str, thread};
use url::Url;

named!( authenticator_data_parser<&[u8], (u8, u32, Vec<u8>)>,
    do_parse!(
        user_present: call!(nom::number::complete::be_u8) >>
        sign_count: u32!(nom::number::Endianness::Big) >>
        signature: call!(nom::combinator::rest) >>
        (
            (user_present, sign_count, signature.to_vec())
        )
    )
);

/// <https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-tokenbinding>
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenBinding {
    pub status: String,
    pub id: Option<String>,
}

/// <https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata>
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectedClientData {
    #[serde(rename = "type")]
    pub sign_type: String,

    pub challenge: String,

    pub origin: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_origin: Option<bool>,

    pub token_binding: Option<TokenBinding>,
}

pub struct SignatureResponse {
    pub client_data: String,
    pub signature_data: String,
    pub authenticator_data: String,
}

pub fn webauthn_sign(
    challenge_str: String,
    host: String,
    credential_ids: Vec<String>,
) -> SignatureResponse {
    let mut manager =
        AuthenticatorService::new().expect("The auth service should initialize safely");
    manager.add_u2f_usb_hid_platform_transports();

    let origin: String = format!("https://{}", host);

    let (client_data_json, chall_bytes, app_bytes) =
        generate_input_hashes(origin, challenge_str, host);

    let key_handles: Vec<KeyHandle> = credential_ids
        .iter()
        .map(|credential_id| {
            let credential_id =
                base64::decode_config(credential_id, base64::URL_SAFE_NO_PAD).unwrap();
            KeyHandle {
                credential: credential_id,
                transports: AuthenticatorTransports::empty(),
            }
        })
        .collect();

    let (status_tx, status_rx) = channel::<StatusUpdate>();
    let (sign_tx, sign_rx) = channel();

    thread::spawn(move || loop {
        match status_rx.recv() {
            Ok(StatusUpdate::DeviceAvailable { dev_info }) => {
                println!("STATUS: device available: {}", dev_info)
            }
            Ok(StatusUpdate::DeviceUnavailable { dev_info }) => {
                println!("STATUS: device unavailable: {}", dev_info)
            }
            Ok(StatusUpdate::Success { dev_info }) => {
                println!("STATUS: success using device: {}", dev_info);
            }
            Err(RecvError) => {
                println!("STATUS: end");
                return;
            }
        }
    });

    let callback = StateCallback::new(Box::new(move |rv| {
        sign_tx.send(rv).unwrap();
    }));

    let sign_flags = SignFlags::empty();
    if let Err(e) = manager.sign(
        sign_flags,
        15_000,
        chall_bytes,
        vec![app_bytes.clone()],
        key_handles,
        status_tx,
        callback,
    ) {
        panic!("Couldn't register: {:?}", e);
    }

    let sign_result = sign_rx
        .recv()
        .expect("Problem receiving, unable to continue");
    let (_app_id, _used_handle, sign_data, _device_info) = sign_result.expect("Sign failed");

    let (_, (user_present, counter, signature)) =
        authenticator_data_parser(sign_data.as_slice()).unwrap();

    let mut authenticator_data = vec![];
    authenticator_data.extend(app_bytes);
    authenticator_data.push(user_present);
    authenticator_data.extend(counter.to_be_bytes());

    SignatureResponse {
        client_data: base64::encode_config(client_data_json.as_bytes(), base64::STANDARD),
        signature_data: base64::encode_config(signature, base64::STANDARD),
        authenticator_data: base64::encode_config(authenticator_data, base64::STANDARD),
    }
}

fn generate_input_hashes(
    origin: String,
    challenge_str: String,
    rp_id: String,
) -> (String, Vec<u8>, Vec<u8>) {
    let caller_origin = Url::parse(origin.as_str()).unwrap();

    let collected_client_data = CollectedClientData {
        sign_type: "webauthn.get".to_string(),
        challenge: challenge_str,
        origin: caller_origin.origin().unicode_serialization(),
        token_binding: None,
        cross_origin: None,
    };

    let client_data_json = serde_json::to_string(&collected_client_data).unwrap();
    let mut challenge = Sha256::default();
    challenge.input(client_data_json.as_bytes());
    let chall_bytes = challenge.result().to_vec();

    let mut application = Sha256::default();
    application.input(rp_id.as_bytes());
    let app_bytes = application.result().to_vec();

    (client_data_json, chall_bytes, app_bytes)
}
