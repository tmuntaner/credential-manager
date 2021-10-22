use crate::SignatureResponse;
use anyhow::{anyhow, Result};
use authenticator::{
    authenticatorservice::AuthenticatorService, statecallback::StateCallback,
    AuthenticatorTransports, KeyHandle, SignFlags, StatusUpdate,
};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::sync::mpsc::channel;

pub fn sign(
    challenge_str: String,
    host: String,
    credential_ids: Vec<String>,
) -> Result<SignatureResponse> {
    let mut manager = AuthenticatorService::new()?;
    manager.add_u2f_usb_hid_platform_transports();

    let origin: String = format!("https://{}", host);

    let (client_data_json, chall_bytes, app_bytes) =
        generate_input_hashes(origin, challenge_str, host)?;

    let key_handles: Vec<KeyHandle> = credential_ids
        .iter()
        .map(|credential_id| {
            let credential_id =
                base64::decode_config(credential_id, base64::URL_SAFE_NO_PAD).unwrap_or_default();
            if credential_id.is_empty() {
                None
            } else {
                Some(KeyHandle {
                    credential: credential_id,
                    transports: AuthenticatorTransports::empty(),
                })
            }
        })
        .flatten()
        .collect();

    let (status_tx, _status_rx) = channel::<StatusUpdate>();
    let (sign_tx, sign_rx) = channel();

    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(120);
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&[
                "▹▹▹▹▹",
                "▸▹▹▹▹",
                "▹▸▹▹▹",
                "▹▹▸▹▹",
                "▹▹▹▸▹",
                "▹▹▹▹▸",
                "▪▪▪▪▪",
            ])
            .template("{spinner:.blue} {msg}"),
    );
    pb.set_message("Please insert and activate your U2F device...");

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
        .map_err(|_| anyhow!("Problem receiving, unable to continue"))?
        .map_err(|_| anyhow!("There was an issue authenticating your U2F device. Please ensure that it's set up on your account, plugged in, and that you activate it."))?;
    let (_app_id, _used_handle, sign_data, _device_info) = sign_result;
    pb.finish_with_message("Processing sign request...");

    let sign_data = sign_data.as_slice();
    let user_present = sign_data[0];
    let counter = u32::from_be_bytes([sign_data[1], sign_data[2], sign_data[3], sign_data[4]]);
    let signature = sign_data[5..].to_vec();
    let mut authenticator_data = vec![];
    authenticator_data.extend(app_bytes);
    authenticator_data.push(user_present);
    authenticator_data.extend(counter.to_be_bytes());

    Ok(SignatureResponse {
        client_data: base64::encode_config(client_data_json.as_bytes(), base64::STANDARD),
        signature_data: base64::encode_config(signature, base64::STANDARD),
        authenticator_data: base64::encode_config(authenticator_data, base64::STANDARD),
    })
}

fn generate_input_hashes(
    origin: String,
    challenge_str: String,
    rp_id: String,
) -> Result<(String, Vec<u8>, Vec<u8>)> {
    let client_data_json = crate::utils::client_data(origin, challenge_str)?;

    let mut challenge = Sha256::default();
    challenge.update(client_data_json.as_bytes());
    let chall_bytes = challenge.finalize().to_vec();

    let mut application = Sha256::default();
    application.update(rp_id.as_bytes());
    let app_bytes = application.finalize().to_vec();

    Ok((client_data_json, chall_bytes, app_bytes))
}
