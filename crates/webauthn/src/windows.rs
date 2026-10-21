/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use crate::SignatureResponse;
use anyhow::Result;
use base64::{alphabet, engine, Engine};
use widestring::U16CString;
use windows::core::PCWSTR;
use windows::Win32::Foundation::BOOL;
use windows::Win32::Networking::WindowsWebServices::*;
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

pub fn sign(
    challenge_str: String,
    host: String,
    credential_ids: Vec<String>,
) -> Result<SignatureResponse> {
    let origin: String = format!("https://{}", host);
    let rp_id = U16CString::from_str(host)?;
    let rp_id = PCWSTR(rp_id.as_ptr() as *mut u16);
    let mut app_id_used: BOOL = false.into();
    let client_data = crate::utils::client_data(origin, challenge_str)?;

    let hwnd = unsafe { GetForegroundWindow() };

    let base64urlsafe =
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::NO_PAD);
    let base64standard =
        engine::GeneralPurpose::new(&alphabet::STANDARD, engine::general_purpose::PAD);

    let ids: Vec<Vec<u8>> = credential_ids
        .into_iter()
        .map(|credential_id| base64urlsafe.decode(credential_id).unwrap_or_default())
        .collect();

    let len = ids.len();
    let mut credentials: Vec<WEBAUTHN_CREDENTIAL> = Vec::with_capacity(len);

    for id in ids.iter() {
        credentials.push(WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: id.len() as u32,
            pbId: id.as_ptr() as *mut u8,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        });
    }

    let credentials_list = WEBAUTHN_CREDENTIALS {
        cCredentials: len as u32,
        pCredentials: credentials.as_mut_ptr(),
    };

    let client_data_bytes = client_data.as_bytes();
    let webuathn_client_data = Box::new(WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: client_data_bytes.len() as u32,
        pbClientDataJSON: client_data_bytes.as_ptr() as *mut u8,
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    });
    let webuathn_client_data = Box::into_raw(webuathn_client_data);

    let options = Box::new(WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
        dwTimeoutMilliseconds: 30 * 1000u32,
        CredentialList: credentials_list,
        Extensions: WEBAUTHN_EXTENSIONS::default(),
        dwAuthenticatorAttachment: 0u32,
        dwUserVerificationRequirement: 0u32,
        dwFlags: 0u32,
        pwszU2fAppId: PCWSTR::null(),
        pbU2fAppId: std::ptr::addr_of_mut!(app_id_used),
        pCancellationId: std::ptr::null_mut(),
        pAllowCredentialList: std::ptr::null_mut(),
        dwCredLargeBlobOperation: 0,
        cbCredLargeBlob: 0,
        pbCredLargeBlob: std::ptr::null_mut(),
    });
    let options = Box::into_raw(options);

    let assertion_ptr = unsafe {
        WebAuthNAuthenticatorGetAssertion(hwnd, rp_id, webuathn_client_data, Some(options))
    }?;
    let assertion: Box<WEBAUTHN_ASSERTION> = unsafe { Box::from_raw(assertion_ptr) };

    let signature = unsafe {
        std::slice::from_raw_parts_mut(assertion.pbSignature, assertion.cbSignature as usize)
    };
    let signature_data = base64standard.encode(signature);

    let authenticator_data = unsafe {
        std::slice::from_raw_parts_mut(
            assertion.pbAuthenticatorData,
            assertion.cbAuthenticatorData as usize,
        )
    };
    let authenticator_data = base64standard.encode(authenticator_data);

    unsafe { drop(Box::from_raw(options)) }
    unsafe { drop(Box::from_raw(webuathn_client_data)) }

    Ok(SignatureResponse {
        client_data: base64standard.encode(client_data.as_bytes()),
        authenticator_data,
        signature_data,
    })
}
