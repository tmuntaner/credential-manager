use crate::SignatureResponse;
use anyhow::Result;
use webauthn_sys::Windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use webauthn_sys::Windows::Win32::{Foundation::*, Networking::WindowsWebServices::*};
use widestring::U16CString;

pub fn sign(
    challenge_str: String,
    host: String,
    credential_ids: Vec<String>,
) -> Result<SignatureResponse> {
    let origin: String = format!("https://{}", host);
    let rp_id = U16CString::from_str(host)?;
    let rp_id = PWSTR(rp_id.as_ptr() as *mut u16);
    let client_data = crate::utils::client_data(origin, challenge_str)?;

    let hwnd = unsafe { GetForegroundWindow() };

    let credential_type = String::from("public-key");
    let credential_type = U16CString::from_str(credential_type)?;
    let credential_type = PWSTR(credential_type.as_ptr() as *mut u16);

    let mut webauthn_credentials: Vec<WEBAUTHN_CREDENTIAL> = credential_ids
        .into_iter()
        .map(|credential_id| {
            base64::decode_config(credential_id, base64::URL_SAFE_NO_PAD).unwrap_or_default()
        })
        .map(|mut decoded_credential| {
            WEBAUTHN_CREDENTIAL {
                dwVersion: 1u32, // WEBAUTHN_CREDENTIAL_CURRENT_VERSION
                cbId: decoded_credential.len() as u32,
                pbId: decoded_credential.as_mut_ptr(),
                pwszCredentialType: credential_type,
            }
        })
        .collect();

    let webauthn_credentials = WEBAUTHN_CREDENTIALS {
        cCredentials: webauthn_credentials.len() as u32,
        pCredentials: webauthn_credentials.as_mut_ptr(),
    };

    let hash_algorithm = String::from("SHA-256");
    let hash_algorithm = U16CString::from_str(hash_algorithm)?;
    let hash_algorithm = PWSTR(hash_algorithm.as_ptr() as *mut u16);

    let client_data_bytes = client_data.as_bytes();
    let webuathn_client_data = Box::new(WEBAUTHN_CLIENT_DATA {
        dwVersion: 1u32,
        cbClientDataJSON: client_data_bytes.len() as u32,
        pbClientDataJSON: client_data_bytes.as_ptr() as *mut u8,
        pwszHashAlgId: hash_algorithm,
    });
    let webuathn_client_data = Box::into_raw(webuathn_client_data);

    let options = Box::new(WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: 5u32,
        dwTimeoutMilliseconds: 30 * 1000u32,
        CredentialList: webauthn_credentials,
        Extensions: WEBAUTHN_EXTENSIONS::default(),
        dwAuthenticatorAttachment: 0u32,
        dwUserVerificationRequirement: 0u32,
        dwFlags: 0u32,
        pwszU2fAppId: rp_id,
        pbU2fAppId: std::ptr::null_mut(),
        pCancellationId: std::ptr::null_mut(),
        pAllowCredentialList: std::ptr::null_mut(),
    });
    let options = Box::into_raw(options);

    let assertion_ptr =
        unsafe { WebAuthNAuthenticatorGetAssertion(hwnd, rp_id, webuathn_client_data, options) }?;
    let assertion: Box<WEBAUTHN_ASSERTION> = unsafe { Box::from_raw(assertion_ptr) };

    let signature = unsafe {
        std::slice::from_raw_parts_mut(assertion.pbSignature, assertion.cbSignature as usize)
    };
    let signature_data = base64::encode_config(signature.to_vec(), base64::STANDARD);

    let authenticator_data = unsafe {
        std::slice::from_raw_parts_mut(
            assertion.pbAuthenticatorData,
            assertion.cbAuthenticatorData as usize,
        )
    };
    let authenticator_data = base64::encode_config(authenticator_data.to_vec(), base64::STANDARD);

    unsafe { drop(Box::from_raw(options)) }
    unsafe { drop(Box::from_raw(webuathn_client_data)) }

    Ok(SignatureResponse {
        client_data: base64::encode_config(client_data.as_bytes(), base64::STANDARD),
        authenticator_data,
        signature_data,
    })
}
