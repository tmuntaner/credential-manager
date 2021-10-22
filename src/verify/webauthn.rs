use anyhow::Result;
use webauthn::SignatureResponse;

pub fn webauthn_sign(
    challenge_str: String,
    host: String,
    credential_ids: Vec<String>,
) -> Result<SignatureResponse> {
    let signature = webauthn::sign(challenge_str, host, credential_ids)?;

    Ok(signature)
}
