use crate::WebauthnError;
use serde::Serialize;
use url::Url;

/// The client data of an assertion for authentik, serialized like a browser does.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AssertionClientData<'a> {
    #[serde(rename = "type")]
    sign_type: &'a str,
    challenge: &'a str,
    origin: String,
    cross_origin: bool,
}

/// The `clientDataJSON` of a WebAuthn assertion, as a browser builds it: no `tokenBinding`, and
/// `crossOrigin: false`.
pub fn assertion_client_data(origin: &str, challenge_str: &str) -> Result<String, WebauthnError> {
    let caller_origin = Url::parse(origin)?;

    let client_data = AssertionClientData {
        sign_type: "webauthn.get",
        challenge: challenge_str,
        origin: caller_origin.origin().unicode_serialization(),
        cross_origin: false,
    };

    Ok(serde_json::to_string(&client_data)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_client_data_matches_what_a_browser_sends() {
        let json = assertion_client_data("https://id.example.com", "abc_DEF-123").unwrap();

        assert_eq!(
            json,
            r#"{"type":"webauthn.get","challenge":"abc_DEF-123","origin":"https://id.example.com","crossOrigin":false}"#
        );
        assert!(!json.contains("tokenBinding"));
    }

    #[test]
    fn assertion_client_data_normalizes_the_origin() {
        let json = assertion_client_data("https://id.example.com:443/some/path", "c").unwrap();

        assert!(
            json.contains(r#""origin":"https://id.example.com""#),
            "{}",
            json
        );
    }

    #[test]
    fn assertion_client_data_rejects_an_invalid_origin() {
        assert!(assertion_client_data("not a url", "c").is_err());
    }
}
