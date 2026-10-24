use crate::domain::models::mfa::{
    MfaChallenge, MfaDevice, MfaResponse, WebauthnAssertion, WebauthnOptions,
};
use crate::outbound::flow::challenge::{DeviceChallenge, ValidateChallenge};
use crate::outbound::flow::session::ExecutorError;
use base64::{alphabet, engine, Engine};
use serde_json::{json, Value};

/// Gather a list of devices from the validate stage.
pub fn challenge(validate: &ValidateChallenge) -> MfaChallenge {
    MfaChallenge {
        devices: validate.device_challenges.iter().map(device).collect(),
    }
}

/// Parse a device from the device challenge.
fn device(device: &DeviceChallenge) -> MfaDevice {
    match device.device_class.as_str() {
        "totp" => MfaDevice::Totp,
        "webauthn" => {
            let options = &device.challenge;
            MfaDevice::WebAuthn(WebauthnOptions {
                challenge: options["challenge"].as_str().map(str::to_string),
                rp_id: options["rpId"].as_str().map(str::to_string),
                credential_ids: options["allowCredentials"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|credential| credential["id"].as_str().map(str::to_string))
                    .collect(),
                user_verification_required: options["userVerification"] == "required",
            })
        }
        other => MfaDevice::Other(other.to_string()),
    }
}

/// Generate the POST body for the validate stage.
pub fn body(validate: &ValidateChallenge, response: MfaResponse) -> Result<Value, ExecutorError> {
    match response {
        MfaResponse::Totp { device, code } => {
            let device = validate
                .device_challenges
                .get(device)
                .ok_or(ExecutorError::UnknownDevice(device))?;

            Ok(json!({
                "component": "ak-stage-authenticator-validate",
                "code": code.as_str(),
                "selected_challenge": device,
            }))
        }
        MfaResponse::WebAuthn(assertion) => Ok(webauthn_body(&assertion)),
    }
}

/// Generate the webauthn body for the assertion.
/// It should be base64url without padding.
fn webauthn_body(assertion: &WebauthnAssertion) -> Value {
    let base64url =
        engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::NO_PAD);
    let credential_id = base64url.encode(&assertion.credential_id);

    json!({
        "component": "ak-stage-authenticator-validate",
        "webauthn": {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "assertionClientExtensions": "{}",
            "response": {
                "clientDataJSON": base64url.encode(&assertion.client_data_json),
                "authenticatorData": base64url.encode(&assertion.authenticator_data),
                "signature": base64url.encode(&assertion.signature),
                "userHandle": null,
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::secret::TotpCode;
    use crate::outbound::flow::challenge::Challenge;
    use crate::outbound::flow::session::FlowSession;
    use crate::outbound::flow::test_support::{
        challenge_response, mock_authentication, url, FakeMfa, AUTH_EXEC, AUTH_LOCATION,
        AUTOSUBMIT_STS, INIT, VALIDATE,
    };
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;

    fn validate(devices: Value) -> ValidateChallenge {
        let value =
            json!({"component": "ak-stage-authenticator-validate", "device_challenges": devices});
        let Challenge::Validate(validate) = Challenge::parse(&value).unwrap() else {
            panic!("expected a validate challenge");
        };
        validate
    }

    fn webauthn_device(options: Value) -> Value {
        json!([{"device_class": "webauthn", "device_uid": "1", "challenge": options, "last_used": null}])
    }

    fn webauthn_options(device: Value) -> WebauthnOptions {
        match challenge(&validate(device)).devices.remove(0) {
            MfaDevice::WebAuthn(options) => options,
            other => panic!("expected a WebAuthn device, got {other:?}"),
        }
    }

    /// Bytes chosen so that base64url differs from standard base64 (`-_8` / `+/8=`).
    fn signed() -> WebauthnAssertion {
        WebauthnAssertion {
            credential_id: vec![0xfb, 0xff],
            client_data_json: b"{}".to_vec(),
            authenticator_data: vec![1, 2, 3],
            signature: vec![0xff],
        }
    }

    #[test]
    fn reads_the_devices_of_the_captured_validate_stage() {
        let Challenge::Validate(validate) =
            Challenge::parse(&serde_json::from_str(VALIDATE).unwrap()).unwrap()
        else {
            panic!("expected a validate challenge");
        };

        let challenge = challenge(&validate);

        assert_eq!(challenge.devices.len(), 2);
        assert_eq!(challenge.devices[0], MfaDevice::Totp);
        let MfaDevice::WebAuthn(options) = &challenge.devices[1] else {
            panic!("expected a WebAuthn device");
        };
        assert_eq!(options.credential_ids.len(), 6);
        assert!(!options.user_verification_required);
        assert!(options.challenge.is_some());
        assert!(options.rp_id.is_some());
    }

    #[test]
    fn reads_the_webauthn_options() {
        let options = webauthn_options(webauthn_device(json!({
            "challenge": "c2VydmVyLWNoYWxsZW5nZQ",
            "rpId": "id.example.com",
            "allowCredentials": [{"id": "AQID", "type": "public-key"}, {"type": "public-key"}],
            "userVerification": "required",
        })));

        assert_eq!(
            options,
            WebauthnOptions {
                challenge: Some("c2VydmVyLWNoYWxsZW5nZQ".to_string()),
                rp_id: Some("id.example.com".to_string()),
                credential_ids: vec!["AQID".to_string()],
                user_verification_required: true,
            }
        );
    }

    #[test]
    fn missing_webauthn_options_are_left_empty() {
        assert_eq!(
            webauthn_options(webauthn_device(json!({}))),
            WebauthnOptions::default()
        );
        assert_eq!(
            webauthn_options(webauthn_device(json!({"allowCredentials": null}))),
            WebauthnOptions::default()
        );
    }

    #[test]
    fn unsupported_devices_keep_their_class() {
        let challenge = challenge(&validate(
            json!([{"device_class": "sms", "device_uid": "1"}]),
        ));

        assert_eq!(challenge.devices, vec![MfaDevice::Other("sms".to_string())]);
    }

    #[test]
    fn totp_body_has_the_code_and_the_selected_device() {
        let validate = validate(json!([
            {"device_class": "sms", "device_uid": "0"},
            {"device_class": "totp", "device_uid": "1", "challenge": {}, "last_used": null},
        ]));
        let response = MfaResponse::Totp {
            device: 1,
            code: TotpCode::new("123456"),
        };

        assert_eq!(
            body(&validate, response).unwrap(),
            json!({
                "component": "ak-stage-authenticator-validate",
                "code": "123456",
                "selected_challenge": {
                    "device_class": "totp", "device_uid": "1", "challenge": {}, "last_used": null
                },
            })
        );
    }

    #[test]
    fn a_totp_answer_for_an_unknown_device_is_an_error() {
        let response = MfaResponse::Totp {
            device: 3,
            code: TotpCode::new("123456"),
        };

        let err = body(&validate(json!([])), response).unwrap_err();

        assert!(matches!(err, ExecutorError::UnknownDevice(3)));
    }

    #[test]
    fn webauthn_body_is_base64url_without_padding_and_has_no_selected_challenge() {
        let body = body(&validate(json!([])), MfaResponse::WebAuthn(signed())).unwrap();

        assert_eq!(
            body,
            json!({
                "component": "ak-stage-authenticator-validate",
                "webauthn": {
                    "id": "-_8",
                    "rawId": "-_8",
                    "type": "public-key",
                    "assertionClientExtensions": "{}",
                    "response": {
                        "clientDataJSON": "e30",
                        "authenticatorData": "AQID",
                        "signature": "_w",
                        "userHandle": null,
                    },
                },
            })
        );
    }

    #[tokio::test]
    async fn logs_in_with_webauthn_through_the_flow() {
        let server = MockServer::start();
        let validate = json!({
            "component": "ak-stage-authenticator-validate",
            "device_challenges": webauthn_device(json!({
                "challenge": "c2VydmVyLWNoYWxsZW5nZQ",
                "rpId": "127.0.0.1",
                "allowCredentials": [{"id": "AQID", "type": "public-key"}],
                "userVerification": "preferred",
            })),
        })
        .to_string();
        mock_authentication(&server, &validate);
        // Like the real server: the answer is a 302 back to the executor, which then redirects.
        let webauthn_post = server.mock(|when, then| {
            when.method(POST).path(AUTH_EXEC).json_body_includes(
                json!({
                    "component": "ak-stage-authenticator-validate",
                    "webauthn": {"id": "-_8", "type": "public-key"},
                })
                .to_string(),
            );
            then.status(302)
                .header("Location", AUTH_LOCATION)
                .header("Set-Cookie", "stage=mfa; Path=/");
        });
        let followed = server.mock(|when, then| {
            when.method(GET)
                .path(AUTH_EXEC)
                .header_includes("Cookie", "stage=mfa");
            then.status(200)
                .header("Content-Type", "application/json")
                .body(r#"{"component": "xak-flow-redirect", "to": "/done/"}"#);
        });
        server.mock(|when, then| {
            when.method(GET).path("/done/");
            then.status(302).header("Location", "/if/flow/authz/");
        });
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/v3/flows/executor/authz/")
                .query_param("query", "");
            challenge_response(then, AUTOSUBMIT_STS);
        });

        let mfa = FakeMfa::answering(MfaResponse::WebAuthn(signed()));
        let assertion = FlowSession::new(&mfa)
            .unwrap()
            .login_saml(&url(&server, INIT), "user", "secret")
            .await
            .unwrap();

        webauthn_post.assert();
        followed.assert();
        assert_eq!(assertion.destination, "https://signin.aws.amazon.com/saml");
        assert_eq!(mfa.asked.borrow()[0].1, "127.0.0.1");
    }
}
