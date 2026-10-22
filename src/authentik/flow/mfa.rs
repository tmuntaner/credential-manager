use crate::authentik::flow::challenge::{DeviceChallenge, ValidateChallenge};
use crate::authentik::mfa::MfaSelection;
use async_trait::async_trait;
use base64::{alphabet, engine, Engine};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use thiserror::Error;
use webauthn::{WebauthnAssertion, WebauthnClient, WebauthnError};

/// How many attempts the MFA has before giving up.
const MAX_ATTEMPTS: usize = 3;

#[derive(Debug, Error)]
pub enum MfaError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Webauthn(#[from] WebauthnError),

    #[error("MFA rejected")]
    Rejected,

    #[error("MFA rejected {MAX_ATTEMPTS} times: {0}")]
    TooManyRejections(String),

    #[error("MFA required but not implemented")]
    NotImplemented,

    #[error("failed to parse your selection")]
    UnparsableSelection,

    #[error("you've selected an invalid Factor Type")]
    InvalidFactorType,

    #[error("this IdP requires PIN user verification (CTAP2), not supported yet; use TOTP")]
    PinRequired,

    #[error("the WebAuthn challenge is for {rp_id}, not for the IdP host {idp_host}")]
    WrongRelyingParty { rp_id: String, idp_host: String },

    #[error("the WebAuthn challenge has no challenge")]
    NoWebauthnChallenge,

    #[error("the WebAuthn challenge has no allowed credentials")]
    NoAllowedCredentials,

    #[error("TOTP was selected but is not offered (offered: {0})")]
    TotpNotOffered(String),

    #[error("WebAuthn was selected but is not offered (offered: {0})")]
    WebauthnNotOffered(String),

    #[error("the selected MFA method is not supported by authentik")]
    UnsupportedSelection,

    #[error("no supported MFA method (offered: {0})")]
    NoSupportedMethod(String),
}

/// Answers the `ak-stage-authenticator-validate` stage of a flow.
#[async_trait]
pub trait MfaHandler: Send + Sync {
    /// Given the validate-stage challenge, returns the JSON body to POST (it must include
    /// `"component": "ak-stage-authenticator-validate"`). `idp_host` is e.g. `id.suse.com`.
    async fn respond(
        &self,
        challenge: &ValidateChallenge,
        idp_host: &str,
    ) -> Result<Value, MfaError>;

    /// Called when the server rejected the previous response, with the formatted `response_errors`.
    /// Return `Ok(())` to allow another `respond`, `Err` to give up.
    fn rejected(&self, _reason: &str) -> Result<(), MfaError> {
        Err(MfaError::Rejected)
    }
}

/// A handler for flows that must not need MFA.
pub struct NoMfaHandler;

#[async_trait]
impl MfaHandler for NoMfaHandler {
    async fn respond(
        &self,
        _challenge: &ValidateChallenge,
        _idp_host: &str,
    ) -> Result<Value, MfaError> {
        Err(MfaError::NotImplemented)
    }
}

/// Asks the user things. Separate from [`InteractiveMfa`] so the logic can be tested without stdin.
pub trait Prompter: Send + Sync {
    fn totp_code(&self) -> Result<String, MfaError>;
    /// Asks the user to pick one of `methods` and returns its index.
    fn choose_method(&self, methods: &[&str]) -> Result<usize, MfaError>;
}

/// Prompts on stderr and reads the answer from stdin.
pub struct StdioPrompter;

impl StdioPrompter {
    fn read_line() -> Result<String, MfaError> {
        let _ = io::stderr().flush();
        let mut buffer = String::new();
        io::stdin().lock().read_line(&mut buffer)?;

        Ok(buffer.trim_end_matches(['\r', '\n']).to_string())
    }
}

impl Prompter for StdioPrompter {
    fn totp_code(&self) -> Result<String, MfaError> {
        eprint!("TOTP Code: ");
        StdioPrompter::read_line()
    }

    fn choose_method(&self, methods: &[&str]) -> Result<usize, MfaError> {
        eprintln!("Please select a MFA Factor Type:");
        for (i, method) in methods.iter().enumerate() {
            eprintln!("( {i} ) {method}");
        }
        eprint!("Factor Type? (0 - {}) ", methods.len() - 1);

        let selection: usize = StdioPrompter::read_line()?
            .parse()
            .map_err(|_| MfaError::UnparsableSelection)?;
        if selection >= methods.len() {
            return Err(MfaError::InvalidFactorType);
        }

        Ok(selection)
    }
}

/// Signs a WebAuthn challenge with a hardware key.
pub trait AssertionSigner: Send + Sync {
    /// `challenge` and `credential_ids` are base64url, as sent by the server.
    fn sign(
        &self,
        challenge: String,
        rp_id: String,
        origin: String,
        credential_ids: Vec<String>,
    ) -> Result<WebauthnAssertion, WebauthnError>;
}

/// Signs with a USB security key, showing a progress bar and optionally a desktop notification while it
/// waits for the touch.
pub struct HardwareSigner {
    enable_desktop_notifications: bool,
}

impl HardwareSigner {
    pub fn new(enable_desktop_notifications: bool) -> Self {
        HardwareSigner {
            enable_desktop_notifications,
        }
    }
}

impl AssertionSigner for HardwareSigner {
    fn sign(
        &self,
        challenge: String,
        rp_id: String,
        origin: String,
        credential_ids: Vec<String>,
    ) -> Result<WebauthnAssertion, WebauthnError> {
        let mut client = WebauthnClient::new();
        if self.enable_desktop_notifications {
            client.add_desktop_notification_notifier();
        }
        client.add_progress_bar_notifier();

        client.sign_assertion(challenge, rp_id, origin, credential_ids)
    }
}

enum Method<'a> {
    Totp(&'a DeviceChallenge),
    WebAuthn(&'a DeviceChallenge),
}

impl Method<'_> {
    fn name(&self) -> &'static str {
        match self {
            Method::Totp(_) => "TOTP",
            Method::WebAuthn(_) => "WebAuthn",
        }
    }
}

/// Answers the validate stage with a TOTP code or a hardware WebAuthn key, asking the user which when
/// both are offered.
pub struct InteractiveMfa {
    selection: Option<MfaSelection>,
    prompter: Box<dyn Prompter>,
    signer: Box<dyn AssertionSigner>,
    rejections: AtomicUsize,
}

impl InteractiveMfa {
    pub fn new(selection: Option<MfaSelection>, enable_desktop_notifications: bool) -> Self {
        InteractiveMfa::with_parts(
            selection,
            Box::new(StdioPrompter),
            Box::new(HardwareSigner::new(enable_desktop_notifications)),
        )
    }

    pub fn with_parts(
        selection: Option<MfaSelection>,
        prompter: Box<dyn Prompter>,
        signer: Box<dyn AssertionSigner>,
    ) -> Self {
        InteractiveMfa {
            selection,
            prompter,
            signer,
            rejections: AtomicUsize::new(0),
        }
    }

    fn respond_webauthn(
        &self,
        device: &DeviceChallenge,
        idp_host: &str,
    ) -> Result<Value, MfaError> {
        let options = &device.challenge;

        if options["userVerification"] == "required" {
            return Err(MfaError::PinRequired);
        }
        if let Some(rp_id) = options["rpId"].as_str() {
            if rp_id != idp_host {
                return Err(MfaError::WrongRelyingParty {
                    rp_id: rp_id.to_string(),
                    idp_host: idp_host.to_string(),
                });
            }
        }

        let challenge = options["challenge"]
            .as_str()
            .ok_or(MfaError::NoWebauthnChallenge)?;
        let credential_ids: Vec<String> = options["allowCredentials"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|credential| credential["id"].as_str().map(str::to_string))
            .collect();
        if credential_ids.is_empty() {
            return Err(MfaError::NoAllowedCredentials);
        }

        let assertion = self.signer.sign(
            challenge.to_string(),
            idp_host.to_string(),
            format!("https://{idp_host}"),
            credential_ids,
        )?;

        Ok(webauthn_body(&assertion))
    }

    /// Picks the method to use out of the ones the server offers and this client supports.
    fn choose_method<'a>(&self, challenge: &'a ValidateChallenge) -> Result<Method<'a>, MfaError> {
        let devices = &challenge.device_challenges;
        let totp = devices.iter().find(|d| d.device_class == "totp");
        let webauthn = devices.iter().find(|d| d.device_class == "webauthn");

        let mut available = vec![];
        if let Some(totp) = totp {
            available.push(Method::Totp(totp));
        }
        if let Some(webauthn) = webauthn {
            available.push(Method::WebAuthn(webauthn));
        }

        let offered = || {
            let mut classes: Vec<&str> = devices.iter().map(|d| d.device_class.as_str()).collect();
            classes.dedup();
            classes.join(", ")
        };

        match self.selection {
            Some(MfaSelection::Totp) => totp
                .map(Method::Totp)
                .ok_or_else(|| MfaError::TotpNotOffered(offered())),
            Some(MfaSelection::WebAuthn) => webauthn
                .map(Method::WebAuthn)
                .ok_or_else(|| MfaError::WebauthnNotOffered(offered())),
            Some(MfaSelection::Invalid) => Err(MfaError::UnsupportedSelection),
            None => match available.len() {
                0 => Err(MfaError::NoSupportedMethod(offered())),
                1 => Ok(available.remove(0)),
                _ => {
                    let names: Vec<&str> = available.iter().map(Method::name).collect();
                    let index = self.prompter.choose_method(&names)?;
                    if index >= available.len() {
                        return Err(MfaError::InvalidFactorType);
                    }
                    Ok(available.remove(index))
                }
            },
        }
    }
}

/// The validate-stage body for an assertion, as a browser sends it: base64url without padding and no
/// `selected_challenge`.
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

#[async_trait]
impl MfaHandler for InteractiveMfa {
    async fn respond(
        &self,
        challenge: &ValidateChallenge,
        idp_host: &str,
    ) -> Result<Value, MfaError> {
        match self.choose_method(challenge)? {
            Method::Totp(device) => {
                let code = self.prompter.totp_code()?;

                Ok(json!({
                    "component": "ak-stage-authenticator-validate",
                    "code": code.trim(),
                    "selected_challenge": device,
                }))
            }
            Method::WebAuthn(device) => self.respond_webauthn(device, idp_host),
        }
    }

    fn rejected(&self, reason: &str) -> Result<(), MfaError> {
        let rejections = self.rejections.fetch_add(1, Ordering::SeqCst) + 1;
        eprintln!("MFA was rejected: {reason}");

        if rejections >= MAX_ATTEMPTS {
            return Err(MfaError::TooManyRejections(reason.to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentik::flow::session::tests::AUTH_LOCATION;
    use crate::authentik::flow::session::tests::{
        challenge_response, mock_authentication, AUTH_EXEC, AUTOSUBMIT_STS, INIT, VALIDATE,
    };
    use crate::authentik::flow::session::FlowSession;
    use httpmock::Method::{GET, POST};
    use httpmock::MockServer;
    use std::sync::{Arc, Mutex};

    /// Answers prompts from a script and records what it was asked.
    #[derive(Default)]
    struct ScriptedPrompter {
        code: String,
        choice: usize,
        asked: Mutex<Vec<String>>,
    }

    impl Prompter for Arc<ScriptedPrompter> {
        fn totp_code(&self) -> Result<String, MfaError> {
            self.asked.lock().unwrap().push("totp".to_string());
            Ok(self.code.clone())
        }

        fn choose_method(&self, methods: &[&str]) -> Result<usize, MfaError> {
            self.asked.lock().unwrap().push(methods.join("|"));
            Ok(self.choice)
        }
    }

    /// `(challenge, rp_id, origin, credential_ids)`
    type SignCall = (String, String, String, Vec<String>);

    /// Records what it was asked to sign and returns a fixed assertion, or an error.
    #[derive(Default)]
    struct FakeSigner {
        fail: bool,
        calls: Mutex<Vec<SignCall>>,
    }

    impl AssertionSigner for Arc<FakeSigner> {
        fn sign(
            &self,
            challenge: String,
            rp_id: String,
            origin: String,
            credential_ids: Vec<String>,
        ) -> Result<WebauthnAssertion, WebauthnError> {
            self.calls
                .lock()
                .unwrap()
                .push((challenge, rp_id, origin, credential_ids));
            if self.fail {
                return Err(WebauthnError::ReceiveSignResult);
            }

            Ok(signed())
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

    fn signer() -> Arc<FakeSigner> {
        Arc::new(FakeSigner::default())
    }

    fn mfa(selection: Option<MfaSelection>, prompter: &Arc<ScriptedPrompter>) -> InteractiveMfa {
        mfa_with_signer(selection, prompter, &signer())
    }

    fn mfa_with_signer(
        selection: Option<MfaSelection>,
        prompter: &Arc<ScriptedPrompter>,
        signer: &Arc<FakeSigner>,
    ) -> InteractiveMfa {
        InteractiveMfa::with_parts(
            selection,
            Box::new(prompter.clone()),
            Box::new(signer.clone()),
        )
    }

    fn webauthn_options() -> Value {
        json!({
            "challenge": "c2VydmVyLWNoYWxsZW5nZQ",
            "timeout": 60000,
            "rpId": "id.example.com",
            "allowCredentials": [
                {"id": "AQID", "type": "public-key"},
                {"id": "-_8", "type": "public-key"},
            ],
            "userVerification": "preferred",
        })
    }

    fn prompter(code: &str, choice: usize) -> Arc<ScriptedPrompter> {
        Arc::new(ScriptedPrompter {
            code: code.to_string(),
            choice,
            ..Default::default()
        })
    }

    fn challenge(classes: &[&str]) -> ValidateChallenge {
        ValidateChallenge {
            device_challenges: classes
                .iter()
                .enumerate()
                .map(|(i, class)| DeviceChallenge {
                    device_class: class.to_string(),
                    device_uid: i.to_string(),
                    challenge: if *class == "webauthn" {
                        webauthn_options()
                    } else {
                        json!({})
                    },
                    last_used: None,
                })
                .collect(),
        }
    }

    async fn respond(mfa: &InteractiveMfa, classes: &[&str]) -> Result<Value, MfaError> {
        mfa.respond(&challenge(classes), "id.example.com").await
    }

    #[tokio::test]
    async fn totp_body_has_the_code_and_the_selected_device() {
        let prompter = prompter(" 123456\n", 0);
        let mfa = mfa(None, &prompter);

        let body = respond(&mfa, &["totp"]).await.unwrap();

        assert_eq!(
            body,
            json!({
                "component": "ak-stage-authenticator-validate",
                "code": "123456",
                "selected_challenge": {
                    "device_class": "totp", "device_uid": "0", "challenge": {}, "last_used": null
                },
            })
        );
        // Only one method: no question about which.
        assert_eq!(*prompter.asked.lock().unwrap(), vec!["totp"]);
    }

    #[tokio::test]
    async fn selection_decides_between_offered_methods() {
        let prompter = prompter("111111", 0);

        let body = respond(
            &mfa(Some(MfaSelection::Totp), &prompter),
            &["webauthn", "totp"],
        )
        .await
        .unwrap();
        assert_eq!(body["code"], "111111");

        let body = respond(
            &mfa(Some(MfaSelection::WebAuthn), &prompter),
            &["totp", "webauthn"],
        )
        .await
        .unwrap();
        assert!(body.get("webauthn").is_some());
        assert!(body.get("code").is_none());

        // An explicit selection never prompts for the method.
        assert_eq!(*prompter.asked.lock().unwrap(), vec!["totp"]);
    }

    #[tokio::test]
    async fn selection_that_is_not_offered_is_an_error() {
        let prompter = prompter("", 0);

        let err = respond(
            &mfa(Some(MfaSelection::Totp), &prompter),
            &["webauthn", "sms"],
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TOTP was selected but is not offered (offered: webauthn, sms)"
        );

        let err = respond(&mfa(Some(MfaSelection::WebAuthn), &prompter), &["totp"])
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "WebAuthn was selected but is not offered (offered: totp)"
        );
    }

    #[tokio::test]
    async fn an_invalid_selection_is_unsupported() {
        let prompter = prompter("", 0);

        let err = respond(&mfa(Some(MfaSelection::Invalid), &prompter), &["totp"])
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "the selected MFA method is not supported by authentik"
        );
    }

    #[tokio::test]
    async fn asks_which_method_when_several_are_offered() {
        let prompter = prompter("222222", 0);
        let body = respond(&mfa(None, &prompter), &["sms", "webauthn", "totp"])
            .await
            .unwrap();
        // The unsupported sms device is not offered; the options are in a stable order.
        assert_eq!(body["code"], "222222");
        assert_eq!(
            *prompter.asked.lock().unwrap(),
            vec!["TOTP|WebAuthn", "totp"]
        );

        let prompter = self::prompter("", 1);
        let body = respond(&mfa(None, &prompter), &["totp", "webauthn"])
            .await
            .unwrap();
        assert!(body.get("webauthn").is_some());

        let prompter = self::prompter("", 5);
        let err = respond(&mfa(None, &prompter), &["totp", "webauthn"])
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "you've selected an invalid Factor Type");
    }

    #[tokio::test]
    async fn only_unsupported_or_no_devices_is_an_error() {
        let prompter = prompter("", 0);

        let err = respond(&mfa(None, &prompter), &["sms", "sms", "email"])
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "no supported MFA method (offered: sms, email)"
        );

        let err = respond(&mfa(None, &prompter), &[]).await.unwrap_err();
        assert_eq!(err.to_string(), "no supported MFA method (offered: )");
    }

    #[test]
    fn gives_up_after_three_rejections() {
        let mfa = mfa(Some(MfaSelection::Totp), &prompter("", 0));

        assert!(mfa.rejected("code: Invalid Token").is_ok());
        assert!(mfa.rejected("code: Invalid Token").is_ok());
        let err = mfa.rejected("code: Invalid Token").unwrap_err();
        assert_eq!(err.to_string(), "MFA rejected 3 times: code: Invalid Token");
    }

    #[test]
    fn can_be_created_with_the_stdio_prompter() {
        let mfa = InteractiveMfa::new(Some(MfaSelection::Totp), true);
        assert!(mfa.rejected("nope").is_ok());
    }

    #[tokio::test]
    async fn logs_in_with_totp_through_the_flow() {
        let server = MockServer::start();
        mock_authentication(&server, VALIDATE);
        let totp = server.mock(|when, then| {
            when.method(POST).path(AUTH_EXEC).json_body_includes(
                json!({
                    "component": "ak-stage-authenticator-validate",
                    "code": "123456",
                    "selected_challenge": {"device_class": "totp", "device_uid": "1"},
                })
                .to_string(),
            );
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

        let session = FlowSession::new(Box::new(mfa(None, &prompter("123456", 0)))).unwrap();
        // The fixture offers TOTP and WebAuthn; choose TOTP (index 0).
        let assertion = session
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap();

        totp.assert();
        assert_eq!(assertion.destination, "https://signin.aws.amazon.com/saml");
    }

    #[tokio::test]
    async fn webauthn_body_is_base64url_without_padding_and_has_no_selected_challenge() {
        let signer = signer();
        let mfa = mfa_with_signer(Some(MfaSelection::WebAuthn), &prompter("", 0), &signer);

        let body = respond(&mfa, &["webauthn"]).await.unwrap();

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
    async fn webauthn_signs_for_the_idp_host_with_all_allowed_credentials() {
        let signer = signer();
        let mfa = mfa_with_signer(Some(MfaSelection::WebAuthn), &prompter("", 0), &signer);

        respond(&mfa, &["totp", "webauthn"]).await.unwrap();

        assert_eq!(
            *signer.calls.lock().unwrap(),
            vec![(
                "c2VydmVyLWNoYWxsZW5nZQ".to_string(),
                "id.example.com".to_string(),
                "https://id.example.com".to_string(),
                vec!["AQID".to_string(), "-_8".to_string()],
            )]
        );
    }

    async fn respond_with_options(options: Value) -> Result<Value, MfaError> {
        let challenge = ValidateChallenge {
            device_challenges: vec![DeviceChallenge {
                device_class: "webauthn".to_string(),
                device_uid: "1".to_string(),
                challenge: options,
                last_used: None,
            }],
        };
        let signer = signer();
        let mfa = mfa_with_signer(None, &prompter("", 0), &signer);
        let result = mfa.respond(&challenge, "id.example.com").await;
        if result.is_err() {
            // None of these must reach the hardware.
            assert!(signer.calls.lock().unwrap().is_empty());
        }

        result
    }

    #[tokio::test]
    async fn webauthn_that_requires_user_verification_is_refused() {
        let mut options = webauthn_options();
        options["userVerification"] = json!("required");

        let err = respond_with_options(options).await.unwrap_err();

        assert!(err.to_string().contains("requires PIN user verification"));
    }

    #[tokio::test]
    async fn webauthn_for_another_rp_id_is_refused() {
        let mut options = webauthn_options();
        options["rpId"] = json!("evil.example.net");

        let err = respond_with_options(options).await.unwrap_err();

        assert_eq!(
            err.to_string(),
            "the WebAuthn challenge is for evil.example.net, not for the IdP host id.example.com"
        );
    }

    #[tokio::test]
    async fn webauthn_without_a_rp_id_uses_the_idp_host() {
        let mut options = webauthn_options();
        options.as_object_mut().unwrap().remove("rpId");

        assert!(respond_with_options(options).await.is_ok());
    }

    #[tokio::test]
    async fn incomplete_webauthn_challenges_are_errors() {
        let mut options = webauthn_options();
        options.as_object_mut().unwrap().remove("challenge");
        let err = respond_with_options(options).await.unwrap_err();
        assert_eq!(err.to_string(), "the WebAuthn challenge has no challenge");

        for allow in [json!([]), json!([{"type": "public-key"}]), json!(null)] {
            let mut options = webauthn_options();
            options["allowCredentials"] = allow;
            let err = respond_with_options(options).await.unwrap_err();
            assert_eq!(
                err.to_string(),
                "the WebAuthn challenge has no allowed credentials"
            );
        }
    }

    #[tokio::test]
    async fn webauthn_signing_errors_are_passed_on() {
        let signer = Arc::new(FakeSigner {
            fail: true,
            ..Default::default()
        });
        let mfa = mfa_with_signer(Some(MfaSelection::WebAuthn), &prompter("", 0), &signer);

        let err = respond(&mfa, &["webauthn"]).await.unwrap_err();

        assert_eq!(err.to_string(), "Problem receiving, unable to continue");
    }

    #[test]
    fn the_hardware_signer_can_be_created() {
        let _ = HardwareSigner::new(true);
        let _ = InteractiveMfa::new(Some(MfaSelection::WebAuthn), false);
    }

    #[tokio::test]
    async fn logs_in_with_webauthn_through_the_flow() {
        let server = MockServer::start();
        let validate = json!({
            "component": "ak-stage-authenticator-validate",
            "device_challenges": [{
                "device_class": "webauthn",
                "device_uid": "1",
                "challenge": {
                    "challenge": "c2VydmVyLWNoYWxsZW5nZQ",
                    "rpId": "127.0.0.1",
                    "allowCredentials": [{"id": "AQID", "type": "public-key"}],
                    "userVerification": "preferred",
                },
                "last_used": null,
            }],
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

        let signer = signer();
        let session =
            FlowSession::new(Box::new(mfa_with_signer(None, &prompter("", 0), &signer))).unwrap();
        let assertion = session
            .login(&server.url(INIT), "user", "secret")
            .await
            .unwrap();

        webauthn_post.assert();
        followed.assert();
        assert_eq!(assertion.destination, "https://signin.aws.amazon.com/saml");
        let calls = signer.calls.lock().unwrap();
        assert_eq!(calls[0].1, "127.0.0.1");
        assert!(calls[0].2.starts_with("https://127.0.0.1"));
    }
}
