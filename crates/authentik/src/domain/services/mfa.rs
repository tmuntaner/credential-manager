use crate::domain::models::mfa::{
    MfaChallenge, MfaDevice, MfaMethod, MfaResponse, WebauthnOptions, WebauthnRequest,
};
use crate::domain::models::secret::TotpCode;
use crate::domain::ports::authenticator::Authenticator;
use crate::domain::ports::flow::{MfaError, SecondFactor};
use crate::domain::services::login::MAX_MFA_ATTEMPTS;
use async_trait::async_trait;
use std::cell::Cell;

/// Answers an MFA challenge interactively with the user.
pub(crate) struct InteractiveMfa<'a, A> {
    selection: Option<MfaMethod>,
    authenticator: &'a A,
    rejections: Cell<usize>,
}

impl<'a, A: Authenticator> InteractiveMfa<'a, A> {
    pub(crate) fn new(selection: Option<MfaMethod>, authenticator: &'a A) -> Self {
        Self {
            selection,
            authenticator,
            rejections: Cell::new(0),
        }
    }

    /// Picks the device to answer with, out of the ones authentik offers and this crate supports.
    async fn choose<'c>(&self, challenge: &'c MfaChallenge) -> Result<Choice<'c>, MfaError> {
        let devices = &challenge.devices;

        // find totp from the devices
        let totp = devices
            .iter()
            .position(|d| matches!(d, MfaDevice::Totp))
            .map(Choice::Totp);

        // find webauthn from the devices
        let webauthn = devices.iter().find_map(|d| match d {
            MfaDevice::WebAuthn(options) => Some(Choice::WebAuthn(options)),
            _ => None,
        });

        // the list of offered methods
        let offered = || {
            let mut classes: Vec<&str> = devices.iter().map(MfaDevice::class).collect();
            classes.dedup();
            classes.join(", ")
        };

        match self.selection {
            Some(MfaMethod::Totp) => totp.ok_or_else(|| MfaError::TotpNotOffered(offered())),
            Some(MfaMethod::WebAuthn) => {
                webauthn.ok_or_else(|| MfaError::WebauthnNotOffered(offered()))
            }
            None => {
                let mut available: Vec<Choice> = totp.into_iter().chain(webauthn).collect();
                match available.len() {
                    0 => Err(MfaError::NoSupportedMethod(offered())), // there is no MFA option
                    1 => Ok(available.remove(0)), // give the first option if only one is available
                    _ => {
                        // give the user the choice of method
                        let methods: Vec<MfaMethod> =
                            available.iter().map(Choice::method).collect();
                        let method = self.authenticator.choose_method(&methods).await?;

                        available
                            .into_iter()
                            .find(|choice| choice.method() == method)
                            .ok_or(MfaError::InvalidFactorType)
                    }
                }
            }
        }
    }

    async fn sign(
        &self,
        options: &WebauthnOptions,
        idp_host: &str,
    ) -> Result<MfaResponse, MfaError> {
        if options.user_verification_required {
            return Err(MfaError::PinRequired);
        }

        if let Some(rp_id) = &options.rp_id {
            if rp_id != idp_host {
                return Err(MfaError::WrongRelyingParty {
                    rp_id: rp_id.clone(),
                    idp_host: idp_host.to_string(),
                });
            }
        }

        // get the challenge string
        let challenge = options
            .challenge
            .clone()
            .ok_or(MfaError::NoWebauthnChallenge)?;

        // get which credentials are allowed to sign it
        if options.credential_ids.is_empty() {
            return Err(MfaError::NoAllowedCredentials);
        }

        // sign the challenge
        let assertion = self
            .authenticator
            .sign(&WebauthnRequest {
                challenge,
                rp_id: idp_host.to_string(),
                origin: format!("https://{idp_host}"),
                credential_ids: options.credential_ids.clone(),
            })
            .await?;

        Ok(MfaResponse::WebAuthn(assertion))
    }
}

/// A device to answer with.
enum Choice<'c> {
    /// The index of the TOTP device.
    Totp(usize),
    WebAuthn(&'c WebauthnOptions),
}

impl Choice<'_> {
    fn method(&self) -> MfaMethod {
        match self {
            Choice::Totp(_) => MfaMethod::Totp,
            Choice::WebAuthn(_) => MfaMethod::WebAuthn,
        }
    }
}

#[async_trait(?Send)]
impl<A: Authenticator> SecondFactor for InteractiveMfa<'_, A> {
    async fn respond(
        &self,
        challenge: &MfaChallenge,
        idp_host: &str,
    ) -> Result<MfaResponse, MfaError> {
        match self.choose(challenge).await? {
            Choice::Totp(device) => Ok(MfaResponse::Totp {
                device,
                code: TotpCode::new(self.authenticator.totp_code().await?.as_str().trim()),
            }),
            Choice::WebAuthn(options) => self.sign(options, idp_host).await,
        }
    }

    async fn rejected(&self, reason: &str) -> Result<(), MfaError> {
        let rejections = self.rejections.get() + 1;
        self.rejections.set(rejections);
        if rejections >= MAX_MFA_ATTEMPTS {
            return Err(MfaError::TooManyRejections {
                attempts: rejections,
                reason: reason.to_string(),
            });
        }
        self.authenticator.mfa_rejected(reason).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::mfa::WebauthnAssertion;
    use crate::domain::ports::authenticator::{AuthenticatorError, MockAuthenticator};
    use mockall::predicate::eq;

    const HOST: &str = "id.example.com";

    fn options() -> WebauthnOptions {
        WebauthnOptions {
            challenge: Some("c2VydmVyLWNoYWxsZW5nZQ".to_string()),
            rp_id: Some(HOST.to_string()),
            credential_ids: vec!["AQID".to_string(), "-_8".to_string()],
            user_verification_required: false,
        }
    }

    fn challenge(classes: &[&str]) -> MfaChallenge {
        MfaChallenge {
            devices: classes
                .iter()
                .map(|class| match *class {
                    "totp" => MfaDevice::Totp,
                    "webauthn" => MfaDevice::WebAuthn(options()),
                    other => MfaDevice::Other(other.to_string()),
                })
                .collect(),
        }
    }

    fn assertion() -> WebauthnAssertion {
        WebauthnAssertion {
            credential_id: vec![0xfb, 0xff],
            client_data_json: b"{}".to_vec(),
            authenticator_data: vec![1, 2, 3],
            signature: vec![0xff],
        }
    }

    /// An authenticator that must not be asked anything; tests add what they expect.
    fn untouched() -> MockAuthenticator {
        MockAuthenticator::new()
    }

    /// Answers the TOTP prompt once with `code`, and nothing else.
    fn prompting_code(code: &'static str) -> MockAuthenticator {
        let mut authenticator = untouched();
        authenticator
            .expect_totp_code()
            .times(1)
            .returning(move || Ok(TotpCode::new(code)));
        authenticator.expect_choose_method().never();
        authenticator.expect_sign().never();
        authenticator
    }

    /// Signs once, and asks nothing.
    fn signing() -> MockAuthenticator {
        let mut authenticator = untouched();
        authenticator
            .expect_sign()
            .times(1)
            .returning(|_| Ok(assertion()));
        authenticator.expect_totp_code().never();
        authenticator.expect_choose_method().never();
        authenticator
    }

    #[tokio::test]
    async fn answers_the_only_totp_device_with_the_trimmed_code_without_asking_which() {
        let authenticator = prompting_code(" 123456\n");
        let mfa = InteractiveMfa::new(None, &authenticator);

        let response = mfa
            .respond(&challenge(&["sms", "totp"]), HOST)
            .await
            .unwrap();

        assert_eq!(
            response,
            MfaResponse::Totp {
                device: 1,
                code: TotpCode::new("123456")
            }
        );
    }

    #[tokio::test]
    async fn the_selection_decides_between_offered_methods_without_asking() {
        let authenticator = prompting_code("111111");
        let mfa = InteractiveMfa::new(Some(MfaMethod::Totp), &authenticator);
        let response = mfa
            .respond(&challenge(&["webauthn", "totp"]), HOST)
            .await
            .unwrap();
        assert!(matches!(response, MfaResponse::Totp { device: 1, .. }));

        let authenticator = signing();
        let mfa = InteractiveMfa::new(Some(MfaMethod::WebAuthn), &authenticator);
        let response = mfa
            .respond(&challenge(&["totp", "webauthn"]), HOST)
            .await
            .unwrap();
        assert_eq!(response, MfaResponse::WebAuthn(assertion()));
    }

    #[tokio::test]
    async fn a_selection_that_is_not_offered_is_an_error() {
        let authenticator = untouched();

        let mfa = InteractiveMfa::new(Some(MfaMethod::Totp), &authenticator);
        let err = mfa
            .respond(&challenge(&["webauthn", "sms"]), HOST)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TOTP was selected but is not offered (offered: webauthn, sms)"
        );

        let mfa = InteractiveMfa::new(Some(MfaMethod::WebAuthn), &authenticator);
        let err = mfa.respond(&challenge(&["totp"]), HOST).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "WebAuthn was selected but is not offered (offered: totp)"
        );
    }

    #[tokio::test]
    async fn asks_which_method_when_several_are_offered() {
        let mut authenticator = untouched();
        // The unsupported sms device is not offered; the options are in a stable order.
        authenticator
            .expect_choose_method()
            .withf(|methods| methods == [MfaMethod::Totp, MfaMethod::WebAuthn])
            .times(1)
            .returning(|_| Ok(MfaMethod::Totp));
        authenticator
            .expect_totp_code()
            .times(1)
            .returning(|| Ok(TotpCode::new("222222")));
        authenticator.expect_sign().never();
        let mfa = InteractiveMfa::new(None, &authenticator);

        let response = mfa
            .respond(&challenge(&["sms", "webauthn", "totp"]), HOST)
            .await
            .unwrap();

        assert_eq!(
            response,
            MfaResponse::Totp {
                device: 2,
                code: TotpCode::new("222222")
            }
        );
    }

    #[tokio::test]
    async fn a_failed_choice_is_passed_on() {
        let mut authenticator = untouched();
        authenticator
            .expect_choose_method()
            .returning(|_| Err(AuthenticatorError::Failed("no such option".into())));
        let mfa = InteractiveMfa::new(None, &authenticator);

        let err = mfa
            .respond(&challenge(&["totp", "webauthn"]), HOST)
            .await
            .unwrap_err();

        assert!(matches!(err, MfaError::Authenticator(_)));
        assert_eq!(err.to_string(), "no such option");
    }

    #[tokio::test]
    async fn only_unsupported_or_no_devices_is_an_error() {
        let authenticator = untouched();
        let mfa = InteractiveMfa::new(None, &authenticator);

        let err = mfa
            .respond(&challenge(&["sms", "sms", "email"]), HOST)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "no supported MFA method (offered: sms, email)"
        );

        let err = mfa.respond(&challenge(&[]), HOST).await.unwrap_err();
        assert_eq!(err.to_string(), "no supported MFA method (offered: )");
    }

    #[tokio::test]
    async fn tells_the_user_about_rejections_and_gives_up_after_three() {
        let mut authenticator = untouched();
        authenticator
            .expect_mfa_rejected()
            .with(eq("code: Invalid Token"))
            .times(MAX_MFA_ATTEMPTS - 1)
            .return_const(());
        let mfa = InteractiveMfa::new(Some(MfaMethod::Totp), &authenticator);

        assert!(mfa.rejected("code: Invalid Token").await.is_ok());
        assert!(mfa.rejected("code: Invalid Token").await.is_ok());
        let err = mfa.rejected("code: Invalid Token").await.unwrap_err();
        assert_eq!(err.to_string(), "MFA rejected 3 times: code: Invalid Token");
    }

    #[tokio::test]
    async fn signs_for_the_idp_host_with_all_allowed_credentials() {
        let mut authenticator = untouched();
        authenticator
            .expect_sign()
            .with(eq(WebauthnRequest {
                challenge: "c2VydmVyLWNoYWxsZW5nZQ".to_string(),
                rp_id: HOST.to_string(),
                origin: format!("https://{HOST}"),
                credential_ids: vec!["AQID".to_string(), "-_8".to_string()],
            }))
            .times(1)
            .returning(|_| Ok(assertion()));
        let mfa = InteractiveMfa::new(Some(MfaMethod::WebAuthn), &authenticator);

        mfa.respond(&challenge(&["totp", "webauthn"]), HOST)
            .await
            .unwrap();
    }

    async fn respond_with(
        options: WebauthnOptions,
        authenticator: &MockAuthenticator,
    ) -> Result<MfaResponse, MfaError> {
        let challenge = MfaChallenge {
            devices: vec![MfaDevice::WebAuthn(options)],
        };

        InteractiveMfa::new(None, authenticator)
            .respond(&challenge, HOST)
            .await
    }

    /// Fails the test if the key is asked to sign.
    fn never_signing() -> MockAuthenticator {
        let mut authenticator = untouched();
        authenticator.expect_sign().never();
        authenticator
    }

    #[tokio::test]
    async fn webauthn_that_requires_user_verification_is_refused() {
        let options = WebauthnOptions {
            user_verification_required: true,
            ..options()
        };

        let err = respond_with(options, &never_signing()).await.unwrap_err();

        assert!(matches!(err, MfaError::PinRequired));
    }

    #[tokio::test]
    async fn webauthn_for_another_rp_id_is_refused() {
        let options = WebauthnOptions {
            rp_id: Some("evil.example.net".to_string()),
            ..options()
        };

        let err = respond_with(options, &never_signing()).await.unwrap_err();

        assert_eq!(
            err.to_string(),
            "the WebAuthn challenge is for evil.example.net, not for the IdP host id.example.com"
        );
    }

    #[tokio::test]
    async fn webauthn_without_a_rp_id_uses_the_idp_host() {
        let options = WebauthnOptions {
            rp_id: None,
            ..options()
        };

        assert!(respond_with(options, &signing()).await.is_ok());
    }

    #[tokio::test]
    async fn incomplete_webauthn_challenges_are_errors() {
        let options_without_challenge = WebauthnOptions {
            challenge: None,
            ..options()
        };
        let err = respond_with(options_without_challenge, &never_signing())
            .await
            .unwrap_err();
        assert!(matches!(err, MfaError::NoWebauthnChallenge));

        let options_without_credentials = WebauthnOptions {
            credential_ids: vec![],
            ..options()
        };
        let err = respond_with(options_without_credentials, &never_signing())
            .await
            .unwrap_err();
        assert!(matches!(err, MfaError::NoAllowedCredentials));
    }

    #[tokio::test]
    async fn signing_errors_are_passed_on() {
        let mut authenticator = untouched();
        authenticator
            .expect_sign()
            .returning(|_| Err(AuthenticatorError::Failed("no key".into())));

        let err = respond_with(options(), &authenticator).await.unwrap_err();

        assert!(matches!(err, MfaError::Authenticator(_)));
        assert_eq!(err.to_string(), "no key");
    }
}
