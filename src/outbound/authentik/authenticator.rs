use crate::domain::models::user_interaction::{ChoicePrompt, SecretPrompt, UserNotice};
use crate::domain::ports::notifier::Notifier;
use crate::domain::ports::user_interaction::{InteractionError, UserInteraction};
use crate::domain::ports::webauthn::WebauthnClientPort;
use async_trait::async_trait;
use authentik::{
    Authenticator, AuthenticatorError, MfaMethod, TotpCode, WebauthnAssertion, WebauthnRequest,
};
use std::rc::Rc;
use std::sync::Arc;
use thiserror::Error;

const TITLE: &str = "c9s: multi-factor authentication";

#[derive(Debug, Error)]
enum MfaPromptError {
    #[error("the chosen verification method is not one of the available ones")]
    InvalidFactorType,
}

impl From<MfaPromptError> for AuthenticatorError {
    fn from(e: MfaPromptError) -> Self {
        AuthenticatorError::Failed(Box::new(e))
    }
}

impl From<InteractionError> for AuthenticatorError {
    fn from(e: InteractionError) -> Self {
        AuthenticatorError::Failed(Box::new(e))
    }
}

/// Works with the user to interactively handle MFA.
pub struct InteractiveAuthenticator<W, U, N>
where
    W: WebauthnClientPort,
    U: UserInteraction,
    N: Notifier,
{
    webauthn_client: Rc<W>,
    interaction: Arc<U>,
    notifier: Arc<N>,
}

impl<W, U, N> InteractiveAuthenticator<W, U, N>
where
    W: WebauthnClientPort,
    U: UserInteraction,
    N: Notifier,
{
    pub fn new(webauthn_client: Rc<W>, interaction: Arc<U>, notifier: Arc<N>) -> Self {
        InteractiveAuthenticator {
            webauthn_client,
            interaction,
            notifier,
        }
    }
}

#[async_trait(?Send)]
impl<W, U, N> Authenticator for InteractiveAuthenticator<W, U, N>
where
    W: WebauthnClientPort,
    U: UserInteraction,
    N: Notifier,
{
    async fn totp_code(&self) -> Result<TotpCode, AuthenticatorError> {
        let code = self
            .interaction
            .ask_secret(
                SecretPrompt::new(TITLE, "TOTP code")
                    .with_description("Enter the one-time code from your authenticator app."),
            )
            .await?;

        Ok(TotpCode::new(code.into_inner()))
    }

    async fn choose_method(&self, methods: &[MfaMethod]) -> Result<MfaMethod, AuthenticatorError> {
        let prompt = ChoicePrompt::new(
            TITLE,
            "Choose how to verify your identity.",
            methods.iter().map(|method| name(*method)),
        );
        let index = self.interaction.choose(&prompt).await?;

        methods
            .get(index)
            .copied()
            .ok_or(MfaPromptError::InvalidFactorType.into())
    }

    async fn mfa_rejected(&self, reason: &str) {
        let notice = UserNotice::warning(format!("Verification failed: {reason}"));
        // Nothing to do when the notice cannot be shown.
        let _ = self.notifier.notify(&notice).await;
    }

    async fn sign(
        &self,
        request: &WebauthnRequest,
    ) -> Result<WebauthnAssertion, AuthenticatorError> {
        let assertion = self
            .webauthn_client
            .sign_assertion(
                request.challenge.clone(),
                request.rp_id.clone(),
                request.origin.clone(),
                request.credential_ids.clone(),
            )
            .await
            .map_err(|e| AuthenticatorError::Failed(Box::new(e)))?;

        Ok(assertion.into())
    }
}

fn name(method: MfaMethod) -> &'static str {
    match method {
        MfaMethod::Totp => "One-time code (TOTP)",
        MfaMethod::WebAuthn => "Security key (WebAuthn)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::secret::SafeSecret;
    use crate::domain::models::user_interaction::NoticeLevel;
    use crate::domain::ports::notifier::{MockNotifier, NotifyError};
    use crate::domain::ports::user_interaction::MockUserInteraction;
    use crate::domain::ports::webauthn::{WebauthnAssertion as Assertion, WebauthnError};

    struct NoWebauthn;

    #[async_trait(?Send)]
    impl WebauthnClientPort for NoWebauthn {
        async fn sign_assertion(
            &self,
            _challenge: String,
            _rp_id: String,
            _origin: String,
            _credential_ids: Vec<String>,
        ) -> Result<Assertion, WebauthnError> {
            unreachable!("no test signs")
        }
    }

    const METHODS: &[MfaMethod] = &[MfaMethod::Totp, MfaMethod::WebAuthn];

    fn authenticator(
        interaction: MockUserInteraction,
        notifier: MockNotifier,
    ) -> InteractiveAuthenticator<NoWebauthn, MockUserInteraction, MockNotifier> {
        InteractiveAuthenticator::new(
            Rc::new(NoWebauthn),
            Arc::new(interaction),
            Arc::new(notifier),
        )
    }

    #[tokio::test]
    async fn totp_code_is_what_the_user_entered() {
        let mut interaction = MockUserInteraction::new();
        interaction
            .expect_ask_secret()
            .times(1)
            .withf(|prompt| prompt.label == "TOTP code")
            .returning(|_| Ok(SafeSecret::new("123456")));

        let code = authenticator(interaction, MockNotifier::new())
            .totp_code()
            .await
            .unwrap();

        assert_eq!(code.as_str(), "123456");
    }

    #[tokio::test]
    async fn a_cancelled_totp_prompt_is_an_error() {
        let mut interaction = MockUserInteraction::new();
        interaction
            .expect_ask_secret()
            .returning(|_| Err(InteractionError::Cancelled));

        let err = authenticator(interaction, MockNotifier::new())
            .totp_code()
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "cancelled by the user");
    }

    #[tokio::test]
    async fn offers_the_methods_by_name_and_maps_the_index_back() {
        let mut interaction = MockUserInteraction::new();
        interaction
            .expect_choose()
            .times(1)
            .withf(|prompt| prompt.options == ["One-time code (TOTP)", "Security key (WebAuthn)"])
            .returning(|_| Ok(1));

        let method = authenticator(interaction, MockNotifier::new())
            .choose_method(METHODS)
            .await
            .unwrap();

        assert_eq!(method, MfaMethod::WebAuthn);
    }

    #[tokio::test]
    async fn rejects_an_index_that_is_not_a_listed_method() {
        let mut interaction = MockUserInteraction::new();
        interaction.expect_choose().returning(|_| Ok(2));

        let err = authenticator(interaction, MockNotifier::new())
            .choose_method(METHODS)
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "the chosen verification method is not one of the available ones"
        );
    }

    #[tokio::test]
    async fn warns_when_mfa_is_rejected() {
        let mut notifier = MockNotifier::new();
        notifier
            .expect_notify()
            .times(1)
            .withf(|notice| {
                notice.level == NoticeLevel::Warning
                    && notice.message == "Verification failed: bad code"
            })
            .returning(|_| Ok(()));

        authenticator(MockUserInteraction::new(), notifier)
            .mfa_rejected("bad code")
            .await;
    }

    #[tokio::test]
    async fn a_failing_notice_is_ignored() {
        let mut notifier = MockNotifier::new();
        notifier
            .expect_notify()
            .returning(|_| Err(NotifyError::Unavailable));

        authenticator(MockUserInteraction::new(), notifier)
            .mfa_rejected("bad code")
            .await;
    }
}
