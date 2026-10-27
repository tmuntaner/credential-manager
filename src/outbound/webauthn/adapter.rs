use crate::domain::ports::webauthn::{WebauthnAssertion, WebauthnClientPort, WebauthnError};
use async_trait::async_trait;
use std::sync::Arc;
use webauthn::{SecurityKeyUi, WebauthnClient};

pub struct WebauthnAdapter {
    client: WebauthnClient,
}

impl WebauthnAdapter {
    /// `ui` is how the user is asked for the security key PIN.
    pub fn new(enable_notifications: bool, ui: Arc<dyn SecurityKeyUi>) -> Self {
        let mut client = WebauthnClient::new();
        client.with_security_key_ui(ui);

        if enable_notifications {
            client.add_desktop_notification_notifier();
        }

        client.add_progress_bar_notifier();

        Self { client }
    }
}

#[async_trait(?Send)]
impl WebauthnClientPort for WebauthnAdapter {
    async fn sign_assertion(
        &self,
        challenge: String,
        rp_id: String,
        origin: String,
        credential_ids: Vec<String>,
    ) -> Result<WebauthnAssertion, WebauthnError> {
        let assertion = self
            .client
            .sign_assertion(challenge, rp_id, origin, credential_ids)
            .await
            .map_err(|e| WebauthnError::Failed(Box::new(e)))?;

        Ok(assertion.into())
    }
}

impl From<webauthn::WebauthnAssertion> for WebauthnAssertion {
    fn from(value: webauthn::WebauthnAssertion) -> Self {
        Self {
            credential_id: value.credential_id,
            client_data_json: value.client_data_json,
            authenticator_data: value.authenticator_data,
            signature: value.signature,
        }
    }
}
