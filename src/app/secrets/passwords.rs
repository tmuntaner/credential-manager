use crate::domain::models::secret::SafeSecret;
use crate::domain::models::user_interaction::{ConfirmPrompt, SecretPrompt};
use crate::domain::ports::secret_store::SecretStoreError;
use crate::domain::ports::secret_store::{SecretKey, SecretStore};
use crate::domain::ports::user_interaction::InteractionError;
use crate::domain::ports::user_interaction::UserInteraction;
use url::Url;

/// An error with the password.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PasswordError {
    #[error("the app url is not valid")]
    InvalidAppUrl(#[source] url::ParseError),
    #[error("could not find the domain of the app url {url}")]
    NoAppDomain { url: String },
    #[error("the secret store failed")]
    Store(#[source] SecretStoreError),
    #[error("could not ask for the password")]
    Interaction(#[source] InteractionError),
}

impl PasswordError {
    /// Whether the user canceled the question, which is not a failure.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Interaction(InteractionError::Cancelled))
    }
}

/// The stored password, unless `with_password` forces asking for it. A password that was asked for can be
/// saved in the store, when the user agrees.
pub async fn get_password(
    app_url: String,
    username: String,
    with_password: bool,
    store: Option<&dyn SecretStore>,
    prompt: &dyn UserInteraction,
) -> Result<SafeSecret, PasswordError> {
    let app_domain = Url::parse(app_url.as_str()).map_err(PasswordError::InvalidAppUrl)?;
    let app_domain = app_domain
        .domain()
        .ok_or_else(|| PasswordError::NoAppDomain {
            url: app_url.clone(),
        })?;
    let service = format!("c9s -- {app_domain}");
    let key = SecretKey::new(&username, &service, "c9s");

    if !with_password {
        if let Some(store) = store {
            if let Some(password) = store.get(&key).await.map_err(PasswordError::Store)? {
                return Ok(password);
            }
        }
    }

    prompt_user_for_password(store, &key, &username, app_domain, prompt).await
}

async fn prompt_user_for_password(
    store: Option<&dyn SecretStore>,
    key: &SecretKey,
    username: &str,
    domain: &str,
    prompt: &dyn UserInteraction,
) -> Result<SafeSecret, PasswordError> {
    let password_prompt = SecretPrompt::new("c9s: password required", "Password")
        .with_description(format!("Enter the password of {username} for {domain}."));
    let password = prompt
        .ask_secret(password_prompt)
        .await
        .map_err(PasswordError::Interaction)?;

    if let Some(store) = store {
        let confirm_prompt = ConfirmPrompt::new(
            "c9s: save password",
            format!("Save the password of {username} for {domain} in your keyring, so you are not asked again?"),
        )
        .with_labels("Save", "Don't save");
        let should_save = prompt
            .confirm(confirm_prompt)
            .await
            .map_err(PasswordError::Interaction)?;

        if should_save {
            store
                .set(key, password.clone())
                .await
                .map_err(PasswordError::Store)?;
        }
    }

    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ports::user_interaction::MockUserInteraction;

    #[tokio::test]
    async fn an_ip_url_has_no_domain() {
        let prompt = MockUserInteraction::new();
        let err = get_password("http://127.0.0.1/".into(), "u".into(), false, None, &prompt)
            .await
            .unwrap_err();
        assert!(matches!(err, PasswordError::NoAppDomain { .. }));
    }

    #[tokio::test]
    async fn a_bad_url_is_invalid() {
        let prompt = MockUserInteraction::new();
        let err = get_password("not a url".into(), "u".into(), false, None, &prompt)
            .await
            .unwrap_err();
        assert!(matches!(err, PasswordError::InvalidAppUrl(_)));
    }

    #[tokio::test]
    async fn forcing_the_prompt_does_not_read_the_store() {
        use crate::domain::ports::secret_store::MockSecretStore;
        // No `expect_get`: reading the store would panic.
        let store = MockSecretStore::new();
        let mut prompt = MockUserInteraction::new();
        prompt
            .expect_ask_secret()
            .returning(|_| Ok(SafeSecret::new("pw")));
        prompt.expect_confirm().returning(|_| Ok(false));
        let password = get_password(
            "https://idp.example.com".into(),
            "u".into(),
            true,
            Some(&store),
            &prompt,
        )
        .await
        .unwrap();
        assert_eq!(password.into_inner(), "pw");
    }

    #[tokio::test]
    async fn a_cancelled_question_is_reported_as_cancelled() {
        let mut prompt = MockUserInteraction::new();
        prompt
            .expect_ask_secret()
            .returning(|_| Err(InteractionError::Cancelled));
        let err = get_password(
            "https://idp.example.com".into(),
            "u".into(),
            false,
            None,
            &prompt,
        )
        .await
        .unwrap_err();
        assert!(err.is_cancelled());
    }
}
