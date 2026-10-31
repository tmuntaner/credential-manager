use anyhow::{anyhow, Result};
use c9s::domain::models::prompt_mode::PromptMode;
use c9s::domain::models::secret::SafeSecret;
use c9s::domain::models::settings::AppConfig;
use c9s::domain::models::user_interaction::{ConfirmPrompt, SecretPrompt};
use c9s::domain::ports::notifier::Notifier;
use c9s::domain::ports::secret_store::{SecretKey, SecretStore};
use c9s::domain::ports::user_interaction::UserInteraction;
use c9s::outbound::prompt::select::{build, build_notifier, notifiers, prompts, PromptEnvironment};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Selects the best interaction and notifier for the user based on the environment.
pub fn interaction(
    settings: &AppConfig,
    prompt_flag: Option<PromptMode>,
) -> (
    Arc<impl UserInteraction + 'static>,
    Arc<impl Notifier + 'static>,
) {
    let mode = prompt_flag.or(settings.prompt_mode()).unwrap_or_default();
    let env = PromptEnvironment::from_process(settings.pinentry_program());
    (
        Arc::new(build(&prompts(mode, &env))),
        Arc::new(build_notifier(&notifiers(mode, &env))),
    )
}

pub async fn get_password(
    app_url: String,
    username: String,
    with_password: bool,
    store: Option<&dyn SecretStore>,
    prompt: &dyn UserInteraction,
) -> Result<SafeSecret> {
    let app_domain = Url::parse(app_url.as_str())?;
    let app_domain = app_domain
        .domain()
        .ok_or_else(|| anyhow!("could not find app domain"))?;
    let service = format!("c9s -- {app_domain}");
    let key = SecretKey::new(&username, &service, "c9s");

    let password = if let Some(store) = store {
        store.get(&key).await?
    } else {
        None
    };

    let password = match with_password {
        true => prompt_user_for_password(store, &key, &username, app_domain, prompt).await?,
        false => match password {
            Some(password) => password,
            None => prompt_user_for_password(store, &key, &username, app_domain, prompt).await?,
        },
    };

    Ok(password)
}

pub async fn get_cached_credential<T: DeserializeOwned>(
    key: &str,
    store: Option<&dyn SecretStore>,
) -> Result<Option<T>> {
    let cached_credential = if let Some(store) = store {
        let service = format!("c9s credential -- {key}");
        let secret_key = SecretKey::new(key, &service, "c9s");
        store.get(&secret_key).await?.map(|s| s.into_inner())
    } else {
        None
    };

    if let Some(cached_credential) = cached_credential {
        let credentials: T = serde_json::from_str(cached_credential.as_str())?;

        return Ok(Some(credentials));
    }

    Ok(None)
}

pub async fn set_cached_credential<T: Serialize>(
    key: &str,
    credential: &T,
    store: Option<&dyn SecretStore>,
) -> Result<()> {
    if let Some(store) = store {
        let service = format!("c9s credential -- {key}");
        let secret_key = SecretKey::new(key, &service, "c9s");
        let json = serde_json::to_string(credential)?;
        store.set(&secret_key, SafeSecret::new(json)).await?;
    }

    Ok(())
}

async fn prompt_user_for_password(
    store: Option<&dyn SecretStore>,
    key: &SecretKey,
    username: &str,
    domain: &str,
    prompt: &dyn UserInteraction,
) -> Result<SafeSecret> {
    let password_prompt = SecretPrompt::new("c9s: password required", "Password")
        .with_description(format!("Enter the password of {username} for {domain}."));
    let password = prompt.ask_secret(password_prompt).await?;

    if let Some(store) = store {
        let confirm_prompt = ConfirmPrompt::new(
            "c9s: save password",
            format!("Save the password of {username} for {domain} in your keyring, so you are not asked again?"),
        )
        .with_labels("Save", "Don't save");
        let should_save = prompt.confirm(confirm_prompt).await?;

        if should_save {
            store.set(key, password.clone()).await?;
        }
    }

    Ok(password)
}

pub fn true_or_false(s: &str) -> Result<bool, &'static str> {
    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("expected `true` or `false`"),
    }
}

pub fn parse_ttl(value: &str) -> Result<Duration, String> {
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .ok_or("missing unit, use s, m, h or d")?;
    let (number, unit) = value.split_at(split);
    let number: u64 = number.parse().map_err(|_| "expected e.g. 30m, 1h or 1d")?;
    let seconds = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err("unknown unit, use s, m, h or d".to_string()),
    };
    let ttl = Duration::from_secs(number.saturating_mul(seconds));
    if ttl.is_zero() {
        // a ttl of 0 asks Rancher for a token that never expires
        return Err("the ttl must be longer than 0".to_string());
    }

    Ok(ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ttls_and_refuses_one_that_never_expires() {
        assert_eq!(parse_ttl("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_ttl("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_ttl("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_ttl("1d").unwrap(), Duration::from_secs(86400));
        assert!(parse_ttl("0m").is_err());
        assert!(parse_ttl("10").is_err());
        assert!(parse_ttl("h").is_err());
        assert!(parse_ttl("1w").is_err());
    }
}
