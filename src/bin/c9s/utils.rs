use anyhow::{anyhow, Result};
use keyring::KeyringClient;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{self, BufRead, Write};
use std::time::Duration;
use url::Url;

pub fn get_password(
    app_url: String,
    username: String,
    with_password: bool,
    keyring_enabled: bool,
) -> Result<String> {
    let app_domain = Url::parse(app_url.as_str())?;
    let app_domain = app_domain
        .domain()
        .ok_or_else(|| anyhow!("could not find app domain"))?;
    let service = format!("c9s -- {app_domain}");

    let keyring = KeyringClient::new(username.as_str(), service.as_str(), "c9s")?;
    let password = if keyring_enabled {
        keyring.get_password()?
    } else {
        None
    };

    let password = match with_password {
        true => prompt_user_for_password(&keyring, keyring_enabled)?,
        false => match password {
            Some(password) => password,
            None => prompt_user_for_password(&keyring, keyring_enabled)?,
        },
    };

    Ok(password)
}

pub fn get_cached_credential<T: DeserializeOwned>(
    key: &str,
    keyring_enabled: bool,
) -> Result<Option<T>> {
    let cached_credential = if keyring_enabled {
        let service = format!("c9s credential -- {key}");
        let keyring = KeyringClient::new(key, &service, "c9s")?;
        keyring.get_password()?
    } else {
        None
    };

    if let Some(cached_credential) = cached_credential {
        let credentials: T = serde_json::from_str(cached_credential.as_str())?;

        return Ok(Some(credentials));
    }

    Ok(None)
}

pub fn set_cached_credential<T: Serialize>(
    key: &str,
    credential: &T,
    keyring_enabled: bool,
) -> Result<()> {
    if keyring_enabled {
        let service = format!("c9s credential -- {key}");
        let keyring = KeyringClient::new(key, &service, "c9s")?;
        let json = serde_json::to_string(credential)?;
        keyring.set_password(json)?;
    }

    Ok(())
}

fn prompt_user_for_password(keyring: &KeyringClient, keyring_enabled: bool) -> Result<String> {
    let password = rpassword::prompt_password("Password: ")?;

    if keyring_enabled {
        eprint!("Save password? (y/n) ");
        let _ = io::stdout().flush();
        let mut buffer = String::new();
        io::stdin().lock().read_line(&mut buffer)?;
        // remove \n on unix or \r\n on windows
        let len = buffer.trim_end_matches(&['\r', '\n'][..]).len();
        buffer.truncate(len);

        if buffer == "y" {
            keyring.set_password(password.clone())?;
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
