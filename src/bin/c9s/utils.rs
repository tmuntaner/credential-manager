use anyhow::{anyhow, Result};
use std::io::{self, BufRead, Write};
use tmuntaner_keyring::KeyringClient;
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
    let service = format!("c9s -- {}", app_domain);

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

fn prompt_user_for_password(keyring: &KeyringClient, keyring_enabled: bool) -> Result<String> {
    let password = rpassword::prompt_password_stderr("Password: ")?;

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
