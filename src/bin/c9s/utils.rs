use anyhow::{anyhow, Result};
use std::io::{self, BufRead, Write};
use url::Url;

pub fn get_password(app_url: String, username: String, with_password: bool) -> Result<String> {
    let app_domain = Url::parse(app_url.as_str())?;
    let app_domain = app_domain
        .domain()
        .ok_or_else(|| anyhow!("could not find app domain"))?;
    let service = format!("c9s -- {}", app_domain);

    let keyring = keyring::Keyring::new(service.as_str(), username.as_str());

    let password = match with_password {
        true => {
            let password = rpassword::prompt_password_stdout("Password: ")?;

            print!("Save password? (y/n) ");
            let _ = io::stdout().flush();
            let mut buffer = String::new();
            io::stdin().lock().read_line(&mut buffer)?;
            // remove \n on unix or \r\n on windows
            let len = buffer.trim_end_matches(&['\r', '\n'][..]).len();
            buffer.truncate(len);

            if buffer == "y" {
                keyring.set_password(password.as_str()).unwrap();
            }

            password
        }
        false => keyring
            .get_password()
            .map_err(|_e| anyhow!("please supply a password"))?,
    };

    Ok(password)
}
