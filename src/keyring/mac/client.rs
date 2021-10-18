use anyhow::Result;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::passwords::find_generic_password;

pub struct KeyringClient {
    username: String,
    service: String,
}

impl KeyringClient {
    pub fn new(username: String, service: String) -> Result<Self> {
        Ok(KeyringClient { username, service })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        let keychain = SecKeychain::default()?;
        keychain.set_generic_password(
            self.service.clone().as_str(),
            self.username.clone().as_str(),
            password.as_bytes(),
        )?;

        Ok(())
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        let keychain = SecKeychain::default()?;
        let result = find_generic_password(
            Some(&[keychain]),
            self.service.as_str(),
            self.username.as_str(),
        );
        let secret = match result {
            Ok((password, _)) => {
                let secret = String::from_utf8(password.to_vec())?;
                Some(secret)
            }
            Err(_) => None,
        };

        Ok(secret)
    }
}
