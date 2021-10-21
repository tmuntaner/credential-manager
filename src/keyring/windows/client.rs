use anyhow::Result;

pub struct KeyringClient {
    username: String,
    service: String,
}

impl KeyringClient {
    pub fn new(username: String, service: String) -> Result<Self> {
        Ok(KeyringClient { username, service })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        wincred::set_password(self.service.clone(), self.username.clone(), password)
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        wincred::get_password(self.service.clone())
    }
}
