use crate::errors::KeyringError;
use crate::wincred::client::WincredClient;

pub struct Keyring<'a> {
    client: WincredClient<'a>,
}

impl<'a> Keyring<'a> {
    pub fn new(
        username: &'a str,
        service: &'a str,
        _application: &'a str,
    ) -> Result<Self, KeyringError> {
        let client: WincredClient = WincredClient::new(username, service)?;
        Ok(Self { client })
    }

    pub fn set_password(&self, password: String) -> Result<(), KeyringError> {
        self.client.set_password(password)
    }

    pub fn get_password(&self) -> Result<Option<String>, KeyringError> {
        self.client.get_password()
    }
}
