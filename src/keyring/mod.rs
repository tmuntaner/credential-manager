use anyhow::Result;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
mod mac;

#[cfg(target_os = "linux")]
use crate::keyring::linux::client::KeyringClient;

#[cfg(target_os = "windows")]
use crate::keyring::windows::client::KeyringClient;

#[cfg(target_os = "macos")]
use crate::keyring::mac::client::KeyringClient;

#[cfg(any(target_os = "windows", target_os = "macos"))]
pub struct Keyring {
    client: KeyringClient,
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
impl Keyring {
    pub fn new(username: String, service: String) -> Result<Self> {
        let client = KeyringClient::new(username, service)?;

        Ok(Keyring { client })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        self.client.set_password(password)
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        self.client.get_password()
    }
}

#[cfg(target_os = "linux")]
pub struct Keyring<'a> {
    client: KeyringClient<'a>,
}

#[cfg(target_os = "linux")]
impl Keyring<'_> {
    pub fn new(username: String, service: String) -> Result<Self> {
        let client = KeyringClient::new(username, service)?;

        Ok(Keyring { client })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        self.client.set_password(password)
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        self.client.get_password()
    }
}
