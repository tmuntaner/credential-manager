/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use anyhow::Result;

#[cfg(target_os = "linux")]
mod secret_service;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
use linux::Keyring;

#[cfg(target_os = "macos")]
mod mac;

#[cfg(target_os = "macos")]
use mac::Keyring;

#[cfg(target_os = "windows")]
mod wincred;

#[cfg(target_os = "windows")]
mod win;

#[cfg(target_os = "windows")]
use win::Keyring;

/// This Keyring Client interacts with the OS specific keyring to store a secret.
///
/// ## Keyring Backends:
/// * Windows - [wincred](https://docs.microsoft.com/en-us/windows/win32/api/wincred/)
/// * Linux - [Secret Service](https://specifications.freedesktop.org/secret-service/latest/)
/// * Mac - [Security Framework](https://developer.apple.com/documentation/security)
pub struct KeyringClient<'a> {
    client: Keyring<'a>,
}

impl<'a> KeyringClient<'a> {
    /// Returns a new keyring client
    ///
    /// # Arguments
    ///
    /// * `username` - The username to store secrets under
    /// * `service` - A unique identifier within your application
    /// * `application` - The name of your application
    pub fn new(username: &'a str, service: &'a str, application: &'a str) -> Result<Self> {
        let client = Keyring::new(username, service, application)?;

        Ok(KeyringClient { client })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        self.client.set_password(password)
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        self.client.get_password()
    }
}
