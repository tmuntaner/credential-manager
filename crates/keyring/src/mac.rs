/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use anyhow::Result;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::passwords::find_generic_password;

pub struct Keyring<'a> {
    username: &'a str,
    service: &'a str,
}

impl<'a> Keyring<'a> {
    pub fn new(username: &'a str, service: &'a str, _application: &'a str) -> Result<Self> {
        Ok(Keyring { username, service })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        let keychain = SecKeychain::default()?;
        keychain.set_generic_password(self.service, self.username, password.as_bytes())?;

        Ok(())
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        let keychain = SecKeychain::default()?;
        let result = find_generic_password(Some(&[keychain]), self.service, self.username);
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
