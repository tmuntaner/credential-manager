/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use crate::wincred::client::WincredClient;
use anyhow::Result;

pub struct Keyring<'a> {
    client: WincredClient<'a>,
}

impl<'a> Keyring<'a> {
    pub fn new(username: &'a str, service: &'a str, _application: &'a str) -> Result<Self> {
        let client: WincredClient = WincredClient::new(username, service)?;
        Ok(Self { client })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        self.client.set_password(password)
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        self.client.get_password()
    }
}
