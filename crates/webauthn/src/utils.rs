/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use crate::CollectedClientData;
use anyhow::Result;
use url::Url;

pub fn client_data(origin: String, challenge_str: String) -> Result<String> {
    let caller_origin = Url::parse(origin.as_str())?;

    let collected_client_data = CollectedClientData {
        sign_type: "webauthn.get".to_string(),
        challenge: challenge_str,
        origin: caller_origin.origin().unicode_serialization(),
        token_binding: None,
        cross_origin: None,
    };
    let client_data = serde_json::to_string(&collected_client_data)?;

    Ok(client_data)
}
