/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

mod utils;

pub trait WebauthnNotifier {
    fn notify_start(&self) -> Result<()>;
    fn notify_end(&self) -> Result<()>;
}

#[cfg(feature = "progress_bar")]
mod progress_bar;

#[cfg(feature = "progress_bar")]
use crate::progress_bar::ProgressBarFallbackNotifier;

#[cfg(feature = "notifications")]
mod desktop_notifications;

#[cfg(feature = "notifications")]
use crate::desktop_notifications::DesktopNotificationsFallbackNotifier;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod mozilla;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// <https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata>
#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectedClientData {
    #[serde(rename = "type")]
    sign_type: String,
    challenge: String,
    origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cross_origin: Option<bool>,
    token_binding: Option<TokenBinding>,
}

/// <https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-tokenbinding>
#[derive(Debug, Clone, Deserialize, Serialize)]
struct TokenBinding {
    status: String,
    id: Option<String>,
}

pub struct SignatureResponse {
    pub client_data: String,
    pub signature_data: String,
    pub authenticator_data: String,
}

#[derive(Default)]
pub struct WebauthnClient {
    notifiers: Vec<Box<dyn WebauthnNotifier>>,
}

impl WebauthnClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_notifier(&mut self, notifier: Box<dyn WebauthnNotifier>) -> &mut WebauthnClient {
        self.notifiers.push(notifier);

        self
    }

    #[cfg(feature = "progress_bar")]
    pub fn add_progress_bar_notifier(&mut self) -> &mut WebauthnClient {
        let notifier = Box::new(ProgressBarFallbackNotifier::new());

        self.add_notifier(notifier)
    }

    #[cfg(feature = "notifications")]
    pub fn add_desktop_notification_notifier(&mut self) -> &mut WebauthnClient {
        let notifier = Box::new(DesktopNotificationsFallbackNotifier::new());

        self.add_notifier(notifier)
    }

    #[cfg(target_os = "windows")]
    pub fn sign(
        self,
        challenge_str: String,
        host: String,
        credential_ids: Vec<String>,
    ) -> Result<SignatureResponse> {
        windows::sign(challenge_str, host, credential_ids)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn sign(
        self,
        challenge_str: String,
        host: String,
        credential_ids: Vec<String>,
    ) -> Result<SignatureResponse> {
        mozilla::sign(challenge_str, host, credential_ids, self.notifiers)
    }
}
