/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use zbus::dbus_proxy;
use zvariant::Value;

/// https://specifications.freedesktop.org/secret-service/latest/re05.html
#[dbus_proxy(interface = "org.freedesktop.Secret.Prompt", assume_defaults = true)]
trait Prompt {
    fn prompt(&self, window_id: &str) -> zbus::Result<()>;

    fn dismiss(&self) -> zbus::Result<()>;

    #[dbus_proxy(signal)]
    fn completed(&self, dismissed: bool, result: Value<'_>) -> zbus::Result<()>;
}
