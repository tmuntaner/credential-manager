/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use zbus::dbus_proxy;

/// https://specifications.freedesktop.org/secret-service/latest/re04.html
#[dbus_proxy(interface = "org.freedesktop.Secret.Session", assume_defaults = true)]
trait Session {
    fn close(&self) -> zbus::Result<()>;
}
