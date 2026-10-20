/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use anyhow::{anyhow, Result};
use std::ffi::c_void;
use widestring::{U16CString, U16String};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::{Foundation::*, Security::Credentials::*, System::SystemInformation::*};

// <https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw#members>
const CRED_FLAG_NONE: u32 = 0;
const CRED_TYPE_GENERIC: u32 = 1;

pub struct WincredClient<'a> {
    username: &'a str,
    service: &'a str,
}

impl<'a> WincredClient<'a> {
    pub fn new(username: &'a str, service: &'a str) -> Result<Self> {
        Ok(Self { username, service })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        // <https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime>
        // <https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Foundation/struct.FILETIME.html>
        let last_written = Box::new(FILETIME::default());
        let last_written_ptr: *mut FILETIME = Box::into_raw(last_written); // we're now responsible for freeing this

        // <https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime>
        // <https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/System/SystemInformation/fn.GetSystemTimeAsFileTime.html>
        unsafe { GetSystemTimeAsFileTime(last_written_ptr) };
        let last_written = unsafe { *last_written_ptr };

        let target = U16CString::from_str(self.service)?;
        let target = PWSTR(target.as_ptr() as *mut u16);

        let username = U16CString::from_str(self.username)?;
        let username = PWSTR(username.as_ptr() as *mut u16);

        let secret = U16CString::from_str(password.clone())?;

        // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw>
        let cred = CREDENTIALW {
            Flags: CRED_FLAGS(CRED_FLAG_NONE),
            Type: CRED_TYPE(CRED_TYPE_GENERIC),
            TargetName: target,
            Comment: PWSTR(std::ptr::null_mut() as *mut u16),
            LastWritten: last_written,
            CredentialBlobSize: password.len() as u32 * 2,
            CredentialBlob: secret.as_ptr() as *mut u8, // byte array
            Persist: CRED_PERSIST_LOCAL_MACHINE,        // persist
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: PWSTR(std::ptr::null_mut() as *mut u16),
            UserName: username,
        };

        // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew>
        // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Foundation/struct.BOOL.html
        let result: BOOL = unsafe { CredWriteW(&cred, CRED_FLAG_NONE) };

        // after calling Box::into_raw, we're responsible for cleaning up filetime.
        unsafe { drop(Box::from_raw(last_written_ptr)) }

        if result.as_bool() {
            Ok(())
        } else {
            Err(anyhow!("failed to save windows credential"))
        }
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        let target = U16CString::from_str(self.service)?;
        let target_ptr = target.as_ptr();

        // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw>
        let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
        let credential_ptr: *mut *mut CREDENTIALW = &mut credential;

        // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Foundation/struct.BOOL.html
        let result: BOOL = unsafe {
            // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw>
            // <https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Security/Credentials/fn.CredReadW.html>
            CredReadW(
                PCWSTR(target_ptr as *mut u16),
                CRED_TYPE_GENERIC,
                CRED_FLAG_NONE,
                credential_ptr,
            )
        };

        let secret = if result.as_bool() {
            let secret = unsafe {
                U16String::from_ptr(
                    (*credential).CredentialBlob as *const u16,
                    (*credential).CredentialBlobSize as usize / 2,
                )
                .to_string_lossy()
            };

            Some(secret)
        } else {
            None
        };

        // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credfree>
        // <https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Security/Credentials/fn.CredFree.html>
        unsafe { CredFree(credential as *const c_void) };

        Ok(secret)
    }
}
