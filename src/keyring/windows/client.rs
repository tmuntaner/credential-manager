use anyhow::{anyhow, Result};

use crate::keyring::windows::Windows::Win32::{
    Foundation::*, Security::Credentials::*, System::SystemInformation::*,
};
use std::ffi::c_void;
use widestring::{U16CString, U16String};

const CRED_TYPE_GENERIC: u32 = 1;

pub struct KeyringClient {
    username: String,
    service: String,
}

impl KeyringClient {
    pub fn new(username: String, service: String) -> Result<Self> {
        Ok(KeyringClient { username, service })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        // file time will get the current system time
        // <https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime>
        let filetime = Box::new(FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        });
        let filetime: *mut FILETIME = Box::into_raw(filetime);

        // <https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime>
        unsafe { GetSystemTimeAsFileTime(filetime) };

        let target = U16CString::from_str(self.service.clone())?;
        let secret = U16CString::from_str(password.clone())?;
        let username = U16CString::from_str(self.username.clone())?;

        // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw>
        let cred = CREDENTIALW {
            Flags: CRED_FLAGS(0u32),
            Type: CRED_TYPE(CRED_TYPE_GENERIC),
            TargetName: PWSTR(target.as_ptr() as *mut u16),
            Comment: PWSTR(std::ptr::null_mut() as *mut u16),
            LastWritten: unsafe { *filetime },
            CredentialBlobSize: password.len() as u32 * 2,
            CredentialBlob: secret.as_ptr() as *mut u8,
            Persist: CRED_PERSIST(1),
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: PWSTR(std::ptr::null_mut() as *mut u16),
            UserName: PWSTR(username.as_ptr() as *mut u16),
        };

        // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew>
        let result: BOOL = unsafe { CredWriteW(&cred, 0u32) };

        unsafe { drop(Box::from_raw(filetime)) }

        if result.0 == 0 {
            Err(anyhow!("failed to save windows credential"))
        } else {
            Ok(())
        }
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        let target = U16CString::from_str(self.service.clone())?;
        let target_ptr = target.as_ptr();

        // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw>
        let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
        let credential_ptr: *mut *mut CREDENTIALW = &mut credential;

        let result: BOOL = unsafe {
            // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw>
            CredReadW(
                PWSTR(target_ptr as *mut u16),
                CRED_TYPE_GENERIC,
                0u32, // no flags
                credential_ptr,
            )
        };

        // result.0 will be 0 if we could not find the secret
        let secret = if result.0 == 0 {
            None
        } else {
            let secret = unsafe {
                U16String::from_ptr(
                    (*credential).CredentialBlob as *const u16,
                    (*credential).CredentialBlobSize as usize / 2,
                )
                .to_string_lossy()
            };

            Some(secret)
        };

        // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credfree>
        unsafe { CredFree(credential as *const c_void) };

        Ok(secret)
    }
}
