use anyhow::{anyhow, Result};

use std::ffi::c_void;
use widestring::{U16CString, U16String};
use wincred_sys::Windows::Win32::{
    Foundation::*, Security::Credentials::*, System::SystemInformation::*,
};

// <https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw#members>
const CRED_FLAG_NONE: u32 = 0;
const CRED_TYPE_GENERIC: u32 = 1;

pub fn set_password(target: String, username: String, password: String) -> Result<()> {
    // file time will get the current system time
    // <https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime>
    // <https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Foundation/struct.FILETIME.html>
    let filetime = Box::new(FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    });
    let filetime: *mut FILETIME = Box::into_raw(filetime);

    // <https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime>
    // <https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/System/SystemInformation/fn.GetSystemTimeAsFileTime.html>
    unsafe { GetSystemTimeAsFileTime(filetime) };

    let target = U16CString::from_str(target)?;
    let secret = U16CString::from_str(password.clone())?;
    let username = U16CString::from_str(username)?;

    // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw>
    let cred = CREDENTIALW {
        Flags: CRED_FLAGS(CRED_FLAG_NONE),
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
    // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Foundation/struct.BOOL.html
    let result: BOOL = unsafe { CredWriteW(&cred, CRED_FLAG_NONE) };

    unsafe { drop(Box::from_raw(filetime)) }

    if result.as_bool() {
        Err(anyhow!("failed to save windows credential"))
    } else {
        Ok(())
    }
}

pub fn get_password(target: String) -> Result<Option<String>> {
    let target = U16CString::from_str(target)?;
    let target_ptr = target.as_ptr();

    // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw>
    let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
    let credential_ptr: *mut *mut CREDENTIALW = &mut credential;

    // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Foundation/struct.BOOL.html
    let result: BOOL = unsafe {
        // <https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw>
        // <https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Security/Credentials/fn.CredReadW.html>
        CredReadW(
            PWSTR(target_ptr as *mut u16),
            CRED_TYPE_GENERIC,
            CRED_FLAG_NONE,
            credential_ptr,
        )
    };

    let secret = if result.as_bool() {
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
    // <https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Security/Credentials/fn.CredFree.html>
    unsafe { CredFree(credential as *const c_void) };

    Ok(secret)
}
