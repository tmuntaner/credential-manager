#[cfg(target_os = "windows")]
fn main() {
    windows::build! {
        Windows::Win32::Foundation::{BOOL, PWSTR, FILETIME},
        Windows::Win32::Security::Credentials::{CredReadW, CredWriteW, CredDeleteW, CredFree, CREDENTIALW, CRED_FLAGS, CRED_TYPE, CRED_PERSIST},
        Windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime,
    };
}

#[cfg(target_os = "linux")]
fn main() {}

#[cfg(target_os = "macos")]
fn main() {}
