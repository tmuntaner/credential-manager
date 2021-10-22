fn main() {
    windows::build! {
        Windows::Win32::Foundation::{BOOL, PWSTR},
        Windows::Win32::Networking::WindowsWebServices::{
            WEBAUTHN_CLIENT_DATA, // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Networking/WindowsWebServices/struct.WEBAUTHN_CLIENT_DATA.html
            WebAuthNAuthenticatorGetAssertion, // // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Networking/WindowsWebServices/fn.WebAuthNAuthenticatorGetAssertion.html
            WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Networking/WindowsWebServices/struct.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS.html
            WEBAUTHN_CREDENTIALS, // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Networking/WindowsWebServices/struct.WEBAUTHN_CREDENTIALS.html
            WEBAUTHN_CREDENTIAL, // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Networking/WindowsWebServices/struct.WEBAUTHN_CREDENTIAL.html
            WEBAUTHN_CLIENT_DATA, // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Networking/WindowsWebServices/struct.WEBAUTHN_CLIENT_DATA.html
            WebAuthNFreeAssertion, // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/Networking/WindowsWebServices/fn.WebAuthNFreeAssertion.html
        },
        Windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow // https://microsoft.github.io/windows-docs-rs/doc/bindings/Windows/Win32/UI/WindowsAndMessaging/fn.GetForegroundWindow.html
    };
}
