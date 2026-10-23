use crate::outbound::authentik::convert;
use authentik::{
    Authenticator, AuthenticatorError, MfaMethod, TotpCode, WebauthnAssertion, WebauthnRequest,
};
use std::io::{self, BufRead, Write};
use thiserror::Error;
use webauthn::WebauthnClient;

#[derive(Debug, Error)]
enum TerminalError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("failed to parse your selection")]
    UnparsableSelection,

    #[error("you've selected an invalid Factor Type")]
    InvalidFactorType,
}

impl From<TerminalError> for AuthenticatorError {
    fn from(e: TerminalError) -> Self {
        AuthenticatorError::Failed(Box::new(e))
    }
}

/// Asks for the second factor on stderr and reads the answer from stdin. Signs with a USB security key,
/// showing a progress bar and optionally a desktop notification while it waits for the touch.
pub struct TerminalAuthenticator {
    enable_desktop_notifications: bool,
}

impl TerminalAuthenticator {
    pub fn new(enable_desktop_notifications: bool) -> Self {
        TerminalAuthenticator {
            enable_desktop_notifications,
        }
    }

    fn read_line() -> Result<String, TerminalError> {
        let _ = io::stderr().flush();
        let mut buffer = String::new();
        io::stdin().lock().read_line(&mut buffer)?;

        Ok(buffer.trim_end_matches(['\r', '\n']).to_string())
    }
}

impl Authenticator for TerminalAuthenticator {
    fn totp_code(&self) -> Result<TotpCode, AuthenticatorError> {
        eprint!("TOTP Code: ");
        Ok(TotpCode::new(TerminalAuthenticator::read_line()?))
    }

    fn choose_method(&self, methods: &[MfaMethod]) -> Result<MfaMethod, AuthenticatorError> {
        eprintln!("Please select a MFA Factor Type:");
        for (i, method) in methods.iter().enumerate() {
            eprintln!("( {i} ) {}", name(*method));
        }
        eprint!("Factor Type? (0 - {}) ", methods.len().saturating_sub(1));

        Ok(choice(&TerminalAuthenticator::read_line()?, methods)?)
    }

    fn mfa_rejected(&self, reason: &str) {
        eprintln!("MFA was rejected: {reason}");
    }

    fn sign(&self, request: &WebauthnRequest) -> Result<WebauthnAssertion, AuthenticatorError> {
        let mut client = WebauthnClient::new();
        if self.enable_desktop_notifications {
            client.add_desktop_notification_notifier();
        }
        client.add_progress_bar_notifier();

        client
            .sign_assertion(
                request.challenge.clone(),
                request.rp_id.clone(),
                request.origin.clone(),
                request.credential_ids.clone(),
            )
            .map(convert::assertion)
            .map_err(|e| AuthenticatorError::Failed(Box::new(e)))
    }
}

fn name(method: MfaMethod) -> &'static str {
    match method {
        MfaMethod::Totp => "TOTP",
        MfaMethod::WebAuthn => "WebAuthn",
    }
}

/// The method the user picked by its number.
fn choice(input: &str, methods: &[MfaMethod]) -> Result<MfaMethod, TerminalError> {
    let index: usize = input
        .trim()
        .parse()
        .map_err(|_| TerminalError::UnparsableSelection)?;

    methods
        .get(index)
        .copied()
        .ok_or(TerminalError::InvalidFactorType)
}

#[cfg(test)]
mod tests {
    use super::*;

    const METHODS: &[MfaMethod] = &[MfaMethod::Totp, MfaMethod::WebAuthn];

    #[test]
    fn picks_the_method_by_its_number() {
        assert_eq!(choice("1", METHODS).unwrap(), MfaMethod::WebAuthn);
        assert_eq!(choice(" 0 ", METHODS).unwrap(), MfaMethod::Totp);
    }

    #[test]
    fn rejects_what_is_not_a_listed_number() {
        assert!(matches!(
            choice("x", METHODS),
            Err(TerminalError::UnparsableSelection)
        ));
        assert!(matches!(
            choice("2", METHODS),
            Err(TerminalError::InvalidFactorType)
        ));
    }

    #[test]
    fn errors_keep_their_message() {
        let err = AuthenticatorError::from(TerminalError::InvalidFactorType);

        assert_eq!(err.to_string(), "you've selected an invalid Factor Type");
    }
}
