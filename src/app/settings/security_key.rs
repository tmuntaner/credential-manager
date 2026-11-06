use super::models::SetupError;
use crate::domain::models::settings::YubikeyConfig;
use crate::domain::ports::notifier::Notifier;
use crate::domain::ports::secret_wrapper::WrapError;
use crate::domain::ports::user_interaction::UserInteraction;
use std::sync::Arc;

/// The relying party id used when none is given, as in `c9s config global yubikey enroll`.
pub const DEFAULT_RP_ID: &str = "localhost";

/// Enrolls a security key for `rp_id` through the outbound adapter. It does not save it.
///
/// The returned future is not `Send`. We need to run it on the thread that owns a current-thread runtime.
pub async fn enroll_security_key<U: UserInteraction + 'static, N: Notifier + 'static>(
    rp_id: &str,
    interaction: Arc<U>,
    notifier: Arc<N>,
) -> Result<YubikeyConfig, SetupError> {
    if !super::SECURITY_KEY_SUPPORTED {
        return Err(SetupError::general(
            "Security keys are not supported on this system.",
        ));
    }

    crate::outbound::yubikey::enroll(rp_id, interaction, notifier)
        .await
        .map_err(wrap_error)
}

/// Says why a security key could not be enrolled.
pub(super) fn wrap_error(error: WrapError) -> SetupError {
    let message = match error {
        WrapError::DeviceNotPresent => {
            "No security key was found. Plug it in and try again.".to_string()
        }
        WrapError::Cancelled => {
            "Enrolling the security key was cancelled or timed out.".to_string()
        }
        other => format!("The security key could not be enrolled: {other}."),
    };
    SetupError::general(message)
}
