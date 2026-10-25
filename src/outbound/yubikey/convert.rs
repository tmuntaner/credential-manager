use crate::domain::ports::secret_wrapper::WrapError;

impl From<webauthn::WebauthnError> for WrapError {
    fn from(err: webauthn::WebauthnError) -> Self {
        match err {
            webauthn::WebauthnError::ReceiveSignResult
            | webauthn::WebauthnError::ReceiveRegisterResult => WrapError::Cancelled,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            webauthn::WebauthnError::StartSigning(e)
            | webauthn::WebauthnError::StartRegistering(e) => WrapError::Failed(Box::new(e)),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            webauthn::WebauthnError::SecurityKey(ref e) => {
                let msg = e.to_string().to_lowercase();
                if msg.contains("not present")
                    || msg.contains("no device")
                    || msg.contains("not found")
                    || msg.contains("could not find")
                {
                    WrapError::DeviceNotPresent
                } else if msg.contains("cancel")
                    || msg.contains("timed out")
                    || msg.contains("timeout")
                {
                    WrapError::Cancelled
                } else {
                    WrapError::Failed(Box::new(err))
                }
            }
            _ => WrapError::Failed(Box::new(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_receive_sign_result_to_cancelled() {
        let err = WrapError::from(webauthn::WebauthnError::ReceiveSignResult);
        assert!(matches!(err, WrapError::Cancelled));
    }

    #[test]
    fn converts_receive_register_result_to_cancelled() {
        let err = WrapError::from(webauthn::WebauthnError::ReceiveRegisterResult);
        assert!(matches!(err, WrapError::Cancelled));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn converts_unsupported_platform_to_failed() {
        let err = WrapError::from(webauthn::WebauthnError::UnsupportedPlatform);
        assert!(matches!(err, WrapError::Failed(_)));
    }
}
