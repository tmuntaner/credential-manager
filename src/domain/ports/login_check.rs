use crate::domain::models::login::{LoginTarget, ResolveError};
use crate::domain::models::settings::AppConfig;

/// Tells whether an app within the settings snapshot is able to resolve a login.
/// If it cannot resolve it, it won't be able to log in so the app config is invalid.
///
/// The error is [`ResolveError`], the error of the sibling `LoginResolver` port.
#[cfg_attr(test, mockall::automock)]
pub trait LoginCheck {
    fn resolves(&self, settings: &AppConfig, target: &LoginTarget) -> Result<(), ResolveError>;
}

/// A simple LoginCheck which resolves everything.
/// Useful for testing but should not be used for real apps.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLoginCheck;

impl LoginCheck for NoLoginCheck {
    fn resolves(&self, _: &AppConfig, _: &LoginTarget) -> Result<(), ResolveError> {
        Ok(())
    }
}
