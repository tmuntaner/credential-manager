//! Command line spellings of the domain enums, so the domain does not depend on `clap`.

use c9s::domain::models::idp::IdpType;
use c9s::domain::models::prompt_mode::PromptMode;
use c9s::domain::models::settings::AwsAppType;
use clap::ValueEnum;

/// The type of an identity provider instance.
#[derive(ValueEnum, Debug, Clone, Copy, Default)]
pub enum IdpTypeArg {
    #[default]
    Authentik,
}

impl From<IdpTypeArg> for IdpType {
    fn from(arg: IdpTypeArg) -> Self {
        match arg {
            IdpTypeArg::Authentik => IdpType::Authentik,
        }
    }
}

/// How c9s approaches auto input
#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum PromptModeArg {
    /// Uses a popup when possible, and a terminal when not.
    Auto,
    /// Only use a popup.
    Gui,
    /// Only use a terminal.
    Terminal,
}

impl From<PromptModeArg> for PromptMode {
    fn from(arg: PromptModeArg) -> Self {
        match arg {
            PromptModeArg::Auto => PromptMode::Auto,
            PromptModeArg::Gui => PromptMode::Gui,
            PromptModeArg::Terminal => PromptMode::Terminal,
        }
    }
}

/// The kind of AWS application in authentik.
#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum AwsAppTypeArg {
    /// The AWS SAML application, with IAM roles
    #[value(name = "aws")]
    Aws,
    /// The AWS IAM Identity Center application
    #[value(name = "aws-sso")]
    AwsSso,
}

impl From<AwsAppTypeArg> for AwsAppType {
    fn from(arg: AwsAppTypeArg) -> Self {
        match arg {
            AwsAppTypeArg::Aws => AwsAppType::Aws,
            AwsAppTypeArg::AwsSso => AwsAppType::AwsSso,
        }
    }
}
