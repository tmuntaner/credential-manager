use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// The type of an identity provider instance.
#[derive(ValueEnum, PartialEq, Eq, Debug, Clone, Copy, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum IdpType {
    #[default]
    Authentik,
}
