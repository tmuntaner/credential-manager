//! The adapters for AWS. Only the types that implement the ports are public.

mod sso;
mod sts;

pub use sso::{AwsSsoError, SsoCredentials};
pub use sts::StsCredentials;
