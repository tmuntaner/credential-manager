//! Renders a credential for kubectl.

mod kubeconfig;

pub use kubeconfig::{exec_credential, kubeconfig};
