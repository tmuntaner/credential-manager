use time::OffsetDateTime;

/// A temporary token for a Rancher cluster.
#[derive(Debug, Clone, PartialEq)]
pub struct RancherCredential {
    pub token: String,
    pub token_id: String,
    /// Rancher does not report expiry, so we use the creation time plus the requested ttl.
    pub expiry: OffsetDateTime,
    pub cluster_name: String,
    pub cluster_id: String,
    /// The Kubernetes API of the cluster.
    pub server_url: String,
    /// PEM, Rancher's CA.
    pub ca: String,
}
