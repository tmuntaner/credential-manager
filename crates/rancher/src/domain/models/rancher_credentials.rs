use time::OffsetDateTime;

/// A temporary token for a Rancher cluster.
#[derive(Debug, Clone, PartialEq)]
pub struct RancherCredential {
    pub token: String,
    pub token_id: String,
    /// Rancher does not report it, so it is the creation time plus the requested ttl.
    pub expiry: OffsetDateTime,
    pub cluster_name: String,
    pub cluster_id: String,
    /// The Kubernetes API of the cluster, proxied by Rancher.
    pub server_url: String,
    /// PEM, the certificate authority of Rancher.
    pub ca: String,
}
