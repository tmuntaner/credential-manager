use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

/// A short lived token for one cluster behind Rancher.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RancherCredential {
    pub token: String,
    pub token_id: String,
    /// Rancher does not report it, so it is the creation time plus the requested ttl.
    #[serde(with = "time::serde::rfc3339")]
    pub expiry: OffsetDateTime,
    pub cluster_name: String,
    pub cluster_id: String,
    /// The Kubernetes API of the cluster, proxied by Rancher.
    pub server_url: String,
    /// PEM, the certificate authority of Rancher.
    pub ca: String,
}

impl RancherCredential {
    /// Whether the token is still good at `now`, with `margin` to spare.
    pub fn is_valid_at(&self, now: OffsetDateTime, margin: Duration) -> bool {
        self.expiry - margin > now
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::format_description::well_known::Rfc3339;

    fn at(time: &str) -> OffsetDateTime {
        OffsetDateTime::parse(time, &Rfc3339).unwrap()
    }

    fn credential(expiry: OffsetDateTime) -> RancherCredential {
        RancherCredential {
            token: "t".to_string(),
            token_id: "i".to_string(),
            expiry,
            cluster_name: "x".to_string(),
            cluster_id: "c".to_string(),
            server_url: "https://r".to_string(),
            ca: "ca".to_string(),
        }
    }

    #[test]
    fn a_token_is_valid_until_shortly_before_it_expires() {
        let now = at("2026-01-01T12:00:00Z");
        let margin = Duration::seconds(60);

        assert!(credential(at("2026-01-01T13:00:00Z")).is_valid_at(now, margin));
        assert!(!credential(at("2026-01-01T12:00:30Z")).is_valid_at(now, margin));
        assert!(!credential(at("2026-01-01T11:00:00Z")).is_valid_at(now, margin));
    }

    #[test]
    fn the_expiry_is_stored_as_rfc_3339() {
        let json = serde_json::to_value(credential(at("2026-01-01T13:00:00Z"))).unwrap();

        assert_eq!(json["expiry"], "2026-01-01T13:00:00Z");
        let back: RancherCredential = serde_json::from_value(json).unwrap();
        assert_eq!(back.expiry, at("2026-01-01T13:00:00Z"));
    }

    #[test]
    fn an_expiry_that_cannot_be_read_is_not_a_credential() {
        let json = serde_json::json!({
            "token": "t", "tokenId": "i", "expiry": "tomorrow", "clusterName": "x",
            "clusterId": "c", "serverUrl": "https://r", "ca": "ca",
        });

        assert!(serde_json::from_value::<RancherCredential>(json).is_err());
    }
}
