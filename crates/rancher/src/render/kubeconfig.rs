use crate::domain::models::rancher_credentials::RancherCredential;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::json;
use time::format_description::well_known::Rfc3339;

pub fn kubeconfig(credential: &RancherCredential) -> String {
    let quote = |value: &str| json!(value).to_string();
    let name = quote(&credential.cluster_name);

    format!(
        "apiVersion: v1\n\
         kind: Config\n\
         clusters:\n\
         - name: {name}\n  \
           cluster:\n    \
             server: {server}\n    \
             certificate-authority-data: {ca}\n\
         users:\n\
         - name: {name}\n  \
           user:\n    \
             token: {token}\n\
         contexts:\n\
         - name: {name}\n  \
           context:\n    \
             user: {name}\n    \
             cluster: {name}\n\
         current-context: {name}\n",
        server = quote(&credential.server_url),
        ca = quote(&STANDARD.encode(&credential.ca)),
        token = quote(&credential.token),
    )
}

/// The output of a kubectl credential plugin (`users[].user.exec`).
///
/// The expiry of a credential is at most a few years out, so it can always be written as RFC 3339.
pub fn exec_credential(credential: &RancherCredential) -> String {
    json!({
        "apiVersion": "client.authentication.k8s.io/v1",
        "kind": "ExecCredential",
        "status": {
            "token": credential.token,
            "expirationTimestamp": credential.expiry.format(&Rfc3339).expect("the expiry is a year from 0 to 9999"),
        },
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use time::OffsetDateTime;

    fn credential() -> RancherCredential {
        RancherCredential {
            token: "token-abc:secret".to_string(),
            token_id: "token-abc".to_string(),
            expiry: OffsetDateTime::parse("2026-10-22T16:21:26Z", &Rfc3339).unwrap(),
            cluster_name: "op-prg2-1".to_string(),
            cluster_id: "c-m-j2xw7jk8".to_string(),
            server_url: "https://rancher.example.com/k8s/clusters/c-m-j2xw7jk8".to_string(),
            ca: "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n".to_string(),
        }
    }

    #[test]
    fn the_kubeconfig_is_one_cluster_user_and_context() {
        let kubeconfig = kubeconfig(&credential());

        // JSON is YAML, so the scalars can be checked through a JSON parse of each value.
        assert!(kubeconfig
            .starts_with("apiVersion: v1\nkind: Config\nclusters:\n- name: \"op-prg2-1\"\n"));
        assert!(kubeconfig
            .contains("    server: \"https://rancher.example.com/k8s/clusters/c-m-j2xw7jk8\"\n"));
        let ca = STANDARD.encode(credential().ca);
        assert!(kubeconfig.contains(&format!("    certificate-authority-data: \"{ca}\"\n")));
        assert!(kubeconfig.contains("    token: \"token-abc:secret\"\n"));
        assert!(kubeconfig.contains("    user: \"op-prg2-1\"\n    cluster: \"op-prg2-1\"\n"));
        assert!(kubeconfig.ends_with("current-context: \"op-prg2-1\"\n"));
    }

    #[test]
    fn a_hostile_cluster_name_stays_one_scalar() {
        let mut credential = credential();
        credential.cluster_name = "a\"\nkind: Evil".to_string();

        let kubeconfig = kubeconfig(&credential);
        assert!(kubeconfig.contains("- name: \"a\\\"\\nkind: Evil\"\n"));
        assert_eq!(
            kubeconfig
                .lines()
                .filter(|l| l.starts_with("kind:"))
                .count(),
            1
        );
    }

    #[test]
    fn the_exec_credential_carries_the_token_and_expiry() {
        let value: Value = serde_json::from_str(&exec_credential(&credential())).unwrap();

        assert_eq!(value["apiVersion"], "client.authentication.k8s.io/v1");
        assert_eq!(value["kind"], "ExecCredential");
        assert_eq!(value["status"]["token"], "token-abc:secret");
        assert_eq!(
            value["status"]["expirationTimestamp"],
            "2026-10-22T16:21:26Z"
        );
    }
}
