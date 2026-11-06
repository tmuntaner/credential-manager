use super::file::{FileBundle, BUNDLE_VERSION};
use crate::domain::models::settings::SettingsBundle;
use crate::domain::ports::bundle::{BundleCodec, BundleError};

/// Writes and reads a [`SettingsBundle`] as TOML.
#[derive(Debug, Default, Clone, Copy)]
pub struct TomlBundleCodec;

impl BundleCodec for TomlBundleCodec {
    fn encode(&self, bundle: &SettingsBundle) -> Result<String, BundleError> {
        let body = toml::to_string(&FileBundle::from(bundle))
            .map_err(|e| BundleError::Invalid(Box::new(e)))?;

        Ok(format!(
            "# c9s onboarding file. It holds no user specific settings.\n{body}"
        ))
    }

    fn decode(&self, text: &str) -> Result<SettingsBundle, BundleError> {
        let file: FileBundle =
            toml::from_str(text).map_err(|e| BundleError::Invalid(Box::new(e)))?;

        if file.version != BUNDLE_VERSION {
            return Err(BundleError::UnsupportedVersion(file.version));
        }

        SettingsBundle::try_from(file).map_err(|e| BundleError::Invalid(Box::new(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::idp::IdpType;
    use crate::domain::models::mfa::MfaSelection;
    use crate::domain::models::settings::{AppConfig, AwsHost, Idp, RancherHost};

    const FIXTURE: &str = include_str!("../../../testdata/bundle.toml");

    fn bundle() -> SettingsBundle {
        let mut config = AppConfig::default();
        config.add_idp(
            Idp::new(
                "corp".into(),
                IdpType::Authentik,
                "https://id.example.com".into(),
                "me@example.com".into(),
                Some(MfaSelection::Totp),
            )
            .unwrap(),
        );
        config.add_aws_host(
            AwsHost::new(
                "https://id.example.com/application/saml/aws/sso/binding/init/".into(),
                None,
                "corp".into(),
                None,
            )
            .unwrap(),
        );
        config.add_rancher_host(
            RancherHost::new(
                "https://rancher.example.com".into(),
                "client".into(),
                "corp".into(),
                None,
                None,
            )
            .unwrap(),
        );

        config.export(&["corp".to_string()]).unwrap()
    }

    #[test]
    fn round_trips() {
        let text = TomlBundleCodec.encode(&bundle()).unwrap();
        let back = TomlBundleCodec.decode(&text).unwrap();

        assert_eq!(back.idps().len(), 1);
        assert_eq!(back.idps()[0].name(), "corp");
        assert_eq!(back.idps()[0].mfa(), Some(MfaSelection::Totp));
        assert_eq!(back.aws_hosts().len(), 1);
        assert_eq!(back.rancher_hosts()[0].client_id(), "client");
    }

    #[test]
    fn has_no_security_settings() {
        let text = TomlBundleCodec.encode(&bundle()).unwrap();

        assert!(!text.contains("username"));
        assert!(!text.contains("global_settings"));
        assert!(!text.contains("yubikey"));
    }

    #[test]
    fn reads_the_fixture() {
        let bundle = TomlBundleCodec.decode(FIXTURE).unwrap();

        assert_eq!(bundle.idps().len(), 1);
        assert_eq!(bundle.aws_sso_hosts().len(), 1);
        assert_eq!(bundle.aws_sso_hosts()[0].region(), "eu-west-1");
    }

    #[test]
    fn refuses_security_settings() {
        let text = "version = 1\n[global_settings]\nuse_keyring = false\n";

        assert!(matches!(
            TomlBundleCodec.decode(text),
            Err(BundleError::Invalid(_))
        ));
    }

    #[test]
    fn refuses_a_settings_file() {
        let text = "[[idps]]\nname = \"a\"\nurl = \"https://a.example.com\"\nusername = \"u\"\n";

        // No version, so it is not a bundle.
        assert!(matches!(
            TomlBundleCodec.decode(text),
            Err(BundleError::Invalid(_))
        ));
    }

    #[test]
    fn refuses_another_version() {
        assert!(matches!(
            TomlBundleCodec.decode("version = 2\n"),
            Err(BundleError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn refuses_an_invalid_value() {
        let text = "version = 1\n[[idps]]\nname = \"a\"\nurl = \"not a url\"\n";

        assert!(matches!(
            TomlBundleCodec.decode(text),
            Err(BundleError::Invalid(_))
        ));
    }
}
