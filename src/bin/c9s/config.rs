use crate::utils::true_or_false;
use anyhow::anyhow;
use anyhow::Result;
use base::models::mfa::MfaSelection;
use c9s::domain::models::idp::IdpType;
use c9s::domain::models::settings::{AppConfig, AwsHost, AwsSsoHost, Idp, RancherHost};
use clap::Parser;

#[derive(Parser)]
pub struct Config {
    #[clap(subcommand)]
    sub_command: ConfigSubCommand,
}

#[derive(Parser)]
enum ConfigSubCommand {
    Idp(ConfigIdp),
    Aws(ConfigAws),
    Rancher(ConfigRancher),
    Global(ConfigGlobal),
}

#[derive(Parser)]
/// Adds an identity provider, or updates the one with the same name
struct ConfigIdp {
    #[clap(required = true, long)]
    name: String,
    #[clap(long, value_enum, default_value_t)]
    r#type: IdpType,
    /// The url of the instance, e.g. https://id.example.com
    #[clap(required = true, long)]
    url: String,
    #[clap(required = true, short, long)]
    username: String,
    #[clap(short, long)]
    mfa: Option<MfaSelection>,
    /// Use it for the apps that name no identity provider
    #[clap(long)]
    default: bool,
}

#[derive(Parser)]
/// Adds a Rancher, or updates the one with the same url
struct ConfigRancher {
    #[clap(required = true, long)]
    url: String,
    #[clap(required = true, long)]
    client_id: String,
    /// The identity provider to log in with, defaults to the default one
    #[clap(long)]
    idp: Option<String>,
    /// Overrides the username of the identity provider
    #[clap(short, long)]
    username: Option<String>,
    /// Overrides the MFA selection of the identity provider
    #[clap(short, long)]
    mfa: Option<MfaSelection>,
}

#[derive(Parser)]
struct ConfigAws {
    #[clap(subcommand)]
    sub_command: ConfigAwsSubCommand,
}

#[derive(Parser)]
enum ConfigAwsSubCommand {
    App(ConfigAwsApp),
    Sso(ConfigAwsSso),
}

#[derive(Parser)]
struct ConfigAwsApp {
    #[clap(required = true, long)]
    app_url: String,
    /// The identity provider to log in with, defaults to the default one
    #[clap(long)]
    idp: Option<String>,
    /// Overrides the username of the identity provider
    #[clap(short, long)]
    username: Option<String>,
    /// Overrides the MFA selection of the identity provider
    #[clap(short, long)]
    mfa: Option<MfaSelection>,
}

#[derive(Parser)]
struct ConfigAwsSso {
    #[clap(required = true, long)]
    app_url: String,
    /// The identity provider to log in with, defaults to the default one
    #[clap(long)]
    idp: Option<String>,
    /// Overrides the username of the identity provider
    #[clap(short, long)]
    username: Option<String>,
    #[clap(required = true, short, long)]
    region: String,
    /// Overrides the MFA selection of the identity provider
    #[clap(short, long)]
    mfa: Option<MfaSelection>,
}

#[derive(Parser)]
struct ConfigGlobal {
    #[clap(subcommand)]
    sub_command: ConfigGlobalSubCommand,
}

#[derive(Parser)]
enum ConfigGlobalSubCommand {
    UseKeyring(ConfigGlobalUseKeyRing),
    DefaultIdp(ConfigGlobalDefaultIdp),
}

#[derive(Parser)]
/// The identity provider for the apps that name none
struct ConfigGlobalDefaultIdp {
    #[clap(required = true, long)]
    name: String,
}

#[derive(Parser)]
/// Whether c9s should use a keyring service.
struct ConfigGlobalUseKeyRing {
    /// Accepted values: "true" or "false"
    #[clap(long, value_parser = true_or_false)]
    enabled: bool,
}

impl Config {
    pub fn run(&self, settings: &mut AppConfig) -> Result<()> {
        match &self.sub_command {
            ConfigSubCommand::Idp(val) => val.run(settings),
            ConfigSubCommand::Aws(val) => match &val.sub_command {
                ConfigAwsSubCommand::App(val) => val.run(settings),
                ConfigAwsSubCommand::Sso(val) => val.run(settings),
            },
            ConfigSubCommand::Rancher(val) => val.run(settings),
            ConfigSubCommand::Global(val) => match &val.sub_command {
                ConfigGlobalSubCommand::UseKeyring(val) => val.run(settings),
                ConfigGlobalSubCommand::DefaultIdp(val) => val.run(settings),
            },
        }
    }
}

/// The username has to come from the app or from the identity provider it resolves to.
fn check_identity(
    settings: &AppConfig,
    idp: Option<&str>,
    username: &Option<String>,
) -> Result<()> {
    if username.is_none() && settings.resolve_idp(idp)?.is_none() {
        return Err(anyhow!(
            "please supply a username, or an identity provider with `--idp` (see `c9s config idp`)"
        ));
    }

    Ok(())
}

impl ConfigIdp {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        let idp = Idp::new(
            self.name.clone(),
            self.r#type,
            self.url.clone(),
            self.username.clone(),
            self.mfa,
        )?;
        settings.add_idp(idp);
        if self.default {
            settings.set_default_idp(&self.name)?;
        }

        Ok(())
    }
}

impl ConfigAwsApp {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        check_identity(settings, self.idp.as_deref(), &self.username)?;
        let host = AwsHost::new(
            self.app_url.clone(),
            self.username.clone(),
            self.idp.clone(),
            self.mfa,
        )?;
        settings.add_aws_host(host);

        Ok(())
    }
}

impl ConfigAwsSso {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        check_identity(settings, self.idp.as_deref(), &self.username)?;
        let host = AwsSsoHost::new(
            self.app_url.clone(),
            self.username.clone(),
            self.idp.clone(),
            self.region.clone(),
            self.mfa,
        )?;
        settings.add_aws_sso_host(host);

        Ok(())
    }
}

impl ConfigRancher {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        if settings.resolve_idp(self.idp.as_deref())?.is_none() {
            return Err(anyhow!(
                "rancher needs an identity provider, run `c9s config idp`"
            ));
        }
        let host = RancherHost::new(
            self.url.clone(),
            self.client_id.clone(),
            self.idp.clone(),
            self.username.clone(),
            self.mfa,
        )?;
        settings.add_rancher_host(host);

        Ok(())
    }
}

impl ConfigGlobalDefaultIdp {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        settings.set_default_idp(&self.name)?;

        Ok(())
    }
}

impl ConfigGlobalUseKeyRing {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        settings.set_use_keyring(self.enabled);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_URL: &str = "https://id.example.com/application/saml/aws/sso/binding/init/";

    fn parse(args: &[&str]) -> Result<Config, clap::Error> {
        let mut argv = vec!["config"];
        argv.extend(args);

        Config::try_parse_from(argv)
    }

    #[test]
    fn parses_the_aws_app_subcommand() {
        let config = parse(&[
            "aws",
            "app",
            "--app-url",
            APP_URL,
            "--idp",
            "suse",
            "--mfa",
            "totp",
        ])
        .unwrap();

        let ConfigSubCommand::Aws(aws) = config.sub_command else {
            panic!("expected the aws subcommand");
        };
        let ConfigAwsSubCommand::App(host) = aws.sub_command else {
            panic!("expected app");
        };
        assert_eq!(host.app_url, APP_URL);
        assert_eq!(host.idp.as_deref(), Some("suse"));
        assert!(host.username.is_none());
        assert_eq!(host.mfa, Some(MfaSelection::Totp));
    }

    #[test]
    fn parses_the_aws_sso_subcommand() {
        let config =
            parse(&["aws", "sso", "--app-url", APP_URL, "-u", "user", "-r", "eu"]).unwrap();

        let ConfigSubCommand::Aws(aws) = config.sub_command else {
            panic!("expected the aws subcommand");
        };
        let ConfigAwsSubCommand::Sso(host) = aws.sub_command else {
            panic!("expected sso");
        };
        assert_eq!(host.region, "eu");
        assert_eq!(host.username.as_deref(), Some("user"));
    }

    #[test]
    fn parses_the_idp_subcommand() {
        let config = parse(&[
            "idp",
            "--name",
            "suse",
            "--url",
            "https://id.example.com",
            "-u",
            "user",
            "--default",
        ])
        .unwrap();

        let ConfigSubCommand::Idp(idp) = config.sub_command else {
            panic!("expected the idp subcommand");
        };
        assert_eq!(idp.name, "suse");
        assert_eq!(idp.r#type, IdpType::Authentik);
        assert!(idp.default);
        assert!(idp.mfa.is_none());

        assert!(parse(&["idp", "--name", "x", "--url", "u"]).is_err());
        assert!(
            parse(&["idp", "--name", "x", "--url", "u", "-u", "u", "--type", "keycloak"]).is_err()
        );
    }

    #[test]
    fn parses_the_default_idp_subcommand() {
        let config = parse(&["global", "default-idp", "--name", "suse"]).unwrap();

        let ConfigSubCommand::Global(global) = config.sub_command else {
            panic!("expected the global subcommand");
        };
        let ConfigGlobalSubCommand::DefaultIdp(default) = global.sub_command else {
            panic!("expected default-idp");
        };
        assert_eq!(default.name, "suse");
        assert!(parse(&["global", "default-idp"]).is_err());
    }

    #[test]
    fn parses_the_rancher_subcommand() {
        let config = parse(&[
            "rancher",
            "--url",
            "https://rancher.example.com",
            "--client-id",
            "rancher",
        ])
        .unwrap();

        let ConfigSubCommand::Rancher(rancher) = config.sub_command else {
            panic!("expected the rancher subcommand");
        };
        assert_eq!(rancher.client_id, "rancher");
        assert!(rancher.idp.is_none());
        assert!(rancher.username.is_none());
        assert!(rancher.mfa.is_none());

        assert!(parse(&[
            "rancher",
            "--url",
            "u",
            "--client-id",
            "c",
            "--idp",
            "suse",
            "-u",
            "x",
            "-m",
            "totp"
        ])
        .is_ok());
    }

    #[test]
    fn rancher_no_longer_takes_an_issuer() {
        assert!(parse(&[
            "rancher",
            "--url",
            "https://r.example.com",
            "--client-id",
            "c",
            "--issuer",
            "https://id.example.com/",
        ])
        .is_err());
        assert!(parse(&["rancher", "--url", "https://r.example.com"]).is_err());
    }

    #[test]
    fn an_unknown_mfa_is_rejected_while_parsing() {
        assert!(parse(&["rancher", "--url", "u", "--client-id", "c", "-m", "sms"]).is_err());
        assert!(parse(&["rancher", "--url", "u", "--client-id", "c", "-m", "TOTP"]).is_ok());
    }
}
