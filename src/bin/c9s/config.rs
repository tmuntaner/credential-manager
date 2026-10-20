use crate::utils::true_or_false;
use anyhow::Result;
use c9s::settings::{AppConfig, AwsDefaults, AwsHost, AwsSsoHost, SsoProvider};
use clap::Parser;

#[derive(Parser)]
pub struct Config {
    #[clap(subcommand)]
    sub_command: ConfigSubCommand,
}

#[derive(Parser)]
enum ConfigSubCommand {
    Aws(ConfigAws),
    Global(ConfigGlobal),
}

#[derive(Parser)]
struct ConfigAws {
    #[clap(subcommand)]
    sub_command: ConfigAwsSubCommand,
}

#[derive(Parser)]
enum ConfigAwsSubCommand {
    Defaults(ConfigAwsDefaults),
    AuthentikAws(ConfigAwsAuthentikAws),
    AuthentikAwsSso(ConfigAwsAuthentikAwsSso),
}

#[derive(Parser)]
struct ConfigAwsAuthentikAws {
    #[clap(required = true, long)]
    app_url: String,
    #[clap(required = true, short, long)]
    username: String,
    #[clap(short, long)]
    mfa: Option<String>,
}

#[derive(Parser)]
struct ConfigAwsAuthentikAwsSso {
    #[clap(required = true, long)]
    app_url: String,
    #[clap(required = true, short, long)]
    username: String,
    #[clap(required = true, short, long)]
    region: String,
    #[clap(short, long)]
    mfa: Option<String>,
}

#[derive(Parser)]
struct ConfigGlobal {
    #[clap(subcommand)]
    sub_command: ConfigGlobalSubCommand,
}

#[derive(Parser)]
enum ConfigGlobalSubCommand {
    UseKeyring(ConfigGlobalUseKeyRing),
}

#[derive(Parser)]
/// Whether or not c9s should use a keyring service.
struct ConfigGlobalUseKeyRing {
    /// Accepted values: "true" or "false"
    #[clap(long, value_parser = true_or_false)]
    enabled: bool,
}

#[derive(Parser)]
/// Sets the default AWS provider
struct ConfigAwsDefaults {
    #[clap(long, value_enum)]
    sso_provider: SsoProvider,
}

impl Config {
    pub fn run(&self, settings: &mut AppConfig) -> Result<()> {
        match &self.sub_command {
            ConfigSubCommand::Aws(val) => match &val.sub_command {
                ConfigAwsSubCommand::Defaults(val) => val.run(settings),
                ConfigAwsSubCommand::AuthentikAws(val) => val.run(settings),
                ConfigAwsSubCommand::AuthentikAwsSso(val) => val.run(settings),
            },
            ConfigSubCommand::Global(val) => match &val.sub_command {
                ConfigGlobalSubCommand::UseKeyring(val) => val.run(settings),
            },
        }
    }
}

impl ConfigAwsAuthentikAws {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        let host = AwsHost::new(
            self.app_url.clone(),
            self.username.clone(),
            self.mfa.clone(),
        )?;
        settings.add_aws_host(host);
        settings.write_config()?;

        Ok(())
    }
}

impl ConfigAwsAuthentikAwsSso {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        let host = AwsSsoHost::new(
            self.app_url.clone(),
            self.username.clone(),
            self.region.clone(),
            self.mfa.clone(),
        )?;
        settings.add_aws_sso_host(host);
        settings.write_config()?;

        Ok(())
    }
}

impl ConfigGlobalUseKeyRing {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        settings.set_use_keyring(self.enabled);
        settings.write_config()?;

        Ok(())
    }
}

impl ConfigAwsDefaults {
    fn run(&self, settings: &mut AppConfig) -> Result<()> {
        let defaults = AwsDefaults::new(self.sso_provider);

        settings.set_aws_defaults(defaults);
        settings.write_config()?;

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
    fn parses_the_authentik_aws_subcommand() {
        let config = parse(&[
            "aws",
            "authentik-aws",
            "--app-url",
            APP_URL,
            "--username",
            "user@example.com",
            "--mfa",
            "totp",
        ])
        .unwrap();

        let ConfigSubCommand::Aws(aws) = config.sub_command else {
            panic!("expected the aws subcommand");
        };
        let ConfigAwsSubCommand::AuthentikAws(host) = aws.sub_command else {
            panic!("expected authentik-aws");
        };
        assert_eq!(host.app_url, APP_URL);
        assert_eq!(host.username, "user@example.com");
        assert_eq!(host.mfa.as_deref(), Some("totp"));
    }

    #[test]
    fn parses_the_authentik_aws_sso_subcommand() {
        let config = parse(&[
            "aws",
            "authentik-aws-sso",
            "--app-url",
            APP_URL,
            "-u",
            "user",
            "-r",
            "eu-central-1",
        ])
        .unwrap();

        let ConfigSubCommand::Aws(aws) = config.sub_command else {
            panic!("expected the aws subcommand");
        };
        let ConfigAwsSubCommand::AuthentikAwsSso(host) = aws.sub_command else {
            panic!("expected authentik-aws-sso");
        };
        assert_eq!(host.region, "eu-central-1");
    }

    #[test]
    fn the_okta_subcommands_and_flags_are_gone() {
        for args in [
            &["aws", "okta-aws", "--app-url", APP_URL, "--username", "u"][..],
            &[
                "aws",
                "okta-aws-sso",
                "--app-url",
                APP_URL,
                "-u",
                "u",
                "-r",
                "r",
            ],
            &[
                "aws",
                "authentik-aws",
                "--app-url",
                APP_URL,
                "-u",
                "u",
                "--mfa-provider",
                "google",
            ],
        ] {
            assert!(parse(args).is_err(), "{:?}", args);
        }
    }

    #[test]
    fn the_provider_default_takes_the_authentik_names() {
        assert!(parse(&["aws", "defaults", "--sso-provider", "authentik-aws-sso"]).is_ok());
        assert!(parse(&["aws", "defaults", "--sso-provider", "okta-aws"]).is_err());
    }
}
