use super::error::{FieldProblem, InvalidField, Problem};
use super::fields::{
    allow_insecure_localhost, check_client_id, check_mfa, check_name, check_optional_username,
    check_region, check_url, check_username,
};
use super::input::{AwsAppInput, AwsAppKind, IdpInput, RancherInput};
use crate::domain::models::settings::AppConfig;

pub(super) struct ValidIdp {
    pub(super) name: String,
    pub(super) url: String,
    pub(super) username: String,
}

pub(super) struct ValidAws {
    pub(super) app_url: String,
    pub(super) username: Option<String>,
    pub(super) idp: String,
    pub(super) region: Option<String>,
}

pub(super) struct ValidRancher {
    pub(super) url: String,
    pub(super) client_id: String,
    pub(super) username: Option<String>,
    pub(super) idp: String,
}

/// The problems found so far in one change, in form order.
#[derive(Default)]
struct Problems(Vec<FieldProblem>);

impl Problems {
    /// Runs one check of `fields` and keeps the problem, if any, under `field`.
    fn keep<T>(&mut self, field: InvalidField, result: Result<T, String>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(message) => {
                self.0.push(FieldProblem::message(field, message));
                None
            }
        }
    }

    /// The identity provider an app logs in with: chosen, well-formed and configured.
    fn keep_idp(&mut self, settings: &AppConfig, input: &str) -> Option<String> {
        let name = match input.trim() {
            "" => Err("Choose an identity provider.".to_string()),
            name => check_name(name),
        };
        let name = self.keep(InvalidField::Idp, name)?;
        match settings.resolve_idp(&name) {
            Ok(idp) => Some(idp.name().to_string()),
            Err(_) => {
                self.0.push(FieldProblem {
                    field: InvalidField::Idp,
                    problem: Problem::UnknownIdp(name),
                });
                None
            }
        }
    }

    /// The change is refused: these are the problems.
    fn refuse<T>(self) -> Result<T, Vec<FieldProblem>> {
        Err(self.0)
    }
}

pub(super) fn validate_idp(
    input: &IdpInput,
    security_key: bool,
) -> Result<ValidIdp, Vec<FieldProblem>> {
    let mut problems = Problems::default();
    let name = problems.keep(InvalidField::Name, check_name(&input.name));
    let url = problems.keep(
        InvalidField::Url,
        check_url(&input.url, allow_insecure_localhost()),
    );
    let username = problems.keep(InvalidField::Username, check_username(&input.username));
    let mfa = problems.keep(InvalidField::Mfa, check_mfa(input.mfa, security_key));
    match (name, url, username, mfa) {
        (Some(name), Some(url), Some(username), Some(_)) => Ok(ValidIdp {
            name,
            url,
            username,
        }),
        _ => problems.refuse(),
    }
}

pub(super) fn validate_aws(
    settings: &AppConfig,
    input: &AwsAppInput,
    kind: &AwsAppKind,
    security_key: bool,
) -> Result<ValidAws, Vec<FieldProblem>> {
    let mut problems = Problems::default();
    let app_url = problems.keep(
        InvalidField::Url,
        check_url(&input.app_url, allow_insecure_localhost()),
    );
    let region = match kind {
        AwsAppKind::Aws => Some(None),
        AwsAppKind::AwsSso { region } => problems
            .keep(InvalidField::Region, check_region(region))
            .map(Some),
    };
    let username = problems.keep(
        InvalidField::Username,
        check_optional_username(input.username.as_deref()),
    );
    let mfa = problems.keep(InvalidField::Mfa, check_mfa(input.mfa, security_key));
    let idp = problems.keep_idp(settings, &input.idp);
    match (app_url, region, username, mfa, idp) {
        (Some(app_url), Some(region), Some(username), Some(_), Some(idp)) => Ok(ValidAws {
            app_url,
            username,
            idp,
            region,
        }),
        _ => problems.refuse(),
    }
}

pub(super) fn validate_rancher(
    settings: &AppConfig,
    input: &RancherInput,
    security_key: bool,
) -> Result<ValidRancher, Vec<FieldProblem>> {
    let mut problems = Problems::default();
    let url = problems.keep(
        InvalidField::Url,
        check_url(&input.url, allow_insecure_localhost()),
    );
    let client_id = problems.keep(InvalidField::ClientId, check_client_id(&input.client_id));
    let username = problems.keep(
        InvalidField::Username,
        check_optional_username(input.username.as_deref()),
    );
    let mfa = problems.keep(InvalidField::Mfa, check_mfa(input.mfa, security_key));
    let idp = problems.keep_idp(settings, &input.idp);
    match (url, client_id, username, mfa, idp) {
        (Some(url), Some(client_id), Some(username), Some(_), Some(idp)) => Ok(ValidRancher {
            url,
            client_id,
            username,
            idp,
        }),
        _ => problems.refuse(),
    }
}
