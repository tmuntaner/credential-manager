use indicatif::{ProgressBar, ProgressStyle};
use rusoto_core::request::HttpClient;
use rusoto_core::{Region, RusotoError};
use rusoto_credential::StaticProvider;
use rusoto_sts::{
    AssumeRoleWithSAMLError, AssumeRoleWithSAMLRequest, AssumeRoleWithSAMLResponse, Sts, StsClient,
};

#[derive(Clone)]
pub struct SamlAWSRole {
    pub principal_arn: String,
    pub role_arn: String,
}

pub struct AwsCredential {
    pub secret_access_key: String,
    pub access_key_id: String,
    pub role_arn: String,
    pub session_token: String,
}

struct StsFuture {
    request: Result<AssumeRoleWithSAMLResponse, RusotoError<AssumeRoleWithSAMLError>>,
    role_arn: String,
}

pub async fn generate_sts_credentials(
    saml_response: String,
    saml_aws_credentials: Vec<SamlAWSRole>,
) -> Vec<AwsCredential> {
    let tasks: Vec<_> = saml_aws_credentials
        .into_iter()
        .map(|credential| {
            let req = AssumeRoleWithSAMLRequest {
                duration_seconds: Some(60 * 60),
                policy: None,
                policy_arns: None,
                principal_arn: credential.principal_arn,
                role_arn: credential.role_arn,
                saml_assertion: saml_response.clone(),
            };

            tokio::spawn(async {
                let provider = StaticProvider::new_minimal(String::from(""), String::from(""));
                let client =
                    StsClient::new_with(HttpClient::new().unwrap(), provider, Region::default());

                StsFuture {
                    role_arn: req.role_arn.clone(),
                    request: client.assume_role_with_saml(req).await,
                }
            })
        })
        .collect();

    let mut aws_credentials = vec![];

    let style = ProgressStyle::default_bar()
        .template("Generating Credentials:\n[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
        .progress_chars("##-");
    let progress = ProgressBar::new(tasks.len() as u64);
    progress.set_style(style);

    for task in tasks {
        let future = task.await.unwrap();
        let response = future.request.unwrap();
        let credentials = response.credentials.unwrap();
        aws_credentials.push(AwsCredential {
            secret_access_key: credentials.secret_access_key,
            access_key_id: credentials.access_key_id,
            role_arn: future.role_arn.clone(),
            session_token: credentials.session_token,
        });

        progress.set_message(future.role_arn);
        progress.inc(1);
    }
    progress.finish_with_message("done");

    aws_credentials
}
