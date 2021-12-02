use crate::http::api_client::{AcceptType, ApiClient};
use crate::okta::saml_parsers::OktaAwsSsoSamlParser;
use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::collections::HashMap;
use url::Url;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    token: String,
}

struct WorkflowStartResponse {
    org_id: String,
    auth_code: String,
}

struct TrySamlResponse {
    saml: String,
    destination: String,
}

pub struct SsoPortalLogin {
    client: ApiClient,
}

impl SsoPortalLogin {
    /// Generates a new [`AwsCredentials`] object.
    pub fn new() -> Result<SsoPortalLogin> {
        let client = ApiClient::new()?;
        Ok(SsoPortalLogin { client })
    }

    pub async fn run(
        &self,
        app_url: String,
        session_token: String,
        portal_url: String,
    ) -> Result<String> {
        let try_saml_response = self.try_saml(app_url, session_token).await?;
        let workflow_start = self
            .workflow_start(try_saml_response.saml, try_saml_response.destination)
            .await?;
        let token_response = self
            .token_response(portal_url, workflow_start.auth_code, workflow_start.org_id)
            .await?;

        Ok(token_response.token)
    }

    async fn workflow_start(
        &self,
        saml_response: String,
        saml_destination: String,
    ) -> Result<WorkflowStartResponse> {
        let mut form: HashMap<String, String> = HashMap::new();
        form.insert(String::from("SAMLResponse"), saml_response);
        form.insert(String::from("RelayState"), String::from(""));

        let response = self
            .client
            .post_form(saml_destination.as_str(), &form, AcceptType::Html)
            .await?;

        let hash_query: HashMap<_, _> = response.url().query_pairs().into_owned().collect();

        // url is in the form of "org-id.awsapps.com" and we want the org-id from it
        let org_id = response
            .url()
            .host_str()
            .ok_or_else(|| anyhow!("could not get host"))?
            .to_string()
            .split('.')
            .next()
            .ok_or_else(|| anyhow!("could not get org-id"))?
            .to_string();
        let auth_code = hash_query
            .get("workflowResultHandle")
            .ok_or_else(|| anyhow!("could not get auth code"))?
            .to_owned();

        Ok(WorkflowStartResponse { org_id, auth_code })
    }

    async fn try_saml(&self, app_url: String, session_token: String) -> Result<TrySamlResponse> {
        let mut params = HashMap::new();
        params.insert(String::from("sessionToken"), session_token);

        let response = self
            .client
            .get(app_url, Some(params), None, AcceptType::Html)
            .await?;
        let body = response.text().await?;

        let saml_response = OktaAwsSsoSamlParser::new(body)?;
        let destination = saml_response.destination()?;

        Ok(TrySamlResponse {
            destination,
            saml: saml_response.raw_saml_response(),
        })
    }

    async fn token_response(
        &self,
        base_url: String,
        auth_code: String,
        org_id: String,
    ) -> Result<TokenResponse> {
        let mut token_url = Url::parse(base_url.as_str())?;
        token_url.set_path("/auth/sso-token");

        let mut form: HashMap<String, String> = HashMap::new();
        form.insert(String::from("authCode"), auth_code);
        form.insert(String::from("orgId"), org_id);

        let response = self
            .client
            .post_form(token_url.as_str(), &form, AcceptType::Json)
            .await?;
        let body = response.text().await?;
        let response: TokenResponse = serde_json::from_str(body.as_str())?;

        Ok(response)
    }
}
