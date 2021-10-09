# c9s - Cloud Credential Manager

## Support Matrix

| Identity Provider | MFA Support | Cloud Provider  |
|---|---|---|
| Okta | webauthn (U2F) | AWS (Okta's AWS SAML and AWS SSO applications) |

## Configuration

The config file for `c9s` is located at ` ~/.config/c9s/settings.toml`, but you can use `c9s config` to manage your configuration.

### Okta

#### AWS

To add configuration for Okta's AWS application, you'll need to provide an `--app-url` argument pointing to your AWS application and a `--username` argument specifying your Okta username.

```bash
c9s config add okta-aws --app-url https://domain.okta.com/home/amazon_aws/0on2crzseasdZUctZ358/272 --username username@domain.com
```

#### AWS SSO

To add configuration for Okta's AWS SSO application, you'll need to provide an `--app-url` argument pointing to your AWS SSO application, `--region` specifying AWS SSO's region, and a `--username` argument specifying your Okta username.

```bash
c9s config add okta-aws-sso --app-url https://domain.okta.com/home/amazon_aws/0on2crzseasdZUctZ358/272 --username username@domain.com --region eu-central-1
```

## Retrieve Credentials

### Okta

#### AWS Credentials

**Defaults:**

If you added configuration, you can run `c9s creds okta-aws` and it will use your first provided configuration as default values.

```bash
c9s creds okta-aws
```

**Override Defaults:**

If you want to override the default values, you can provide them as arguments in the command:

```bash
c9s creds okta-aws --app-url YOUR_APP_URL --username USERNAME
```

**Specify `role-arn`:**

If you want to only retrieve credentials for a single role, provide a value for the `--role-arn` argument:

```bash
c9s creds okta-aws --role-arn YOUR_ROLE_ARN
```

#### AWS SSO Credentials

**Defaults:**

If you added configuration, you can run `c9s creds okta-aws-sso` and it will use your first provided configuration as default values.

```bash
c9s creds okta-aws-sso
```

**Override Defaults:**

If you want to override the default values, you can provide them as arguments in the command:

```bash
c9s creds okta-aws-sso --app-url YOUR_APP_URL --username USERNAME
```

**Specify `role-arn`:**

If you want to only retrieve credentials for a single role, provide a value for the `--role-arn` argument:

```bash
c9s creds okta-aws-sso --role-arn YOUR_ROLE_ARN
```
