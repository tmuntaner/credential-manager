# c9s - Cloud Credential Manager

## Support Matrix

| Identity Provider | MFA Support                     | Cloud Provider                                 |
|-------------------|---------------------------------|------------------------------------------------|
| Okta              | webauthn (U2F), Okta Push, TOTP | AWS (Okta's AWS SAML and AWS SSO applications) |

## Configuration

The config file for `c9s` is located at ` ~/.config/c9s/settings.toml`, but you can use `c9s config` to manage your configuration.

### Okta

#### AWS

To add configuration for Okta's AWS application, you'll need to provide an `--app-url` argument pointing to your AWS application and a `--username` argument specifying your Okta username.

```bash
c9s config aws okta-aws --app-url https://domain.okta.com/home/amazon_aws/0on2crzseasdZUctZ358/272 --username username@domain.com
```

**Note:**

To set `okta-aws` as your default SSO provider for AWS, run the following:

```bash
c9s config aws defaults --sso-provider okta-aws
```

#### AWS SSO

To add configuration for Okta's AWS SSO application, you'll need to provide an `--app-url` argument pointing to your AWS SSO application, `--region` specifying AWS SSO's region, and a `--username` argument specifying your Okta username.

```bash
c9s config aws okta-aws-sso --app-url https://domain.okta.com/home/amazon_aws/0on2crzseasdZUctZ358/272 --username username@domain.com --region eu-central-1
```

**Note:**

To set `okta-aws-sso` as your default SSO provider for AWS, run the following:

```bash
c9s config aws defaults --sso-provider okta-aws-sso
```

## Retrieve Credentials

### Okta

#### AWS Application

**Defaults:**

If you added configuration, you can run `c9s creds aws` and it will use your first provided configuration as default values.

```bash
c9s creds aws
```

**Override Defaults:**

If you want to override the default values, you can provide them as arguments in the command:

```bash
c9s creds aws --app-url YOUR_APP_URL --username USERNAME --sso-provider okta-aws
```

**Specify `role-arn`:**

If you want to only retrieve credentials for a single AWS role, provide a value for the `--role-arn` argument:

```bash
c9s creds aws --role-arn YOUR_ROLE_ARN
```

**AWS CLI Profile:**

**Note:** Some environments may not work well with stdout prompts to notify a user to plug in a hardware security key. Please see the alternative profile below to help in such scenarios.

1. Think of a new AWS CLI profile name. Replace `my-new-profile-name` with it in the following steps.
2. Not the role arn you want to assume as. Replace `my-role-arn` in the `credential_process` with this arn in the next step.
3. Add a new profile to you AWS CLI config file `~/.aws/config`:
    ```text
    [profile my-new-profile]
    region = eu-west-1
    credential_process = sh -c "c9s creds aws --sso-provider okta-aws --role-arn my-role-arn --output aws-profile 2> /dev/tty"
    ```
4. Verify the profile with `aws sts get-caller-identity`
    ```bash
    aws --profile my-new-profile sts get-caller-identity
    ```

**Alternate AWS CLI Profile:**

This alternate profile uses desktop notifications instead of a progress bar to alert a user to input a hardware security key.

 ```text
 [profile my-new-profile]
 region = eu-west-1
 credential_process = sh -c "c9s creds aws --sso-provider okta-aws --role-arn my-role-arn --output aws-profile --desktop-notifications 2> /dev/null"
 ```

#### AWS SSO Application

**Defaults:**

If you added configuration, you can run `c9s creds aws` and it will use your first provided configuration as default values.

```bash
c9s creds aws
```

**Override Defaults:**

If you want to override the default values, you can provide them as arguments in the command:

```bash
c9s creds aws --app-url YOUR_APP_URL --username USERNAME --sso-provider okta-aws-sso
```

**Specify `role-arn`:**

If you want to only retrieve credentials for a single role, provide a value for the `--role-arn` argument:

```bash
c9s creds okta-aws-sso --role-arn YOUR_ROLE_ARN
```

**AWS CLI Profile:**

**Note:** Some environments may not work well with stdout prompts to notify a user to plug in a hardware security key. Please see the alternative profile below to help in such scenarios.

1. Think of a new AWS CLI profile name. Replace `my-new-profile-name` with it in the following steps.
2. Not the role arn you want to assume as. Replace `my-role-arn` in the `credential_process` with this arn in the next step.
3. Add a new profile to you AWS CLI config file `~/.aws/config`:
    ```text
    [profile my-new-profile]
    region = eu-west-1
    credential_process = sh -c "c9s creds okta-aws-sso --sso-provider okta-aws-sso --role-arn my-role-arn --output aws-profile 2> /dev/tty"
    ```
4. Verify the profile with `aws sts get-caller-identity`
    ```bash
    aws --profile my-new-profile sts get-caller-identity
    ```

**Alternate AWS CLI Profile:**

This alternate profile uses desktop notifications instead of a progress bar to alert a user to input a hardware security key.

 ```text
 [profile my-new-profile]
 region = eu-west-1
 credential_process = sh -c "c9s creds aws --sso-provider okta-aws-sso --role-arn my-role-arn --output aws-profile --desktop-notifications 2> /dev/null"
 ```
