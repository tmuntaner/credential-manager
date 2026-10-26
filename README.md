# c9s – Cloud Credential Manager

## Support Matrix

| Identity Provider | MFA Support    | Targets                                                                    |
|-------------------|----------------|----------------------------------------------------------------------------|
| authentik         | TOTP, WebAuthn | AWS (the AWS SAML application and the AWS IAM Identity Center application) |
| authentik         | TOTP, WebAuthn | Rancher (a token for a downstream cluster)                                 |

## Configuration

The config file for `c9s` is located at `~/.config/c9s/settings.toml`,
but you can use `c9s config` to manage your configuration.

### Global Settings

#### Keyring Storage

`c9s` stores passwords and cached secrets in your OS keyring (Secret Service on Linux, Keychain on macOS, Credential Manager on Windows).
It's enabled by default, but you can disable or re-enable it:

```bash
c9s config global use-keyring --enabled false
```

#### YubiKey Secret Wrapping (Hardware-Backed Envelope Encryption)

For more information, please see our documentation on [credential encryption](docs/credential_encryption.md).

`c9s` supports wrapping secrets stored in the OS keyring with AES-256-GCM.
It uses an encryption key derived from a physical YubiKey touch via FIDO2 `hmac-secret` (Linux and macOS).
This is not supported on Windows.

- The derived key is cached in zeroized memory. It exists only in the process lifetime and requires a physical touch per invocation.
- Once a YubiKey is enrolled, it will always wrap IdP credentials.
- If you want to wrap other secrets, you can. It will just require one physical touch per invocation.

**Enroll a YubiKey:**

```bash
c9s config global yubikey enroll [--rp-id localhost]
```

**Check Status:**

```bash
c9s config global yubikey status
```

**Configure Protection for Cached Session Secrets (non IdP secrets):**

```bash
c9s config global yubikey wrap-cached --enabled true
```

**Disable YubiKey Wrapping:**

```bash
c9s config global yubikey disable
```

#### Default Identity Provider

Set the default identity provider for targets that do not explicitly specify `--idp`:

```bash
c9s config global default-idp --name work
```

### Identity Providers

To make it easier to manage multiple targets, you can set a shared identity provider.
The identity provider takes all the information you need to authenticate to your idp: username, url, and mfa type.

```bash
c9s config idp --name work --url https://id.example.com --username username@example.com --mfa totp --default
```

If you add `--default`, it becomes the default idp for all targets.

#### Authentik

When configuring targets, you should be aware what the `--app-url` is for.
`--app-url` is the URL of the **SAML application's** `.../sso/binding/init/` endpoint in Authentik.
You can find this by right-clicking the application tile and copying its URL.
The following is an example of such an `--app-url`:

```text
https://id.example.com/application/saml/<app-slug>/sso/binding/init/
```

The `<app-slug>` is the name of the application in Authentik.

### Rancher

The Rancher target works with an OIDC application, such as in Authentik.
It requires the `--url` of the Rancher server and the `--client-id` from the OIDC application.

Rancher logs in through an identity provider (see above); `--client-id` is the client id of the OIDC application in
authentik that Rancher is configured with. `--username` and `--mfa` are optional overrides of the identity provider's.

```bash
c9s config rancher --url https://rancher.example.com --client-id rancher [--idp work] [--username username@example.com]
```

### AWS Application (IAM roles)

Provide the `--app-url` of your AWS application.
The username comes from the identity provider.
If you wish to provide an override, set `--username` as well.

```bash
c9s config aws app --app-url https://id.example.com/application/saml/my-aws-app/sso/binding/init/ [--idp work] [--username username@example.com]
```

### AWS IAM Identity Center Application

Provide the `--app-url` of your AWS IAM Identity Center application and the `--region` of your Identity Center instance.
The username comes from the identity provider.
If you wish to provide an override, set `--username` as well.

```bash
c9s config aws sso --app-url https://id.example.com/application/saml/my-aws-sso-app/sso/binding/init/ --region eu-central-1 [--idp work] [--username username@example.com]
```

## Retrieve Credentials

### Rancher

`--cluster` is the display name of the cluster in Rancher.
The token lives for `--ttl`. It's one hour (`1h`) by default, but you can also set it for other times: `30m`, `1d`, etc.
`c9s` will reuse valid tokens from its keyring.

**Kubeconfig:**

```bash
c9s creds rancher --cluster my-cluster > ~/.kube/my-cluster.yaml
kubectl --kubeconfig ~/.kube/my-cluster.yaml get namespaces
```

**kubectl credential plugin:**

`--output exec-credential` prints an `ExecCredential`, so kubectl can ask `c9s` for a token whenever it needs one.

```yaml
users:
- name: my-cluster
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: sh
      args: ["-c", "c9s creds rancher --cluster my-cluster --output exec-credential 2> /dev/tty"]
      interactiveMode: Never
```

### AWS Application

**Defaults:**

If you want to override the default values, you can provide them as arguments in the command:

```bash
c9s creds aws --app-url YOUR_APP_URL --username USERNAME --app-type aws
```

If you want to only retrieve credentials for a single AWS role, provide a value for the `--role-arn` argument:

```bash
c9s creds aws --role-arn YOUR_ROLE_ARN
```

**AWS CLI Profile:**

**Note:**
Some environments may not work well with stdout prompts.
It may make it difficult to know when to plug in a hardware security key.

1. Think of a new AWS CLI profile name. Replace `my-new-profile` with it in the following steps.
2. Note the role arn you want to assume. Replace `my-role-arn` in the `credential_process` with this arn in the next step.
3. Add a new profile to your AWS CLI config file `~/.aws/config`:
    ```text
    [profile my-new-profile]
    region = eu-west-1
    credential_process = sh -c "c9s creds aws --app-type aws --role-arn my-role-arn --output aws-profile 2> /dev/tty"
    ```
4. Verify the profile with `aws sts get-caller-identity`
    ```bash
    aws --profile my-new-profile sts get-caller-identity
    ```

### AWS IAM Identity Center Application

**Defaults:**

If you want to override the default values, you can provide them as arguments in the command:

```bash
c9s creds aws --app-url YOUR_APP_URL --username USERNAME --app-type aws-sso
```

**Specify `role-arn`:**

If you want to only retrieve credentials for a single role, provide a value for the `--role-arn` argument:

```bash
c9s creds aws --app-type aws-sso --role-arn YOUR_ROLE_ARN
```

**AWS CLI Profile:**

**Note:**
Some environments may not work well with stdout prompts.
It may make it difficult to know when to plug in a hardware security key.

1. Think of a new AWS CLI profile name. Replace `my-new-profile` with it in the following steps.
2. Note the role arn you want to assume. Replace `my-role-arn` in the `credential_process` with this arn in the next step.
3. Add a new profile to your AWS CLI config file `~/.aws/config`:
    ```text
    [profile my-new-profile]
    region = eu-west-1
    credential_process = sh -c "c9s creds aws --app-type aws-sso --role-arn my-role-arn --output aws-profile 2> /dev/tty"
    ```
4. Verify the profile with `aws sts get-caller-identity`
    ```bash
    aws --profile my-new-profile sts get-caller-identity
    ```
