# Hardware-Backed Credential Encryption

For user convenience, `c9s` will persist data to the OS keyring as a cache.
This is to avoid having the user enter their credentials every time they need a new secret.
The problem is that the OS keyring is not always secure and other processes can access those secrets.

To solve this, `c9s` uses hardware-backed credential encryption with a security key like a YubiKey.
The security key uses the FIDO2 CTAP2 `hmac-secret` extension to generate a derived secret with a set salt.
Because the derived secret is deterministic,
we use that secret to encrypt secrets with AES-256-GCM-Encrypt before we send credentials to the OS keyring.

This means that secrets backed by this encryption can only be used with the enrolled security key.
If the security key is not present, `c9s` will not be able to decrypt the secret,
and the user will need to enter the credentials again.

## Security Key Loss

`c9s` considers credentials saved to the OS keychain to be a convenience and not essential.
It will not take extra efforts to ensure data integrity if a security key was lost.
If it cannot decrypt a secret without a chance of recovery, the user can just enter their password again.

It's planned to eventually offer multiple security-keys to reduce the risk of data loss.

## FIDO2 hmac-secret Extension

Rather than saving a specific credential to a security key,
`c9s` can treat it like a deterministic secret generator.
It achieves this by:

1. `c9s` provides the security-key a challenge 32-byte random salt.
2. The user presses the button on their security-key to prove presence.
3. The security-key combines the salt with its internal master key using HMAC-SHA256.
4. The security-key hands back the resulting 32-byte secret (deterministic).

The only way to retrieve that secret is with the 32-byte random salt and the security-key.
If other processes and attackers do not have access to the security-key and the salt,
they'll be unable to access the key to decrypt `c9s` adds to the keychain.

The benefit is that the encryption key does not live on the OS file-system, nor does a user have to maintain one.
For users with security keys, this reduces the potential attack surface, while aiding convenience.

## Encryption Prefixes

`c9s` prefixes base64 encoded secret data with the following potential prefixes in plain text to know how the data was encrypted.

1. `c9s-yk1`: yubikey version 1 (current).

## Protecting Secrets in Memory

Every secret in memory has the following protections:

* Redacted `std::fmt::Debug` output.
* Uses [zeroize](https://docs.rs/zeroize/latest/zeroize/) to securely zero its memory when dropped.

## Encryption (wrap)

`c9s` uses AES-256-GCM-Encrypt to encrypt any relevant secrets. It does this by:

1. It retrieves the derived key from the security-key.
2. It generates a unique 12-byte nonce using the [getrandom](https://github.com/rust-random/getrandom) crate.
3. In the Additional Authenticated Data (AAD), `c9s` adds the following information:
    * username
    * service: e.g., `SUSEID`
    * application: `c9s`
4. It encrypts the payload with the derived key and AES-256-GCM.
5. It base64 encodes the result and adds the prefix `c9s-yk1` to identify the string as encrypted.
6. It sends the result to the OS keychain.

## Decryption (unwrap)

1. It retrieves the derived key from the security-key.
2. `c9s` retrieves the secret from the keychain and checks the encryption prefix to verify if it was encrypted.
3. It base64 decodes the secret.
4. It splits the payload, separating the payload from the encrypted data.
5. It calls AES-256-GCM-Decrypt to decrypt the data with the derived key.
