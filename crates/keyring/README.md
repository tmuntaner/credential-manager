# keyring-rs

A library to interact with your keyring on Linux, Mac, or Windows.

![Crates.io](https://img.shields.io/crates/v/tmuntaner-keyring)
![Crates.io](https://img.shields.io/crates/l/tmuntaner-keyring)

## Keyring Backends:

* Windows - [wincred](https://docs.microsoft.com/en-us/windows/win32/api/wincred/)
* Linux - [Secret Service](https://specifications.freedesktop.org/secret-service/latest/)
* Mac - [Security Framework](https://developer.apple.com/documentation/security)

## Example

See [example.rs](./examples/example.rs) for the full file.

```rust
use anyhow::{Result, anyhow};
use keyring::KeyringClient;

fn main() -> Result<()> {
    let username = "tmuntaner";
    let service = "keyring-rs-example";
    let application = "keyring-rs";

    let keyring = KeyringClient::new(username, service, application)?;
    let password = String::from("foobar");

    println!("Setting password {}", password);
    keyring.set_password(password.clone())?;

    let result = keyring.get_password()?.ok_or_else(|| anyhow!("should have a password"))?;
    println!("Returned password: {}", password);
    assert_eq!(password, result);

    Ok(())
}
```
