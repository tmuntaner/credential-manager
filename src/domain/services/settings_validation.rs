use url::{Host, Url};

/// Longest accepted url size.
const MAX_URL: usize = 2048;

/// Longest accepted name size.
const MAX_NAME: usize = 64;

/// Longest accepted username size.
const MAX_USERNAME: usize = 256;

/// Longest accepted client id size.
const MAX_CLIENT_ID: usize = 256;

/// Whether a URL may be a plain insecure `http` without encryption.
/// We only allow this for debug builds.
pub fn allow_insecure_localhost() -> bool {
    cfg!(debug_assertions)
}

/// Checks if the URL is valid and returns a cleaned version of it.
pub fn check_url(input: &str, allow_localhost_http: bool) -> Result<String, String> {
    let input = input.trim();

    // don't allow empty values
    if input.is_empty() {
        return Err("Enter a web address, like https://id.example.com".into());
    }

    // don't allow values which are too big
    if input.len() > MAX_URL {
        return Err("This web address is too long.".into());
    }

    // don't allow invalid values
    if input.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("A web address cannot contain spaces or line breaks.".into());
    }

    // parse the URL and ensure it's valid.
    let url = Url::parse(input).map_err(|_| {
        "This is not a web address. Start with https://, like https://id.example.com".to_string()
    })?;

    // disallow username and passwords in URLs.
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Remove the user name and password from the web address. You are asked for them when you log in.".into());
    }

    // ensure there is a hostname
    let host = url
        .host()
        .ok_or_else(|| "This web address has no host name.".to_string())?;

    // validate the scheme
    match url.scheme() {
        "https" => {}
        "http" if allow_localhost_http && is_localhost(&host) => {}
        "http" => {
            return Err(
                "The web address must start with https:// so the connection is private.".into(),
            )
        }
        _ => return Err("The web address must start with https://".into()),
    }

    // compile the clean url to a string and remove trailing slash
    let mut cleaned = url.to_string();
    if url.path() == "/" && url.query().is_none() && url.fragment().is_none() {
        cleaned.pop();
    }

    Ok(cleaned)
}

fn is_localhost(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
    }
}

/// Checks if the name is valid.
pub fn check_name(input: &str) -> Result<String, String> {
    let name = input.trim();

    // ensure that the name isn't empty
    if name.is_empty() {
        return Err("Enter a name, like work".into());
    }

    // ensure that the length isn't too long
    if name.chars().count() > MAX_NAME {
        return Err(format!("Use at most {MAX_NAME} characters."));
    }

    // ensure that there are no invalid characters
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '));
    if !ok {
        return Err("Use only letters, numbers, spaces, dashes, dots and underscores.".into());
    }

    Ok(name.to_string())
}

/// Checks if a username is valid
pub fn check_username(input: &str) -> Result<String, String> {
    let username = input.trim();

    // ensure that username isn't empty
    if username.is_empty() {
        return Err("Enter your user name.".into());
    }

    // ensure that the length isn't too long
    if username.chars().count() > MAX_USERNAME {
        return Err("This user name is too long.".into());
    }

    // ensure that there are no invalid characters in the username
    if username.chars().any(char::is_control) {
        return Err("A user name cannot contain line breaks or other control characters.".into());
    }

    Ok(username.to_string())
}

/// Checks the optional username, validating it if there is a value.
pub fn check_optional_username(input: Option<&str>) -> Result<Option<String>, String> {
    match input.map(str::trim) {
        None | Some("") => Ok(None),
        Some(username) => check_username(username).map(Some),
    }
}

/// Checks the OAuth client id to ensure it's valid.
pub fn check_client_id(input: &str) -> Result<String, String> {
    let client_id = input.trim();

    // ensure the value isn't empty
    if client_id.is_empty() {
        return Err("Enter the client ID of the Rancher application, like rancher.".into());
    }

    // ensure the length isn't too long
    if client_id.chars().count() > MAX_CLIENT_ID {
        return Err("This client ID is too long.".into());
    }

    // ensure there are no invalid characters.
    if client_id
        .chars()
        .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(
            "A client ID cannot contain spaces, line breaks or other control characters.".into(),
        );
    }

    Ok(client_id.to_string())
}

/// Checks the AWS region to ensure it's valid.
pub fn check_region(input: &str) -> Result<String, String> {
    let region = input.trim();

    // split the region into multiple parts, e.g., ['eu', 'central', '1']
    let parts: Vec<&str> = region.split('-').collect();

    // make sure it fits the region format
    let ok = parts.len() >= 3
        && parts[..parts.len() - 1]
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase()))
        && parts
            .last()
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
    if !ok {
        return Err("Enter an AWS region, like eu-west-1.".into());
    }

    Ok(region.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(input: &str) -> Result<String, String> {
        check_url(input, false)
    }

    #[test]
    fn a_url_is_trimmed_and_a_bare_host_loses_its_slash() {
        assert_eq!(
            url("  https://id.example.com/ \n").unwrap(),
            "https://id.example.com"
        );
        assert_eq!(
            url("https://id.example.com/application/saml/aws/sso/binding/init/").unwrap(),
            "https://id.example.com/application/saml/aws/sso/binding/init/"
        );
    }

    #[test]
    fn only_https_is_accepted() {
        for bad in [
            "http://id.example.com",
            "ftp://id.example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,hi",
            "//id.example.com",
            "id.example.com",
            "https://",
            "",
            "   ",
        ] {
            assert!(url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn plain_http_is_only_for_localhost_and_only_when_allowed() {
        assert!(check_url("http://localhost:9000", true).is_ok());
        assert!(check_url("http://127.0.0.1:9000", true).is_ok());
        assert!(check_url("http://[::1]:9000", true).is_ok());
        assert!(check_url("http://localhost:9000", false).is_err());
        assert!(check_url("http://id.example.com", true).is_err());
        // A look-alike host is not localhost.
        assert!(check_url("http://localhost.evil.example", true).is_err());
        assert!(check_url("http://localhost@evil.example", true).is_err());
    }

    #[test]
    fn credentials_in_the_url_are_refused() {
        assert!(url("https://user:secret@id.example.com").is_err());
        assert!(url("https://user@id.example.com").is_err());
        assert!(url("https://:secret@id.example.com").is_err());
    }

    #[test]
    fn whitespace_and_control_characters_inside_are_refused() {
        assert!(url("https://id.example.com/a b").is_err());
        assert!(url("https://id.example.com/a\nb").is_err());
        assert!(url("https://id.exam\tple.com").is_err());
        assert!(url(&format!("https://id.example.com/{}", "a".repeat(2100))).is_err());
    }

    #[test]
    fn names_are_plain() {
        assert_eq!(check_name(" work ").unwrap(), "work");
        assert!(check_name("").is_err());
        assert!(check_name("a/b").is_err());
        assert!(check_name("a\nb").is_err());
        assert!(check_name("x\"=y").is_err());
        assert!(check_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn usernames_are_not_empty_or_multiline() {
        assert_eq!(
            check_username(" me@example.com ").unwrap(),
            "me@example.com"
        );
        assert!(check_username("  ").is_err());
        assert!(check_username("me\nroot").is_err());
    }

    #[test]
    fn regions_look_like_regions() {
        for ok in ["eu-west-1", "us-east-2", "us-gov-west-1", "ap-southeast-4"] {
            assert!(check_region(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "eu",
            "eu-west",
            "EU-WEST-1",
            "eu-west-x",
            "eu_west_1",
            "eu-west-1; rm",
        ] {
            assert!(check_region(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_empty_username_override_is_no_override() {
        assert_eq!(check_optional_username(None).unwrap(), None);
        assert_eq!(check_optional_username(Some("  ")).unwrap(), None);
        assert_eq!(
            check_optional_username(Some(" me ")).unwrap().as_deref(),
            Some("me")
        );
        assert!(check_optional_username(Some("me\nroot")).is_err());
    }

    #[test]
    fn client_ids_are_one_plain_word() {
        assert_eq!(check_client_id(" rancher ").unwrap(), "rancher");
        assert_eq!(check_client_id("a1B2-c3_d.e").unwrap(), "a1B2-c3_d.e");
        for bad in ["", "  ", "ran cher", "ran\ncher", "ran\u{7}cher"] {
            assert!(check_client_id(bad).is_err(), "{bad:?}");
        }
        assert!(check_client_id(&"a".repeat(257)).is_err());
    }
}
