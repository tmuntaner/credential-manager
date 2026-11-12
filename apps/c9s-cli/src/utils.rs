use c9s::domain::models::prompt_mode::PromptMode;
use c9s::domain::models::settings::AppConfig;
use c9s::domain::ports::notifier::Notifier;
use c9s::domain::ports::user_interaction::UserInteraction;
use c9s::outbound::prompt::select::{build, build_notifier, notifiers, prompts, PromptEnvironment};
use std::sync::Arc;
use std::time::Duration;

/// Selects the best interaction and notifier for the user based on the environment.
pub fn interaction(
    settings: &AppConfig,
    prompt_flag: Option<PromptMode>,
) -> (
    Arc<impl UserInteraction + 'static>,
    Arc<impl Notifier + 'static>,
) {
    let mode = prompt_flag.or(settings.prompt_mode()).unwrap_or_default();
    let env = PromptEnvironment::from_process(settings.pinentry_program());
    (
        Arc::new(build(&prompts(mode, &env))),
        Arc::new(build_notifier(&notifiers(mode, &env))),
    )
}

pub fn true_or_false(s: &str) -> Result<bool, &'static str> {
    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("expected `true` or `false`"),
    }
}

pub fn parse_ttl(value: &str) -> Result<Duration, String> {
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .ok_or("missing unit, use s, m, h or d")?;
    let (number, unit) = value.split_at(split);
    let number: u64 = number.parse().map_err(|_| "expected e.g. 30m, 1h or 1d")?;
    let seconds = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err("unknown unit, use s, m, h or d".to_string()),
    };
    let ttl = Duration::from_secs(number.saturating_mul(seconds));
    if ttl.is_zero() {
        // a ttl of 0 asks Rancher for a token that never expires
        return Err("the ttl must be longer than 0".to_string());
    }

    Ok(ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ttls_and_refuses_one_that_never_expires() {
        assert_eq!(parse_ttl("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_ttl("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_ttl("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_ttl("1d").unwrap(), Duration::from_secs(86400));
        assert!(parse_ttl("0m").is_err());
        assert!(parse_ttl("10").is_err());
        assert!(parse_ttl("h").is_err());
        assert!(parse_ttl("1w").is_err());
    }
}
