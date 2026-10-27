use crate::domain::models::secret::SafeSecret;
use crate::domain::models::user_interaction::{
    ChoicePrompt, ConfirmPrompt, NoticeLevel, SecretPrompt, UserNotice,
};
use crate::domain::ports::notifier::{Notifier, NotifyError};
use crate::domain::ports::user_interaction::{InteractionError, UserInteraction};
use async_trait::async_trait;
use std::io::{self, BufRead, Write};
use thiserror::Error;

#[derive(Debug, Error)]
enum TerminalError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("that is not a number")]
    UnparsableSelection,

    #[error("that number is not one of the options")]
    InvalidSelection,

    #[error("there are no options to choose from")]
    NoOptions,
}

impl From<TerminalError> for InteractionError {
    fn from(e: TerminalError) -> Self {
        InteractionError::failed(e)
    }
}

/// Prompts the user in the terminal. Output text goes to stderr and answers come from stdin.
#[derive(Debug, Default)]
pub struct TerminalPrompt;

impl TerminalPrompt {
    async fn read_line(&self) -> Result<String, InteractionError> {
        // Reading blocks, so keep it off the async threads.
        tokio::task::spawn_blocking(read_stdin_line)
            .await
            .map_err(InteractionError::failed)?
    }
}

/// Reads one line from stdin and returns the result without a line ending.
fn read_stdin_line() -> Result<String, InteractionError> {
    let _ = io::stderr().flush();
    let mut buffer = String::new();

    let read = io::stdin()
        .lock()
        .read_line(&mut buffer)
        .map_err(TerminalError::from)?;

    // If we get an end of input, the user canceled.
    if read == 0 {
        return Err(InteractionError::Cancelled);
    }

    Ok(buffer.trim_end_matches(['\r', '\n']).to_string())
}

#[async_trait(?Send)]
impl UserInteraction for TerminalPrompt {
    async fn ask_secret(&self, prompt: SecretPrompt) -> Result<SafeSecret, InteractionError> {
        if let Some(error) = &prompt.error {
            eprintln!("{}", display_text(error));
        }
        if let Some(description) = &prompt.description {
            eprintln!("{}", display_text(description));
        }

        let label = format!("{}: ", display_line(&prompt.label));
        let secret = tokio::task::spawn_blocking(move || rpassword::prompt_password(label))
            .await
            .map_err(InteractionError::failed)?
            .map_err(TerminalError::from)?;

        Ok(SafeSecret::new(secret))
    }

    async fn confirm(&self, prompt: ConfirmPrompt) -> Result<bool, InteractionError> {
        eprint!("{} [y/N] ", display_text(&prompt.description));

        Ok(is_yes(&self.read_line().await?))
    }

    async fn choose(&self, prompt: &ChoicePrompt) -> Result<usize, InteractionError> {
        if prompt.options.is_empty() {
            return Err(TerminalError::NoOptions.into());
        }

        eprintln!("{}:", display_text(&prompt.description));
        for (i, option) in prompt.options.iter().enumerate() {
            eprintln!("  {i}) {}", display_line(option));
        }

        // A typo should not end the login, so ask again. Ending the input cancels.
        loop {
            eprint!("Enter a number (0-{}): ", prompt.options.len() - 1);

            match choice(&self.read_line().await?, prompt.options.len()) {
                Ok(index) => return Ok(index),
                Err(e) => eprintln!("Invalid choice: {e}."),
            }
        }
    }
}

#[async_trait(?Send)]
impl Notifier for TerminalPrompt {
    async fn notify(&self, notice: &UserNotice) -> Result<(), NotifyError> {
        match notice.level {
            NoticeLevel::Info => eprintln!("{}", display_text(&notice.message)),
            NoticeLevel::Warning => eprintln!("Warning: {}", display_text(&notice.message)),
            NoticeLevel::Error => eprintln!("Error: {}", display_text(&notice.message)),
        }

        Ok(())
    }
}

/// Text for the terminal without control characters, so that text from an identity provider
/// (device names, messages) cannot move the cursor, clear the screen or fake another prompt.
/// Line breaks and tabs stay.
fn display_text(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect()
}

/// Like `display_text`, for a text that has to stay on a single line.
fn display_line(text: &str) -> String {
    text.chars()
        .filter_map(|c| match c {
            '\n' | '\t' => Some(' '),
            c if c.is_control() => None,
            c => Some(c),
        })
        .collect()
}

/// If the answer to the question is yes. (yes/no question)
fn is_yes(input: &str) -> bool {
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// The index of the user's choice.
fn choice(input: &str, options: usize) -> Result<usize, TerminalError> {
    let index: usize = input
        .trim()
        .parse()
        .map_err(|_| TerminalError::UnparsableSelection)?;

    if index < options {
        Ok(index)
    } else {
        Err(TerminalError::InvalidSelection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_text_drops_control_characters() {
        assert_eq!(display_text("a\x1b[2Jb\rc\x07\u{9b}d"), "a[2Jbcd");
        assert_eq!(display_text("one\ntwo\tx"), "one\ntwo\tx");
    }

    #[test]
    fn display_line_keeps_a_single_line() {
        assert_eq!(display_line("key\nPIN: \x1b[1mx"), "key PIN: [1mx");
    }

    #[test]
    fn accepts_yes_in_any_case() {
        assert!(is_yes("y"));
        assert!(is_yes(" Yes "));
        assert!(is_yes("Y"));
    }

    #[test]
    fn everything_else_is_no() {
        assert!(!is_yes(""));
        assert!(!is_yes("n"));
        assert!(!is_yes("yep"));
    }

    #[test]
    fn picks_the_option_by_its_number() {
        assert_eq!(choice("1", 2).unwrap(), 1);
        assert_eq!(choice(" 0 ", 2).unwrap(), 0);
    }

    #[test]
    fn rejects_what_is_not_a_listed_number() {
        assert!(matches!(
            choice("x", 2),
            Err(TerminalError::UnparsableSelection)
        ));
        assert!(matches!(
            choice("2", 2),
            Err(TerminalError::InvalidSelection)
        ));
    }

    #[test]
    fn errors_keep_their_message() {
        let err = InteractionError::from(TerminalError::InvalidSelection);

        assert_eq!(err.to_string(), "that number is not one of the options");
    }
}
