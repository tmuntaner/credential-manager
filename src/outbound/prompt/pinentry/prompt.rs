use crate::domain::models::secret::SafeSecret;
use crate::domain::models::user_interaction::{ChoicePrompt, ConfirmPrompt, SecretPrompt};
use crate::domain::ports::user_interaction::{InteractionError, UserInteraction};
use crate::outbound::prompt::pinentry::assuan::ErrKind;
use crate::outbound::prompt::pinentry::error::PinentryError;
use crate::outbound::prompt::pinentry::models::{Reply, TtyOptions};
use crate::outbound::prompt::pinentry::session::Session;
use async_trait::async_trait;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::process::Command;
use zeroize::Zeroizing;

/// The timeout for a pinentry prompt.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Shows popups with pinentry.
#[derive(Debug, Clone)]
pub struct PinentryPrompt {
    program: PathBuf,
    args: Vec<OsString>,
    tty: Option<TtyOptions>,
    timeout: Duration,
}

impl PinentryPrompt {
    /// Creates a prompt that starts `program` for every question.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            tty: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Tells a pinentry that draws on the terminal which one to use.
    pub fn with_tty(mut self, tty: TtyOptions) -> Self {
        self.tty = Some(tty);
        self
    }

    /// Passes extra arguments to the pinentry program.
    pub fn with_args(mut self, args: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Sets how long a prompt may stay open before pinentry is killed. Defaults to five minutes.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Starts the pinentry program and has `talk` use it. The program is killed when it takes too long.
    async fn run<T>(
        &self,
        talk: impl AsyncFnOnce(&mut Session) -> Result<T, PinentryError>,
    ) -> Result<T, PinentryError> {
        // The program receives the PIN, so make it visible which one was started.
        log::debug!("starting pinentry: {}", self.program.display());

        // starts the pinentry program
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| PinentryError::NotStarted(format!("{}: {e}", self.program.display())))?;

        // build the pinentry session
        let mut session = Session::new(
            child.stdin.take().expect("stdin is piped"),
            child.stdout.take().expect("stdout is piped"),
        );

        // start the session
        let result = tokio::time::timeout(self.timeout, async {
            session.start().await?;
            session.options(self.tty.as_ref()).await?;
            let value = talk(&mut session).await?;
            session.bye().await;
            Ok(value)
        })
        .await;
        drop(session);

        match result {
            Err(_elapsed) => {
                let _ = child.kill().await;
                Err(PinentryError::TimedOut(self.timeout.as_secs()))
            }
            Ok(Err(e)) => {
                let _ = child.kill().await;
                let status = child.wait().await;
                Err(match e {
                    PinentryError::Exited(_) => PinentryError::Exited(describe(status)),
                    e => e,
                })
            }
            Ok(Ok(value)) => {
                let _ = child.wait().await;
                Ok(value)
            }
        }
    }
}

#[async_trait(?Send)]
impl UserInteraction for PinentryPrompt {
    async fn ask_secret(&self, prompt: SecretPrompt) -> Result<SafeSecret, InteractionError> {
        Ok(self
            .run(async |session| {
                session.set("SETTITLE", &prompt.title).await?;
                if let Some(description) = &prompt.description {
                    session.set("SETDESC", description).await?;
                }
                session
                    .set("SETPROMPT", &prompt_label(&prompt.label))
                    .await?;
                if let Some(error) = &prompt.error {
                    session.set("SETERROR", error).await?;
                }

                match session.send("GETPIN", "").await? {
                    Reply::Ok(mut data) => {
                        let pin = String::from_utf8(std::mem::take(&mut *data)).map_err(|e| {
                            let _ = Zeroizing::new(e.into_bytes());
                            PinentryError::NotUtf8
                        })?;
                        Ok(SafeSecret::new(pin))
                    }
                    Reply::Err { code, message } => Err(match ErrKind::of(code) {
                        ErrKind::Cancelled => PinentryError::Cancelled,
                        _ => PinentryError::Command(message),
                    }),
                }
            })
            .await?)
    }

    async fn confirm(&self, prompt: ConfirmPrompt) -> Result<bool, InteractionError> {
        Ok(self
            .run(async |session| {
                session.set("SETTITLE", &prompt.title).await?;
                session.set("SETDESC", &prompt.description).await?;
                session
                    .set("SETOK", prompt.ok_label.as_deref().unwrap_or("Yes"))
                    .await?;
                session
                    .set("SETNOTOK", prompt.cancel_label.as_deref().unwrap_or("No"))
                    .await?;

                match session.send("CONFIRM", "").await? {
                    Reply::Ok(_) => Ok(true),
                    Reply::Err { code, message } => match ErrKind::of(code) {
                        ErrKind::NotConfirmed => Ok(false),
                        ErrKind::Cancelled => Err(PinentryError::Cancelled),
                        ErrKind::Other => Err(PinentryError::Command(message)),
                    },
                }
            })
            .await?)
    }

    async fn choose(&self, _prompt: &ChoicePrompt) -> Result<usize, InteractionError> {
        Err(InteractionError::Unavailable)
    }
}

fn describe(status: io::Result<ExitStatus>) -> String {
    match status {
        Ok(status) => status.to_string(),
        Err(e) => e.to_string(),
    }
}

/// pinentry shows the prompt as is; gpg ends it with a colon, and so do we.
fn prompt_label(label: &str) -> String {
    if label.ends_with(':') {
        label.to_string()
    } else {
        format!("{label}:")
    }
}

#[cfg(test)]
mod label_tests {
    use super::*;

    #[test]
    fn the_label_ends_with_a_colon() {
        assert_eq!(prompt_label("PIN"), "PIN:");
        assert_eq!(prompt_label("PIN:"), "PIN:");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::Path;

    const SCRIPT: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/outbound/prompt/testdata/fake_pinentry.sh"
    );

    /// Runs the fake pinentry in `mode` and records the commands it receives.
    struct Fake {
        dir: tempfile::TempDir,
    }

    impl Fake {
        fn new(_name: &str) -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
            }
        }

        fn log(&self) -> PathBuf {
            self.dir.path().join("commands.log")
        }

        fn prompt(&self, mode: &str) -> PinentryPrompt {
            PinentryPrompt::new("/bin/sh").with_args([
                OsString::from(SCRIPT),
                OsString::from(mode),
                self.log().into_os_string(),
            ])
        }

        fn received(&self) -> Vec<String> {
            std::fs::read_to_string(self.log())
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    fn secret_prompt() -> SecretPrompt {
        SecretPrompt::new("Security key", "PIN")
            .with_description("Touch\nyour key")
            .with_error("Wrong PIN, 2 attempts left.")
    }

    #[tokio::test]
    async fn asks_for_a_secret() {
        let fake = Fake::new("secret");

        let secret = fake.prompt("ok").ask_secret(secret_prompt()).await.unwrap();

        assert_eq!(secret.expose_secret(), "hunter 2");
        assert_eq!(
            fake.received(),
            [
                "OPTION no-grab",
                "SETTITLE Security key",
                "SETDESC Touch%0Ayour key",
                "SETPROMPT PIN:",
                "SETERROR Wrong PIN, 2 attempts left.",
                "GETPIN",
                "BYE",
            ]
        );
    }

    #[tokio::test]
    async fn decodes_the_secret() {
        let fake = Fake::new("escaped");

        let secret = fake
            .prompt("escaped")
            .ask_secret(secret_prompt())
            .await
            .unwrap();

        assert_eq!(secret.expose_secret(), "a%b\nc d+");
    }

    #[tokio::test]
    async fn sends_the_terminal_options() {
        let fake = Fake::new("tty");
        let prompt = fake.prompt("ok").with_tty(TtyOptions {
            ttyname: Some("/dev/pts/3".to_string()),
            ttytype: Some("xterm".to_string()),
            lc_ctype: None,
        });

        prompt
            .ask_secret(SecretPrompt::new("t", "PIN"))
            .await
            .unwrap();

        assert_eq!(
            fake.received()[..3],
            [
                "OPTION no-grab",
                "OPTION ttyname=/dev/pts/3",
                "OPTION ttytype=xterm"
            ]
        );
    }

    #[tokio::test]
    async fn a_cancelled_dialog_is_cancelled() {
        let fake = Fake::new("cancel");

        let err = fake
            .prompt("cancel")
            .ask_secret(secret_prompt())
            .await
            .unwrap_err();

        assert!(matches!(err, InteractionError::Cancelled));
    }

    #[tokio::test]
    async fn confirms() {
        let fake = Fake::new("confirm");

        assert!(fake
            .prompt("ok")
            .confirm(ConfirmPrompt::new("c9s", "Save password?"))
            .await
            .unwrap());
        assert_eq!(
            fake.received(),
            [
                "OPTION no-grab",
                "SETTITLE c9s",
                "SETDESC Save password?",
                "SETOK Yes",
                "SETNOTOK No",
                "CONFIRM",
                "BYE",
            ]
        );
    }

    #[tokio::test]
    async fn no_is_not_an_error() {
        let fake = Fake::new("no");

        let answer = fake
            .prompt("no")
            .confirm(ConfirmPrompt::new("c9s", "Save password?").with_labels("Save", "Skip"))
            .await
            .unwrap();

        assert!(!answer);
        assert!(fake.received().contains(&"SETNOTOK Skip".to_string()));
    }

    #[tokio::test]
    async fn a_cancelled_confirmation_is_cancelled() {
        let fake = Fake::new("confirm-cancel");

        let err = fake
            .prompt("cancel")
            .confirm(ConfirmPrompt::new("c9s", "Save password?"))
            .await
            .unwrap_err();

        assert!(matches!(err, InteractionError::Cancelled));
    }

    #[tokio::test]
    async fn a_missing_program_is_unavailable() {
        let err = PinentryPrompt::new(Path::new("/nonexistent/pinentry"))
            .ask_secret(secret_prompt())
            .await
            .unwrap_err();

        assert!(matches!(err, InteractionError::Unavailable));
    }

    #[tokio::test]
    async fn a_program_without_greeting_is_unavailable() {
        let fake = Fake::new("no-greeting");

        let err = fake
            .prompt("no-greeting")
            .ask_secret(secret_prompt())
            .await
            .unwrap_err();

        assert!(matches!(err, InteractionError::Unavailable));
    }

    #[tokio::test]
    async fn a_crash_after_the_dialog_opened_is_a_failure() {
        let fake = Fake::new("crash");

        let err = fake
            .prompt("crash")
            .ask_secret(secret_prompt())
            .await
            .unwrap_err();

        assert!(matches!(err, InteractionError::Failed(_)));
        assert!(err.to_string().contains("exited unexpectedly"), "{err}");
        assert!(err.to_string().contains('3'), "{err}");
    }

    #[tokio::test]
    async fn a_dialog_that_stays_open_is_killed() {
        let fake = Fake::new("hang");

        let err = fake
            .prompt("hang")
            .with_timeout(Duration::from_millis(200))
            .ask_secret(secret_prompt())
            .await
            .unwrap_err();

        assert!(matches!(err, InteractionError::Failed(_)));
        assert!(err.to_string().contains("did not answer"), "{err}");
    }

    #[tokio::test]
    async fn leaves_choices_to_others() {
        let prompt = PinentryPrompt::new("/nonexistent/pinentry");

        assert!(matches!(
            prompt.choose(&ChoicePrompt::new("t", "d", ["a"])).await,
            Err(InteractionError::Unavailable)
        ));
    }
}
