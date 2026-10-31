use crate::domain::models::prompt_mode::PromptMode;
use crate::domain::models::secret::SafeSecret;
use crate::domain::models::user_interaction::{ChoicePrompt, ConfirmPrompt, SecretPrompt};
use crate::domain::ports::notifier::Notifier;
use crate::domain::ports::user_interaction::{InteractionError, UserInteraction};
use crate::domain::services::fallback_interaction::FallbackInteraction;
use crate::domain::services::fallback_notifier::FallbackNotifier;
use crate::outbound::prompt::desktop_notice::DesktopNotice;
use crate::outbound::prompt::pinentry::{PinentryPrompt, TtyOptions};
use crate::outbound::prompt::terminal::TerminalPrompt;
use async_trait::async_trait;
use std::ffi::OsStr;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

const PINENTRY_NAMES: &[&str] = &[
    "pinentry-gnome3",
    "pinentry-qt",
    "pinentry-gtk-2",
    "pinentry-mac",
    "pinentry-fltk",
    "pinentry-efl",
];

/// Where Homebrew installs pinentry on Apple Silicon and Intel.
/// If started outside a shell, c9s may lack it in `PATH`.
const MACOS_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    Windows,
    Other,
}

impl Os {
    fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Other
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromptKind {
    /// Prompt through a pinentry program.
    Pinentry(PinentryProgram),
    /// Prompt through a terminal.
    Terminal,
    /// Tried to prompt through a pinentry program, but it was unavailable.
    /// It gives a string to the user with help install the correct program.
    NoGui(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinentryProgram {
    pub path: PathBuf,
    /// If the user explicitly named this pinentry program in the config or ENV.
    pub explicit: bool,
    /// If the pinentry program uses a terminal instead of a popup.
    pub terminal_only: bool,
}

impl PinentryProgram {
    fn new(path: PathBuf, explicit: bool) -> Self {
        // the pinentry binary may be a symlink.
        let real = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());

        // get the name of the pinentry from the file path.
        let name = real.file_name().and_then(OsStr::to_str).unwrap_or_default();

        // Only a hint to pick a popup or the terminal. It is not a security boundary: the
        // program is trusted because the user named it or it is found in the user's own
        // GnuPG configuration or `PATH`.
        // pinentry-curses and pinentry-tty are both terminal only.
        let terminal_only = name.contains("curses") || name.ends_with("-tty");

        Self {
            path: real,
            explicit,
            terminal_only,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PromptEnvironment {
    pub os: Os,
    pub has_display: bool,
    pub pinentry: Option<PinentryProgram>,
}

impl PromptEnvironment {
    /// Reads the process environment and try to find the proper pinentry program.
    /// The program receives secrets, so it is trusted. The order is `C9S_PINENTRY`, the
    /// settings file, `gpg-agent.conf` and then `PATH`.
    pub fn from_process(configured: Option<PathBuf>) -> Self {
        // see if the user explicitly asked for a specific pinentry program
        let explicit = std::env::var_os("C9S_PINENTRY")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or(configured);

        let os = Os::current();

        // get the pinentry program
        // if it's none, it will try to find the GPG agent's pinentry.
        // if it's none and there is no GPG agent pinentry file, it will try to find one in the
        // user's PATH.
        let pinentry = match explicit {
            Some(path) => Some(PinentryProgram::new(path, true)),
            None if os == Os::Windows => None, // windows doesn't have a pinentry program
            None => gpg_agent_pinentry()
                .or_else(|| find_on_path(os))
                .map(|path| PinentryProgram::new(path, false)),
        };

        Self {
            os,
            has_display: match os {
                Os::Linux | Os::Other => env_set("DISPLAY") || env_set("WAYLAND_DISPLAY"),
                Os::MacOs => true,   // Macs should have a display
                Os::Windows => true, // windows should have a display
            },
            pinentry,
        }
    }
}

fn env_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

/// try to get the pinentry program from the GPG agent.
fn gpg_agent_pinentry() -> Option<PathBuf> {
    // get the GPG agent home directory
    let home = std::env::var_os("GNUPGHOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".gnupg")))?;

    // read the GPG agent config file
    let config = std::fs::read_to_string(home.join("gpg-agent.conf")).ok()?;

    // parse the GPG agent config file and try to parse it for a configured pinentry program
    parse_gpg_agent_pinentry(&config).filter(|path| path.is_file())
}

/// Try to parse the GPG agent conf file to find a configured pinentry program
fn parse_gpg_agent_pinentry(config: &str) -> Option<PathBuf> {
    config.lines().find_map(|line| {
        // try to find a line for the pinentry-program
        let value = line.trim().strip_prefix("pinentry-program")?;
        value
            .starts_with(char::is_whitespace)
            .then(|| PathBuf::from(value.trim()))
            .filter(|path| !path.as_os_str().is_empty())
    })
}

/// Tries to find a pinentry within the PATH for an OS
fn find_on_path(os: Os) -> Option<PathBuf> {
    // find all the PATH directories
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();

    // if it's a Mac, extend to add the homebrew bin directories
    if os == Os::MacOs {
        dirs.extend(MACOS_DIRS.iter().map(PathBuf::from));
    }

    // try to find a valid pinentry in the directories
    find_pinentry(&dirs)
}

/// Returns the first pinentry it finds within a list of directories
fn find_pinentry(dirs: &[PathBuf]) -> Option<PathBuf> {
    PINENTRY_NAMES.iter().find_map(|name| {
        dirs.iter()
            .map(|dir| dir.join(name))
            .find(|path| path.is_file())
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifierKind {
    /// Show notices as desktop notifications.
    DesktopNotice,
    /// Print notices on the terminal.
    Terminal,
}

/// Decides how notices are shown, in priority order.
///
/// A popup hides the terminal, so a notice there (e.g. "touch your key") would go unseen. Then a
/// desktop notification goes first and the terminal is the fallback. Otherwise the user sits at
/// the terminal, and a desktop notification would only repeat the line.
pub fn notifiers(mode: PromptMode, env: &PromptEnvironment) -> Vec<NotifierKind> {
    let has_popup = prompts(mode, env)
        .iter()
        .any(|kind| matches!(kind, PromptKind::Pinentry(p) if !p.terminal_only));

    if has_popup && env.has_display && matches!(env.os, Os::Linux | Os::MacOs) {
        vec![NotifierKind::DesktopNotice, NotifierKind::Terminal]
    } else {
        vec![NotifierKind::Terminal]
    }
}

/// Decides which prompts are asked, in priority order. A forced mode never uses another method.
pub fn prompts(mode: PromptMode, env: &PromptEnvironment) -> Vec<PromptKind> {
    match mode {
        PromptMode::Terminal => vec![PromptKind::Terminal],
        PromptMode::Gui => match &env.pinentry {
            Some(pinentry) if pinentry.explicit || !pinentry.terminal_only => {
                vec![PromptKind::Pinentry(pinentry.clone())]
            }
            _ => vec![PromptKind::NoGui(no_gui_hint(env.os))],
        },
        PromptMode::Auto => {
            let mut prompts = Vec::with_capacity(2);
            match &env.pinentry {
                Some(pinentry) if pinentry.explicit => {
                    prompts.push(PromptKind::Pinentry(pinentry.clone()))
                }
                Some(pinentry) if !pinentry.terminal_only && env.has_display => {
                    prompts.push(PromptKind::Pinentry(pinentry.clone()))
                }
                // ignore terminal only pinentries. We can default to the actual terminal.
                _ => {}
            }
            prompts.push(PromptKind::Terminal);
            prompts
        }
    }
}

fn no_gui_hint(os: Os) -> &'static str {
    match os {
        Os::MacOs => "no pinentry program found; install pinentry-mac (`brew install pinentry-mac`), set C9S_PINENTRY, or use `--prompt terminal`",
        Os::Windows => "popups are not supported on Windows yet; use `--prompt terminal`",
        Os::Linux | Os::Other => "no pinentry program found; install pinentry-gnome3 or pinentry-qt, set C9S_PINENTRY, or use `--prompt terminal`",
    }
}

/// Instantiates a prompt.
pub fn build(plan: &[PromptKind]) -> FallbackInteraction {
    let adapters = plan
        .iter()
        .map(|kind| match kind {
            // Like gpg-agent, always name the terminal: popups ignore it, and a wrapper that falls back to
            // curses needs it.
            PromptKind::Pinentry(pinentry) => {
                Arc::new(PinentryPrompt::new(&pinentry.path).with_tty(tty_options()))
                    as Arc<dyn UserInteraction>
            }
            PromptKind::Terminal => Arc::new(TerminalPrompt) as Arc<dyn UserInteraction>,
            PromptKind::NoGui(hint) => Arc::new(NoGui(hint)) as Arc<dyn UserInteraction>,
        })
        .collect();
    FallbackInteraction::new(adapters)
}

/// Instantiates a notifier.
pub fn build_notifier(plan: &[NotifierKind]) -> FallbackNotifier {
    let notifiers = plan
        .iter()
        .map(|kind| match kind {
            NotifierKind::DesktopNotice => Arc::new(DesktopNotice) as Arc<dyn Notifier>,
            NotifierKind::Terminal => Arc::new(TerminalPrompt) as Arc<dyn Notifier>,
        })
        .collect();
    FallbackNotifier::new(notifiers)
}

/// Get the tty options from ENV
fn tty_options() -> TtyOptions {
    // get the environment variables.
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());

    // try to get build the tty options from ENV
    TtyOptions {
        ttyname: var("GPG_TTY").or_else(stdin_tty_name),
        ttytype: var("TERM"),
        lc_ctype: var("LC_ALL")
            .or_else(|| var("LC_CTYPE"))
            .or_else(|| var("LANG")),
    }
}

fn stdin_tty_name() -> Option<String> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let path = std::fs::read_link("/proc/self/fd/0").ok()?;
    path.starts_with("/dev/")
        .then(|| path.to_str().map(str::to_string))
        .flatten()
}

/// Stands in for a forced popup that does not exist, so the user learns why nothing is shown.
struct NoGui(&'static str);

#[async_trait(?Send)]
impl UserInteraction for NoGui {
    async fn ask_secret(&self, _prompt: SecretPrompt) -> Result<SafeSecret, InteractionError> {
        Err(InteractionError::failed(self.0))
    }

    async fn confirm(&self, _prompt: ConfirmPrompt) -> Result<bool, InteractionError> {
        Err(InteractionError::failed(self.0))
    }

    async fn choose(&self, _prompt: &ChoicePrompt) -> Result<usize, InteractionError> {
        Err(InteractionError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinentry(name: &str, explicit: bool) -> Option<PinentryProgram> {
        Some(PinentryProgram {
            path: PathBuf::from(format!("/usr/bin/{name}")),
            explicit,
            terminal_only: name.contains("curses") || name.ends_with("-tty"),
        })
    }

    fn env(os: Os, display: bool, pinentry: Option<PinentryProgram>) -> PromptEnvironment {
        PromptEnvironment {
            os,
            has_display: display,
            pinentry,
        }
    }

    fn popup(name: &str, explicit: bool) -> PromptKind {
        PromptKind::Pinentry(pinentry(name, explicit).unwrap())
    }

    #[test]
    fn terminal_mode_is_always_only_the_terminal() {
        for e in [
            env(Os::Linux, true, pinentry("pinentry-gnome3", false)),
            env(Os::Linux, true, pinentry("pinentry-gnome3", true)),
            env(Os::MacOs, true, pinentry("pinentry-mac", false)),
            env(Os::Windows, true, None),
        ] {
            assert_eq!(prompts(PromptMode::Terminal, &e), [PromptKind::Terminal]);
        }
    }

    #[test]
    fn auto_prefers_a_popup_and_falls_back_to_the_terminal() {
        let cases = [
            (
                env(Os::Linux, true, pinentry("pinentry-gnome3", false)),
                vec![popup("pinentry-gnome3", false), PromptKind::Terminal],
            ),
            (
                env(Os::MacOs, true, pinentry("pinentry-mac", false)),
                vec![popup("pinentry-mac", false), PromptKind::Terminal],
            ),
            // no display, or ssh without one
            (
                env(Os::Linux, false, pinentry("pinentry-gnome3", false)),
                vec![PromptKind::Terminal],
            ),
            // ssh into a Mac
            (
                env(Os::MacOs, false, pinentry("pinentry-mac", false)),
                vec![PromptKind::Terminal],
            ),
            (env(Os::Linux, true, None), vec![PromptKind::Terminal]),
            (env(Os::Windows, true, None), vec![PromptKind::Terminal]),
            // a terminal pinentry found on its own is no popup
            (
                env(Os::Linux, true, pinentry("pinentry-curses", false)),
                vec![PromptKind::Terminal],
            ),
        ];

        for (e, expected) in cases {
            assert_eq!(prompts(PromptMode::Auto, &e), expected, "{e:?}");
        }
    }

    #[test]
    fn auto_uses_a_pinentry_the_user_named() {
        let e = env(Os::Linux, false, pinentry("pinentry-curses", true));

        assert_eq!(
            prompts(PromptMode::Auto, &e),
            [popup("pinentry-curses", true), PromptKind::Terminal]
        );
    }

    #[test]
    fn a_popup_gets_desktop_notices_when_there_is_a_display() {
        use NotifierKind::{DesktopNotice, Terminal};

        let qt = pinentry("pinentry-qt", false);
        let curses = pinentry("pinentry-curses", false);
        let cases = [
            (
                PromptMode::Gui,
                env(Os::Linux, true, qt.clone()),
                vec![DesktopNotice, Terminal],
            ),
            (
                PromptMode::Auto,
                env(Os::Linux, true, qt.clone()),
                vec![DesktopNotice, Terminal],
            ),
            (
                PromptMode::Auto,
                env(Os::MacOs, true, pinentry("pinentry-mac", false)),
                vec![DesktopNotice, Terminal],
            ),
            // an explicit pinentry on a machine without a display
            (
                PromptMode::Gui,
                env(Os::Linux, false, pinentry("pinentry-qt", true)),
                vec![Terminal],
            ),
            // ssh into a Mac
            (
                PromptMode::Auto,
                env(Os::MacOs, false, pinentry("pinentry-mac", false)),
                vec![Terminal],
            ),
            // the user sits at the terminal
            (
                PromptMode::Terminal,
                env(Os::Linux, true, qt.clone()),
                vec![Terminal],
            ),
            (
                PromptMode::Auto,
                env(Os::Linux, true, curses),
                vec![Terminal],
            ),
            (PromptMode::Auto, env(Os::Linux, true, None), vec![Terminal]),
            (PromptMode::Gui, env(Os::Linux, true, None), vec![Terminal]),
            (PromptMode::Auto, env(Os::Windows, true, qt), vec![Terminal]),
        ];

        for (mode, e, expected) in cases {
            assert_eq!(notifiers(mode, &e), expected, "{mode:?} {e:?}");
        }
    }

    #[test]
    fn forced_gui_never_uses_the_terminal() {
        assert_eq!(
            prompts(
                PromptMode::Gui,
                &env(Os::Linux, false, pinentry("pinentry-qt", false))
            ),
            [popup("pinentry-qt", false)]
        );
        assert!(matches!(
            prompts(PromptMode::Gui, &env(Os::Linux, true, None))[..],
            [PromptKind::NoGui(hint)] if hint.contains("pinentry-gnome3")
        ));
        assert!(matches!(
            prompts(PromptMode::Gui, &env(Os::MacOs, true, pinentry("pinentry-tty", false)))[..],
            [PromptKind::NoGui(hint)] if hint.contains("pinentry-mac")
        ));
        assert!(matches!(
            prompts(PromptMode::Gui, &env(Os::Windows, true, None))[..],
            [PromptKind::NoGui(_)]
        ));
    }

    #[tokio::test]
    async fn a_forced_popup_that_does_not_exist_explains_itself() {
        let interaction = build(&[PromptKind::NoGui("install pinentry")]);

        let err = interaction
            .ask_secret(SecretPrompt::new("t", "PIN"))
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "install pinentry");
    }

    #[test]
    fn reads_the_pinentry_of_gpg_agent() {
        let config =
            "# comment\nenable-ssh-support\npinentry-program   /opt/homebrew/bin/pinentry-mac \n";

        assert_eq!(
            parse_gpg_agent_pinentry(config),
            Some(PathBuf::from("/opt/homebrew/bin/pinentry-mac"))
        );
        assert_eq!(parse_gpg_agent_pinentry("pinentry-programx /a"), None);
        assert_eq!(parse_gpg_agent_pinentry("pinentry-program"), None);
    }

    #[test]
    fn finds_only_popup_pinentries() {
        let dir = std::env::temp_dir().join(format!("c9s-pinentry-path-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["pinentry", "pinentry-curses"] {
            std::fs::write(dir.join(name), "").unwrap();
        }
        let dirs = [PathBuf::from("/nonexistent"), dir.clone()];

        let without_popup = find_pinentry(&dirs);
        std::fs::write(dir.join("pinentry-qt"), "").unwrap();
        let with_popup = find_pinentry(&dirs);
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(without_popup, None);
        assert_eq!(with_popup, Some(dir.join("pinentry-qt")));
    }

    #[test]
    fn recognizes_terminal_pinentries_by_name() {
        assert!(PinentryProgram::new(PathBuf::from("/x/pinentry-curses"), false).terminal_only);
        assert!(PinentryProgram::new(PathBuf::from("/x/pinentry-tty"), false).terminal_only);
        assert!(!PinentryProgram::new(PathBuf::from("/x/pinentry-qt"), false).terminal_only);
    }
}
