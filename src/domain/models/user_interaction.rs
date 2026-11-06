/// What a secret is, so a graphical prompt can configure its input (keyboard, autofill hints) to match.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretKind {
    /// A password, or any other secret that is not one of the kinds below.
    #[default]
    Password,
    /// A one-time code of an authenticator app.
    Totp,
    /// The PIN of a security key.
    Pin,
}

/// A request for the user to provide a secret (password, PIN, TOTP code).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SecretPrompt {
    /// Title for graphical prompts if available.
    pub title: String,
    /// Explanation of the request.
    pub description: Option<String>,
    /// A short label of the input, e.g. "Password" or "Security key PIN".
    pub label: String,
    /// An error from a previous attempt, e.g. "Wrong PIN, 2 attempts left."
    pub error: Option<String>,
    /// What is asked for.
    pub kind: SecretKind,
}

impl SecretPrompt {
    pub fn new(title: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            description: None,
            label: label.into(),
            error: None,
            kind: SecretKind::default(),
        }
    }

    pub fn with_kind(mut self, kind: SecretKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }
}

/// A request for the user to pick one of several options, answered with the index.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChoicePrompt {
    /// Title for graphical prompts if available.
    pub title: String,
    /// Explanation of the request.
    pub description: String,
    /// The options the user should choose from.
    pub options: Vec<String>,
}

impl ChoicePrompt {
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        options: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            title: title.into(),
            description: description.into(),
            options: options.into_iter().map(Into::into).collect(),
        }
    }
}

/// A request for the user to pick either yes or no.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConfirmPrompt {
    /// Title for graphical prompts if available.
    pub title: String,
    /// Explanation of the request.
    pub description: String,
    /// The label for the positive answer.
    pub ok_label: Option<String>,
    /// The label for the negative answer.
    pub cancel_label: Option<String>,
}

impl ConfirmPrompt {
    pub fn new(title: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            description: description.into(),
            ok_label: None,
            cancel_label: None,
        }
    }

    pub fn with_labels(mut self, ok: impl Into<String>, cancel: impl Into<String>) -> Self {
        self.ok_label = Some(ok.into());
        self.cancel_label = Some(cancel.into());
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeLevel {
    Info,
    Warning,
    Error,
}

/// A message to the user.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct UserNotice {
    pub level: NoticeLevel,
    pub message: String,
    /// Something is waiting for the user to act on the notice, e.g., to touch a security key. The user can give
    /// up waiting, which a notifier reports through [`Notifier::dismissed`](crate::domain::ports::notifier::Notifier::dismissed).
    pub awaiting_action: bool,
}

impl UserNotice {
    pub fn new(level: NoticeLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            awaiting_action: false,
        }
    }

    /// Marks that something waits for the user to act, and that the user can cancel the wait.
    pub fn awaiting_action(mut self) -> Self {
        self.awaiting_action = true;
        self
    }

    /// An [`NoticeLevel::Info`] notice.
    pub fn info(message: impl Into<String>) -> Self {
        Self::new(NoticeLevel::Info, message)
    }

    /// A [`NoticeLevel::Warning`] notice.
    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(NoticeLevel::Warning, message)
    }

    /// An [`NoticeLevel::Error`] notice.
    pub fn error(message: impl Into<String>) -> Self {
        Self::new(NoticeLevel::Error, message)
    }
}
