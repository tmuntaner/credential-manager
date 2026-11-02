use std::fmt;
use time::{Duration, OffsetDateTime};

/// How long to keep a session around.
pub(crate) const SESSION_MAX_AGE: Duration = Duration::hours(8);

/// The session cookies of a logged-in user.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthentikSession {
    /// The value of the `Cookie` header.
    cookies: String,
    created_at: OffsetDateTime,
}

impl AuthentikSession {
    pub fn new(cookies: impl Into<String>, created_at: OffsetDateTime) -> Self {
        Self {
            cookies: cookies.into(),
            created_at,
        }
    }

    /// The value of the `Cookie` header.
    pub fn cookies(&self) -> &str {
        &self.cookies
    }

    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Whether the session is still fresh at a point in time.
    pub(crate) fn is_fresh_at(&self, now: OffsetDateTime) -> bool {
        now >= self.created_at && now - self.created_at < SESSION_MAX_AGE
    }
}

impl fmt::Debug for AuthentikSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthentikSession")
            .field("cookies", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_the_cookies() {
        let session = AuthentikSession::new("authentik_session=abc", OffsetDateTime::UNIX_EPOCH);

        assert!(!format!("{session:?}").contains("abc"));
    }

    #[test]
    fn is_fresh_until_the_max_age() {
        let created = OffsetDateTime::UNIX_EPOCH;
        let session = AuthentikSession::new("c=1", created);

        assert!(session.is_fresh_at(created + Duration::hours(7)));
        assert!(!session.is_fresh_at(created + SESSION_MAX_AGE));
        assert!(!session.is_fresh_at(created - Duration::seconds(1)));
    }
}
