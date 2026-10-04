//! Remembered authentications (docs/design.md, section 9.2).

use std::time::{Duration, Instant, SystemTime};

use crate::Authentication;

/// How long an authentication is remembered by default.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// A process, identified so that a reused pid isn't mistaken for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId {
    pub pid: u32,
    /// The process's start time, in clock ticks since boot.
    pub start_time: u64,
}

/// Who an authentication is remembered for: the process that asked, or for
/// polkit's `unix-session` subjects, a login session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Holder {
    Process(ProcessId),
    Session(String),
}

/// A remembered authentication: polkit's temporary authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remembered {
    /// Identifies it, e.g. for polkit's `RevokeTemporaryAuthorizationById`.
    pub id: String,
    pub holder: Holder,
    /// The login session of the agent the user authenticated through, which
    /// lists and revokes it.
    pub scope: Option<String>,
    pub auth: Authentication,
    pub obtained: SystemTime,
    expires: Instant,
    lifetime: Duration,
}

impl Remembered {
    /// When it expires, by the wall clock.
    pub fn expires_at(&self) -> SystemTime {
        self.obtained + self.lifetime
    }
}

/// The authentications remembered for each subject, as polkit's temporary
/// authorizations: one per subject and action, until it expires.
pub struct AuthStore {
    entries: Vec<Remembered>,
    lifetime: Duration,
    next_id: u64,
}

impl Default for AuthStore {
    fn default() -> Self {
        Self::new(DEFAULT_LIFETIME)
    }
}

impl AuthStore {
    pub fn new(lifetime: Duration) -> Self {
        Self {
            entries: Vec::new(),
            lifetime,
            next_id: 0,
        }
    }

    /// How long authentications are remembered.
    pub fn lifetime(&self) -> Duration {
        self.lifetime
    }

    fn expire(&mut self, now: Instant) {
        self.entries.retain(|e| e.expires > now);
    }

    /// Remembers a successful authentication for `holder`, replacing any
    /// remembered for the same action, and returns its id.
    pub fn remember(
        &mut self,
        holder: Holder,
        scope: Option<String>,
        auth: Authentication,
        now: Instant,
    ) -> String {
        let auth = auth.remembered();
        self.entries
            .retain(|e| !(e.holder == holder && e.auth.action == auth.action));
        let id = format!("tmpauthz{}", self.next_id);
        self.next_id += 1;
        self.entries.push(Remembered {
            id: id.clone(),
            holder,
            scope,
            auth,
            obtained: SystemTime::now(),
            expires: now + self.lifetime,
            lifetime: self.lifetime,
        });
        id
    }

    /// The authentications remembered that `matches` accepts, and that
    /// haven't expired.
    pub fn lookup(
        &mut self,
        now: Instant,
        matches: impl Fn(&Remembered) -> bool,
    ) -> Vec<Remembered> {
        self.expire(now);
        self.entries
            .iter()
            .filter(|e| matches(e))
            .cloned()
            .collect()
    }

    /// The authentications remembered through agents of `scope`'s session
    /// that haven't expired.
    pub fn in_scope(&mut self, scope: &str, now: Instant) -> Vec<Remembered> {
        self.expire(now);
        self.entries
            .iter()
            .filter(|e| e.scope.as_deref() == Some(scope))
            .cloned()
            .collect()
    }

    /// The authentication with this id, if it's still remembered.
    pub fn get(&mut self, id: &str, now: Instant) -> Option<Remembered> {
        self.expire(now);
        self.entries.iter().find(|e| e.id == id).cloned()
    }

    /// Forgets the authentication with this id, returning whether there was
    /// one.
    pub fn revoke(&mut self, id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        self.entries.len() != before
    }

    /// Forgets everything remembered through agents of `scope`'s session,
    /// returning how many there were.
    pub fn revoke_scope(&mut self, scope: &str) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.scope.as_deref() != Some(scope));
        before - self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_uid;

    fn auth(action: &str, resource: &str) -> Authentication {
        Authentication {
            user: 0,
            fresh: true,
            action: action.into(),
            resource: entity_uid("System", resource).unwrap(),
        }
    }

    const P: ProcessId = ProcessId {
        pid: 10,
        start_time: 1,
    };

    #[test]
    fn expiry_and_holders() {
        let mut store = AuthStore::new(Duration::from_secs(60));
        let now = Instant::now();
        let reused = ProcessId {
            pid: 10,
            start_time: 2,
        };
        store.remember(Holder::Process(P), None, auth("org.example.a", "x"), now);

        let found = |store: &mut AuthStore, holder: Holder, at| {
            store
                .lookup(at, |r| r.holder == holder)
                .into_iter()
                .map(|r| r.auth)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            found(&mut store, Holder::Process(P), now),
            [auth("org.example.a", "x").remembered()]
        );
        assert!(found(&mut store, Holder::Process(reused), now).is_empty());
        assert!(found(&mut store, Holder::Session("3".into()), now).is_empty());
        assert!(
            found(
                &mut store,
                Holder::Process(P),
                now + Duration::from_secs(61)
            )
            .is_empty()
        );
    }

    #[test]
    fn one_per_action() {
        let mut store = AuthStore::default();
        let now = Instant::now();
        let first = store.remember(Holder::Process(P), None, auth("org.example.a", "x"), now);
        let second = store.remember(Holder::Process(P), None, auth("org.example.a", "y"), now);
        store.remember(Holder::Process(P), None, auth("org.example.b", "x"), now);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("tmpauthz0", "tmpauthz1")
        );
        let ids: Vec<String> = store
            .lookup(now, |_| true)
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids, ["tmpauthz1", "tmpauthz2"]);
    }

    #[test]
    fn listing_and_revoking() {
        let mut store = AuthStore::default();
        let now = Instant::now();
        let a = store.remember(
            Holder::Process(P),
            Some("3".into()),
            auth("org.example.a", "x"),
            now,
        );
        let b = store.remember(
            Holder::Process(P),
            Some("3".into()),
            auth("org.example.b", "x"),
            now,
        );
        store.remember(
            Holder::Process(P),
            Some("4".into()),
            auth("org.example.c", "x"),
            now,
        );

        let listed: Vec<String> = store.in_scope("3", now).into_iter().map(|r| r.id).collect();
        assert_eq!(listed, [a.clone(), b.clone()]);
        assert!(store.revoke(&a));
        assert!(!store.revoke(&a));
        assert_eq!(store.revoke_scope("3"), 1);
        assert!(store.in_scope("3", now).is_empty());
        assert_eq!(store.lookup(now, |_| true).len(), 1);
    }
}
