//! Remembered authentications (docs/design.md, section 9.2).

use std::time::{Duration, Instant};

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

struct Remembered {
    process: ProcessId,
    auth: Authentication,
    expires: Instant,
}

/// The authentications remembered for each subject process.
pub struct AuthStore {
    entries: Vec<Remembered>,
    lifetime: Duration,
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
        }
    }

    /// Remembers a successful authentication by `process`'s subject.
    pub fn remember(&mut self, process: ProcessId, auth: Authentication, now: Instant) {
        self.entries
            .retain(|e| !(e.process == process && e.auth == auth.clone().remembered()));
        self.entries.push(Remembered {
            process,
            auth: auth.remembered(),
            expires: now + self.lifetime,
        });
    }

    /// The authentications remembered for `process` that haven't expired.
    pub fn lookup(&mut self, process: ProcessId, now: Instant) -> Vec<Authentication> {
        self.entries.retain(|e| e.expires > now);
        self.entries
            .iter()
            .filter(|e| e.process == process)
            .map(|e| e.auth.clone())
            .collect()
    }

    /// Forgets everything remembered for `process`, e.g. when it exits.
    pub fn forget(&mut self, process: ProcessId) {
        self.entries.retain(|e| e.process != process);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_uid;

    #[test]
    fn expiry_and_processes() {
        let mut store = AuthStore::new(Duration::from_secs(60));
        let now = Instant::now();
        let p = ProcessId {
            pid: 10,
            start_time: 1,
        };
        let reused = ProcessId {
            pid: 10,
            start_time: 2,
        };
        let auth = Authentication {
            user: 0,
            fresh: true,
            action: "org.example.a".into(),
            resource: entity_uid("System", "local").unwrap(),
        };
        store.remember(p, auth.clone(), now);

        assert_eq!(store.lookup(p, now), [auth.clone().remembered()]);
        assert!(store.lookup(reused, now).is_empty());
        assert!(store.lookup(p, now + Duration::from_secs(61)).is_empty());

        store.remember(p, auth, now);
        store.forget(p);
        assert!(store.lookup(p, now).is_empty());
    }
}
