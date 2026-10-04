//! What the native interface and the polkit-compatible front end share: who
//! the subject is, who may ask about it, and deciding, with an agent's help
//! if the caller allows it.

use std::collections::HashMap;
use std::fs;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use cedarkit_agent_protocol::Identity;
use cedarkit_core::{
    AuthStore, Authentication, Authority, CheckRequest, Decision, Directory, Holder, Nss, Outcome,
    ProcessId, Remembered, Subject, User,
};
use cedarkit_logind::Logind;
use zbus::fdo;
use zbus::names::{BusName, UniqueName};
use zbus::zvariant::{OwnedValue, Value};

use crate::agents::{AgentRequest, Agents};
use crate::cancel::{self, Cancellations, Registration};
use crate::siblings::{Family, family, siblings};

/// A polkit-style subject: a kind, and its details.
pub type SubjectArg = (String, HashMap<String, OwnedValue>);

pub struct State {
    pub authority: Authority,
    pub logind: Option<Arc<Logind>>,
    pub store: Mutex<AuthStore>,
    pub agents: Arc<Agents>,
    pub cancellations: Arc<Cancellations>,
    /// The uid cedarkitd runs as. Callers running as it are as trusted as
    /// root: on the system bus, it is root.
    pub own_uid: u32,
    /// Notified when remembered authentications change, for polkit's
    /// `Changed` signal.
    pub changed: tokio::sync::Notify,
    /// Make up resources from missing polkit details, for mechanisms that
    /// don't pass them yet, such as unpatched systemd.
    pub fill_missing_details: bool,
    /// For each remembered authentication's process, by id, what identifies
    /// its siblings, recorded when it was remembered.
    pub families: Mutex<HashMap<String, Family>>,
}

/// A process, and who it runs as.
#[derive(Debug, Clone, Copy)]
pub struct Process {
    pub id: ProcessId,
    pub uid: u32,
}

/// What a check is for: a process, or for polkit's `unix-session` subjects,
/// a login session.
#[derive(Debug, Clone)]
pub enum Target {
    Process(Process),
    Session { id: String, uid: u32 },
}

impl Target {
    pub fn uid(&self) -> u32 {
        match self {
            Self::Process(p) => p.uid,
            Self::Session { uid, .. } => *uid,
        }
    }

    pub fn process(&self) -> Option<ProcessId> {
        match self {
            Self::Process(p) => Some(p.id),
            Self::Session { .. } => None,
        }
    }

    /// Who an authentication for this target is remembered for.
    pub fn holder(&self) -> Holder {
        match self {
            Self::Process(p) => Holder::Process(p.id),
            Self::Session { id, .. } => Holder::Session(id.clone()),
        }
    }
}

/// A decision, with what polkit reports about it.
pub struct Decided {
    pub outcome: Outcome,
    /// The remembered authentication that allowed it, or that it created.
    pub temporary: Option<String>,
    /// The user dismissed the agent's request.
    pub dismissed: bool,
    /// The challenge would be remembered (polkit's `_keep`).
    pub retained: bool,
}

pub fn invalid(e: impl std::fmt::Display) -> fdo::Error {
    fdo::Error::InvalidArgs(e.to_string())
}

/// Process `pid`, as identified by its start time, and its real uid if not
/// already known.
pub fn process(pid: u32, uid: Option<u32>) -> fdo::Result<Process> {
    let gone = |_| fdo::Error::Failed(format!("process {pid} has exited"));
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(gone)?;
    // The fields after the command name, which may contain anything, start
    // with the state (field 3); the start time is field 22.
    let start_time = stat
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|t| t.parse().ok())
        .ok_or_else(|| fdo::Error::Failed(format!("can't read process {pid}'s start time")))?;
    let uid = match uid {
        Some(uid) => uid,
        None => fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(gone)?
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|ids| ids.split_whitespace().next()?.parse().ok())
            .ok_or_else(|| fdo::Error::Failed(format!("can't read process {pid}'s uid")))?,
    };
    Ok(Process {
        id: ProcessId { pid, start_time },
        uid,
    })
}

/// The pid a pidfd refers to.
fn pidfd_pid(fd: &impl AsFd) -> fdo::Result<u32> {
    let fd = fd.as_fd().as_raw_fd();
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .map_err(|e| fdo::Error::Failed(format!("can't read the pidfd: {e}")))?;
    let pid: i64 = info
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .and_then(|p| p.trim().parse().ok())
        .ok_or_else(|| invalid("not a pidfd"))?;
    u32::try_from(pid).map_err(|_| fdo::Error::Failed("the process has exited".into()))
}

impl State {
    /// Whether a caller running as `uid` is as trusted as cedarkitd.
    pub fn trusted(&self, uid: u32) -> bool {
        uid == 0 || uid == self.own_uid
    }

    /// The process making a D-Bus call, from the bus's credentials.
    pub async fn bus_process(conn: &zbus::Connection, name: BusName<'_>) -> fdo::Result<Process> {
        let creds = fdo::DBusProxy::new(conn)
            .await?
            .get_connection_credentials(name)
            .await?;
        let (Some(pid), Some(uid)) = (creds.process_id(), creds.unix_user_id()) else {
            return Err(fdo::Error::Failed(
                "the bus didn't say who the caller is".into(),
            ));
        };
        process(pid, Some(uid))
    }

    /// The target of a polkit-style subject: `("", {})` for the caller,
    /// `unix-process` (`pidfd`, or `pid` and `start-time`), `unix-session`
    /// (`session-id`) or `system-bus-name` (`name`).
    pub async fn target(
        &self,
        conn: &zbus::Connection,
        caller: &Process,
        (kind, fields): &SubjectArg,
    ) -> fdo::Result<Target> {
        let field = |key: &str| fields.get(key).map(|v| &**v);
        match kind.as_str() {
            "" => Ok(Target::Process(*caller)),
            "unix-process" => {
                let pid = match (field("pidfd"), field("pid")) {
                    (Some(Value::Fd(fd)), _) => pidfd_pid(fd)?,
                    (_, Some(Value::U32(pid))) => *pid,
                    _ => return Err(invalid("unix-process needs a pid")),
                };
                let process = process(pid, None)?;
                match field("start-time") {
                    Some(Value::U64(t)) if *t != 0 && *t != process.id.start_time => {
                        Err(invalid("the process has exited"))
                    }
                    _ => Ok(Target::Process(process)),
                }
            }
            "unix-session" => {
                let Some(Value::Str(id)) = field("session-id") else {
                    return Err(invalid("unix-session needs a session-id"));
                };
                let logind = self
                    .logind
                    .as_ref()
                    .ok_or_else(|| fdo::Error::Failed("logind isn't available".into()))?;
                let session = logind
                    .session(id)
                    .await
                    .map_err(|e| fdo::Error::Failed(e.to_string()))?
                    .ok_or_else(|| invalid(format!("no session {id:?}")))?;
                Ok(Target::Session {
                    id: session.id,
                    uid: session.uid,
                })
            }
            "system-bus-name" => match field("name") {
                Some(Value::Str(name)) => {
                    let name = BusName::try_from(name.as_str()).map_err(invalid)?;
                    Ok(Target::Process(Self::bus_process(conn, name).await?))
                }
                _ => Err(invalid("system-bus-name needs a name")),
            },
            _ => Err(invalid(format!("unknown kind of subject {kind:?}"))),
        }
    }

    /// Whether `caller` may check `action` for `target`: always for its own
    /// user's processes, and otherwise only for root, or an owner of the
    /// action (`@owners`), as polkit.
    pub fn may_check(&self, caller: &Process, target: &Target, action: &str) -> bool {
        if caller.uid == target.uid() || self.trusted(caller.uid) {
            return true;
        }
        let user = Nss.user(caller.uid).ok().flatten();
        self.authority
            .owners(action)
            .iter()
            .any(|owner| match owner.split_once(':') {
                Some(("unix-user", who)) => match who.parse::<u32>() {
                    Ok(uid) => uid == caller.uid,
                    Err(_) => user.as_ref().and_then(|u| u.name.as_deref()) == Some(who),
                },
                Some(("unix-group", group)) => user
                    .as_ref()
                    .is_some_and(|u| u.groups.iter().any(|g| g.name == group)),
                _ => false,
            })
    }

    /// The subject of a check, with what logind knows about it, and the
    /// session whose agent would ask it to authenticate.
    pub async fn subject(&self, target: &Target) -> fdo::Result<(Subject, Option<String>)> {
        let user = Nss
            .user(target.uid())
            .map_err(|e| fdo::Error::Failed(e.to_string()))?
            .unwrap_or_else(|| User::new(target.uid()));
        let mut subject = Subject::new(user);
        let Some(logind) = &self.logind else {
            return Ok((subject, None));
        };
        let (info, id) = match target {
            Target::Process(p) => (logind.process(p.id.pid, p.uid).await, p.id.pid.to_string()),
            Target::Session { id, .. } => (
                logind.session_info(id).await.map(Option::unwrap_or_default),
                format!("session-{id}"),
            ),
        };
        match info {
            Ok(info) => {
                subject = subject.with_facts(info.facts_for(&id));
                let session = info.session.or(info.display).map(|s| s.id);
                Ok((subject, session))
            }
            Err(e) => {
                tracing::warn!(?target, "can't ask logind: {e}");
                Ok((subject, None))
            }
        }
    }

    /// Decides a request, asking the agent of `session` to have the user
    /// authenticate for a challenge if `interact`. Waiting for the user ends
    /// early if the caller cancels the check (`registration`), leaves the
    /// bus, or the subject process exits.
    #[allow(clippy::too_many_arguments)]
    pub async fn decide(
        self: &Arc<Self>,
        conn: &zbus::Connection,
        sender: &UniqueName<'_>,
        caller: &Process,
        target: &Target,
        session: Option<String>,
        mut request: CheckRequest,
        interact: bool,
        registration: Option<Registration>,
        mut details: HashMap<String, String>,
    ) -> Decided {
        let process = target.process();
        let remembered = self
            .store()
            .lookup(Instant::now(), |r| self.shares(target, r));
        request.authentications = remembered.iter().map(|r| r.auth.clone()).collect();
        let mut outcome = self.authority.check(&request);
        let mut decided = Decided {
            temporary: None,
            dismissed: false,
            retained: false,
            outcome: Outcome {
                decision: Decision::Deny,
                reasons: Vec::new(),
                authentication: None,
            },
        };
        if let Some(auth) = &outcome.authentication {
            decided.temporary = remembered
                .iter()
                .find(|r| r.auth == *auth)
                .map(|r| r.id.clone());
        }
        if let Decision::Challenge(options) = &outcome.decision {
            decided.retained = options.iter().all(|o| o.keep);
        }

        if interact
            && let Decision::Challenge(options) = &outcome.decision
            && let Some(session) = &session
        {
            // PAM authenticates users by name.
            let identities: Vec<Identity> = options
                .iter()
                .filter_map(|o| {
                    Some(Identity {
                        uid: o.uid,
                        name: o.name.clone()?,
                    })
                })
                .collect();
            // Who would be remembered, as polkit's `_keep`.
            let keep: Vec<u32> = options.iter().filter(|o| o.keep).map(|o| o.uid).collect();
            let action = request.action_id.clone();
            details.insert("polkit.caller-pid".into(), caller.id.pid.to_string());
            if let Some(process) = process {
                details.insert("polkit.subject-pid".into(), process.pid.to_string());
            }
            let agent_request = AgentRequest {
                action: action.clone(),
                message: self.authority.message(&action).to_owned(),
                icon: self.authority.icon(&action).unwrap_or_default().to_owned(),
                details,
                identities,
            };
            let challenge = if agent_request.identities.is_empty() {
                None
            } else {
                self.agents.begin(session, agent_request)
            };
            match challenge {
                None => tracing::debug!(session, "no authentication agent for the session"),
                Some(challenge) => {
                    let cancelled = cancelled(conn, sender, process, registration);
                    let deny = |reason: &str| Outcome {
                        decision: Decision::Deny,
                        reasons: vec![reason.into()],
                        authentication: None,
                    };
                    // Dropping the challenge cancels the agent's request.
                    outcome = tokio::select! {
                        uid = challenge.wait() => match uid {
                            Some(uid) => {
                                let keep = keep.contains(&uid);
                                self.authenticated(&mut request, target, session, uid, keep, &mut decided)
                            }
                            None => {
                                decided.dismissed = true;
                                deny("the user didn't authenticate")
                            }
                        },
                        reason = cancelled => {
                            tracing::info!(action, "{reason}, so not waiting for the user");
                            deny(reason)
                        }
                    };
                }
            }
        }

        tracing::info!(
            uid = target.uid(),
            ?process,
            action = request.action_id,
            resource = %request.resource.uid,
            decision = outcome.decision.as_str(),
            reasons = ?outcome.reasons,
            "authorization check"
        );
        decided.outcome = outcome;
        decided
    }

    /// Checks again once `uid` has authenticated, and if `keep`, remembers
    /// the authentication as polkit's temporary authorizations: for the
    /// target, for its session's agent, until it expires.
    fn authenticated(
        self: &Arc<Self>,
        request: &mut CheckRequest,
        target: &Target,
        session: &str,
        uid: u32,
        keep: bool,
        decided: &mut Decided,
    ) -> Outcome {
        let auth = Authentication::fresh(uid, request);
        request.authentications.push(auth.clone());
        let outcome = self.authority.check(request);
        if outcome.decision != Decision::Allow || !keep {
            return outcome;
        }
        let family = target.process().and_then(family);
        let id = self.store().remember(
            target.holder(),
            Some(session.to_owned()),
            auth,
            Instant::now(),
        );
        if let Some(family) = family {
            self.families().insert(id.clone(), family);
        }
        tracing::info!(
            id,
            uid,
            action = request.action_id,
            ?target,
            "remembering the authentication"
        );
        decided.temporary = Some(id.clone());
        self.changed.notify_one();

        // Forget it when it expires, telling polkit's clients. As polkit,
        // not when the process exits: its siblings may still use it.
        let state = self.clone();
        let lifetime = self.store().lifetime();
        tokio::spawn(async move {
            tokio::time::sleep(lifetime).await;
            state.families().remove(&id);
            if state.store().revoke(&id) {
                tracing::debug!(id, "forgot the authentication");
                state.changed.notify_one();
            }
        });
        outcome
    }

    /// Whether a remembered authentication counts for `target`: its own, or
    /// as polkit, one remembered for a sibling process in the same terminal,
    /// even if that has since exited.
    fn shares(&self, target: &Target, remembered: &Remembered) -> bool {
        match (target, &remembered.holder) {
            (Target::Process(p), Holder::Process(q)) => {
                p.id == *q
                    || self
                        .families()
                        .get(&remembered.id)
                        .is_some_and(|family| siblings(family, p.id))
            }
            (Target::Session { id, .. }, Holder::Session(other)) => id == other,
            _ => false,
        }
    }

    fn families(&self) -> std::sync::MutexGuard<'_, HashMap<String, Family>> {
        self.families
            .lock()
            .expect("the families' lock isn't poisoned")
    }

    pub fn store(&self) -> std::sync::MutexGuard<'_, AuthStore> {
        self.store.lock().expect("the store's lock isn't poisoned")
    }
}

/// Resolves, with the reason, when a waiting check should end early.
async fn cancelled(
    conn: &zbus::Connection,
    sender: &UniqueName<'_>,
    process: Option<ProcessId>,
    registration: Option<Registration>,
) -> &'static str {
    let by_caller = async {
        match registration {
            Some(mut r) => {
                let _ = (&mut r.cancelled).await;
            }
            None => std::future::pending().await,
        }
    };
    let exited = async {
        match process {
            Some(process) => cancel::process_exited(process).await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        () = by_caller => "the caller cancelled the check",
        () = cancel::name_vanished(conn, sender) => "the caller left the bus",
        () = exited => "the process exited",
    }
}
