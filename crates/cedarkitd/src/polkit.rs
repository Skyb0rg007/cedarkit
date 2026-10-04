//! The polkit-compatible front end, `org.freedesktop.PolicyKit1.Authority`
//! (docs/design.md, section 11), for unmodified polkit clients and agents.
//!
//! Checks are built from polkit's details, following the `@detail` and
//! `@singleton` annotations, and decided as native ones are. polkit agents,
//! such as GNOME Shell's, register here and run polkit's own helper, which
//! reports who authenticated as root, as it does to polkitd.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use cedarkit_core::{CheckRequest, Decision, Holder, polkit};
use zbus::fdo;
use zbus::message::Header;
use zbus::names::UniqueName;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedValue, Value};

use crate::agents::PolkitAgent;
use crate::authority1::ALLOW_USER_INTERACTION;
use crate::cancel;
use crate::state::{Process, State, SubjectArg, Target};

pub const BUS_NAME: &str = "org.freedesktop.PolicyKit1";
pub const PATH: &str = "/org/freedesktop/PolicyKit1/Authority";

/// polkit's `BackendFeatures`: temporary authorizations.
const TEMPORARY_AUTHORIZATION: u32 = 1;

/// An action's description: id, description, message, vendor name, vendor
/// URL, icon, the implicit authorizations for any, inactive and active
/// sessions, and annotations.
type ActionDescriptionArg = (
    String,
    String,
    String,
    String,
    String,
    String,
    u32,
    u32,
    u32,
    HashMap<String, String>,
);

/// polkit's `AuthorizationResult`, a single struct `(bba{ss})`: whether the
/// subject is authorized, whether authenticating would help, and details.
#[derive(Debug, serde::Serialize, zbus::zvariant::Type)]
pub struct AuthorizationResult {
    is_authorized: bool,
    is_challenge: bool,
    details: HashMap<String, String>,
}

impl AuthorizationResult {
    fn new(is_authorized: bool, is_challenge: bool, details: HashMap<String, String>) -> Self {
        Self {
            is_authorized,
            is_challenge,
            details,
        }
    }
}

/// A temporary authorization: id, action, subject, and when it was obtained
/// and expires, in seconds since the epoch.
type TemporaryAuthorizationArg = (String, String, SubjectArg, u64, u64);

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.PolicyKit1.Error")]
pub enum PolkitError {
    #[zbus(error)]
    ZBus(zbus::Error),
    Failed(String),
    Cancelled(String),
    NotAuthorized(String),
    CancellationIdNotUnique(String),
    NotSupported(String),
}

impl From<fdo::Error> for PolkitError {
    fn from(e: fdo::Error) -> Self {
        match e {
            fdo::Error::AccessDenied(msg) => Self::NotAuthorized(msg),
            fdo::Error::InvalidArgs(msg) | fdo::Error::Failed(msg) => Self::Failed(msg),
            e => Self::Failed(e.to_string()),
        }
    }
}

type Result<T> = std::result::Result<T, PolkitError>;

/// polkit's `ImplicitAuthorization` for a result label.
fn implicit(label: &str) -> u32 {
    match label {
        "auth_self" => 1,
        "auth_admin" => 2,
        "auth_self_keep" => 3,
        "auth_admin_keep" => 4,
        "yes" => 5,
        _ => 0,
    }
}

fn sender<'h>(header: &'h Header<'_>) -> Result<&'h UniqueName<'h>> {
    header
        .sender()
        .ok_or_else(|| PolkitError::Failed("no sender".into()))
}

fn epoch_seconds(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The uid of a polkit identity, `("unix-user", {uid})`.
fn identity_uid((kind, fields): &SubjectArg) -> Result<u32> {
    match (kind.as_str(), fields.get("uid").map(|v| &**v)) {
        ("unix-user", Some(Value::U32(uid))) => Ok(*uid),
        ("unix-user", Some(Value::I32(uid))) => {
            u32::try_from(*uid).map_err(|_| PolkitError::Failed("invalid uid".into()))
        }
        _ => Err(PolkitError::Failed(
            "only unix-user identities are supported".into(),
        )),
    }
}

pub struct PolkitAuthority {
    pub state: Arc<State>,
}

impl PolkitAuthority {
    /// The session of a process, or its user's graphical session.
    async fn session_of(&self, process: &Process) -> Option<(String, u32)> {
        let logind = self.state.logind.as_ref()?;
        let info = logind.process(process.id.pid, process.uid).await.ok()?;
        let session = info.session.or(info.display)?;
        Some((session.id, session.uid))
    }

    /// The session a subject is in: a `unix-session`'s own, or a process's.
    async fn session(
        &self,
        conn: &zbus::Connection,
        caller: &Process,
        subject: &SubjectArg,
    ) -> Result<(String, u32)> {
        match self.state.target(conn, caller, subject).await? {
            Target::Session { id, uid } => Ok((id, uid)),
            Target::Process(process) => self
                .session_of(&process)
                .await
                .ok_or_else(|| PolkitError::Failed("the subject isn't in a session".into())),
        }
    }

    /// The caller's own session, which it may act on without privileges,
    /// returning whether the caller may act on `session`.
    async fn may_act_on(&self, caller: &Process, session: &str) -> bool {
        self.state.trusted(caller.uid)
            || self
                .session_of(caller)
                .await
                .is_some_and(|(own, _)| own == session)
    }

    /// Checks that a call comes from polkit's helper, which runs as root.
    fn trusted_caller(&self, caller: &Process) -> Result<()> {
        if self.state.trusted(caller.uid) {
            Ok(())
        } else {
            Err(PolkitError::NotAuthorized(
                "Only uid 0 may invoke this method.".into(),
            ))
        }
    }

    async fn register_agent(
        &self,
        header: &Header<'_>,
        conn: &zbus::Connection,
        subject: &SubjectArg,
        path: &str,
        fallback: bool,
    ) -> Result<()> {
        let sender = sender(header)?;
        let caller = State::bus_process(conn, sender.clone().into()).await?;
        let (session, uid) = self.session(conn, &caller, subject).await?;
        // Agents serve their own user's session, as in polkit.
        if !self.state.trusted(caller.uid)
            && (uid != caller.uid || !self.may_act_on(&caller, &session).await)
        {
            return Err(PolkitError::NotAuthorized(
                "An authentication agent may only be registered for the caller's own session"
                    .into(),
            ));
        }
        let agent = PolkitAgent {
            conn: conn.clone(),
            name: sender.to_string(),
            path: path.to_owned(),
        };
        self.state
            .agents
            .register_polkit(&session, caller.uid, fallback, agent)
            .map_err(|_| {
                PolkitError::Failed(
                    "An authentication agent already exists for the given subject".into(),
                )
            })?;

        // Forget the agent when it leaves the bus.
        let (conn, name, agents) = (conn.clone(), sender.to_owned(), self.state.agents.clone());
        tokio::spawn(async move {
            cancel::name_vanished(&conn, &name).await;
            agents.unregister_polkit(name.as_str(), None);
        });
        Ok(())
    }

    async fn agent_response(
        &self,
        header: &Header<'_>,
        conn: &zbus::Connection,
        cookie: &str,
        identity: &SubjectArg,
        claimed: Option<u32>,
    ) -> Result<()> {
        let caller = State::bus_process(conn, sender(header)?.clone().into()).await?;
        self.trusted_caller(&caller)?;
        let uid = identity_uid(identity)?;
        self.state
            .agents
            .polkit_response(cookie, claimed, uid)
            .map_err(PolkitError::Failed)
    }

    /// The session whose temporary authorizations a call is about, if the
    /// caller may see them.
    async fn temporary_session(
        &self,
        header: &Header<'_>,
        conn: &zbus::Connection,
        subject: &SubjectArg,
    ) -> Result<String> {
        if subject.0 != "unix-session" {
            return Err(PolkitError::NotSupported(
                "Can only handle unix-session subjects".into(),
            ));
        }
        let caller = State::bus_process(conn, sender(header)?.clone().into()).await?;
        let (session, _) = self.session(conn, &caller, subject).await?;
        if !self.may_act_on(&caller, &session).await {
            return Err(PolkitError::NotAuthorized(
                "Can only handle the caller's own session".into(),
            ));
        }
        Ok(session)
    }
}

#[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl PolkitAuthority {
    #[zbus(property)]
    fn backend_name(&self) -> &str {
        "cedarkit"
    }

    #[zbus(property)]
    fn backend_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    #[zbus(property)]
    fn backend_features(&self) -> u32 {
        TEMPORARY_AUTHORIZATION
    }

    /// Every declared action, with the defaults its `.policy` file gave.
    fn enumerate_actions(&self, _locale: String) -> Vec<ActionDescriptionArg> {
        self.state
            .authority
            .polkit_actions()
            .into_iter()
            .map(|a| {
                let [any, inactive, active] = a.defaults.map(|d| implicit(&d));
                (
                    a.id,
                    a.description,
                    a.message,
                    a.vendor,
                    a.vendor_url,
                    a.icon,
                    any,
                    inactive,
                    active,
                    a.annotations.into_iter().collect(),
                )
            })
            .collect()
    }

    /// polkit's `CheckAuthorization`: whether the subject is authorized, and
    /// if not, whether authenticating would help.
    #[allow(clippy::too_many_arguments)]
    async fn check_authorization(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        subject: SubjectArg,
        action_id: String,
        details: HashMap<String, String>,
        flags: u32,
        cancellation_id: String,
    ) -> Result<(AuthorizationResult,)> {
        let state = &self.state;
        let sender = sender(&header)?;
        let registration = match cancellation_id.as_str() {
            "" => None,
            id => Some(
                state
                    .cancellations
                    .register(sender, id)
                    .map_err(|_| PolkitError::CancellationIdNotUnique(id.to_owned()))?,
            ),
        };
        let caller = State::bus_process(conn, sender.clone().into()).await?;
        let target = state.target(conn, &caller, &subject).await?;
        if !state.may_check(&caller, &target, &action_id) {
            return Err(PolkitError::NotAuthorized(
                "Only trusted callers (e.g. uid 0 or an action owner) can use \
                 CheckAuthorization() for subjects belonging to other identities"
                    .into(),
            ));
        }

        // Anything that stops the request being understood denies it.
        let not_authorized = |reason: String| {
            tracing::info!(action = action_id, uid = target.uid(), "denied: {reason}");
            Ok((AuthorizationResult::new(false, false, HashMap::new()),))
        };
        let mut resource = match state.authority.polkit_resource(&action_id, &details) {
            Ok(resource) => resource,
            Err(e) => return not_authorized(e.to_string()),
        };
        if let Some(logind) = &state.logind
            && let Err(e) = logind.fill_resource(&mut resource).await
        {
            return not_authorized(e.to_string());
        }
        let parsed = match state.authority.parse_details(&action_id, &details) {
            Ok(parsed) => parsed,
            Err(e) => return not_authorized(e.to_string()),
        };
        let (subject, session) = state.subject(&target).await?;
        let request = CheckRequest {
            details: parsed,
            ..CheckRequest::new(subject, action_id.as_str(), resource)
        };

        let interact = flags & ALLOW_USER_INTERACTION != 0;
        let decided = state
            .decide(
                conn,
                sender,
                &caller,
                &target,
                session,
                request,
                interact,
                registration,
                details,
            )
            .await;

        let mut result = HashMap::new();
        if let Some(id) = decided.temporary {
            result.insert("polkit.temporary_authorization_id".into(), id);
        }
        if decided.retained {
            result.insert(
                "polkit.retains_authorization_after_challenge".into(),
                "true".into(),
            );
        }
        if decided.dismissed {
            result.insert("polkit.dismissed".into(), "true".into());
        }
        let decision = &decided.outcome.decision;
        result.insert(
            "polkit.result".into(),
            polkit::result(decision, target.uid()).into(),
        );
        // A single struct, rather than three arguments.
        Ok((match decision {
            Decision::Allow => AuthorizationResult::new(true, false, result),
            Decision::Challenge(_) => AuthorizationResult::new(false, true, result),
            Decision::Deny => AuthorizationResult::new(false, false, result),
        },))
    }

    fn cancel_check_authorization(
        &self,
        #[zbus(header)] header: Header<'_>,
        cancellation_id: String,
    ) -> Result<()> {
        let sender = sender(&header)?;
        self.state
            .cancellations
            .cancel(sender, &cancellation_id)
            .map_err(Into::into)
    }

    async fn register_authentication_agent(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        subject: SubjectArg,
        _locale: String,
        object_path: String,
    ) -> Result<()> {
        self.register_agent(&header, conn, &subject, &object_path, false)
            .await
    }

    async fn register_authentication_agent_with_options(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        subject: SubjectArg,
        _locale: String,
        object_path: String,
        options: HashMap<String, OwnedValue>,
    ) -> Result<()> {
        let fallback = matches!(
            options.get("fallback").map(|v| &**v),
            Some(Value::Bool(true))
        );
        self.register_agent(&header, conn, &subject, &object_path, fallback)
            .await
    }

    fn unregister_authentication_agent(
        &self,
        #[zbus(header)] header: Header<'_>,
        _subject: SubjectArg,
        object_path: String,
    ) -> Result<()> {
        let sender = sender(&header)?;
        if self
            .state
            .agents
            .unregister_polkit(sender.as_str(), Some(&object_path))
        {
            Ok(())
        } else {
            Err(PolkitError::Failed("No such authentication agent".into()))
        }
    }

    /// From polkit's helper: `identity` authenticated for `cookie`.
    async fn authentication_agent_response(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        cookie: String,
        identity: SubjectArg,
    ) -> Result<()> {
        self.agent_response(&header, conn, &cookie, &identity, None)
            .await
    }

    /// From polkit's helper, run for the agent's user `uid`.
    async fn authentication_agent_response2(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        uid: u32,
        cookie: String,
        identity: SubjectArg,
    ) -> Result<()> {
        self.agent_response(&header, conn, &cookie, &identity, Some(uid))
            .await
    }

    /// From polkit's socket-activated helper, run for the agent process
    /// `subject`.
    async fn authentication_agent_response3(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        cookie: String,
        identity: SubjectArg,
        subject: SubjectArg,
    ) -> Result<()> {
        let caller = State::bus_process(conn, sender(&header)?.clone().into()).await?;
        self.trusted_caller(&caller)?;
        let agent = self.state.target(conn, &caller, &subject).await?;
        self.agent_response(&header, conn, &cookie, &identity, Some(agent.uid()))
            .await
    }

    async fn enumerate_temporary_authorizations(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        subject: SubjectArg,
    ) -> Result<Vec<TemporaryAuthorizationArg>> {
        let session = self.temporary_session(&header, conn, &subject).await?;
        let remembered = self.state.store().in_scope(&session, Instant::now());
        Ok(remembered
            .into_iter()
            .map(|r| {
                let subject = match &r.holder {
                    Holder::Process(p) => (
                        "unix-process".to_owned(),
                        HashMap::from([
                            ("pid".to_owned(), OwnedValue::from(p.pid)),
                            ("start-time".to_owned(), OwnedValue::from(p.start_time)),
                        ]),
                    ),
                    Holder::Session(id) => (
                        "unix-session".to_owned(),
                        HashMap::from([(
                            "session-id".to_owned(),
                            OwnedValue::try_from(Value::from(id.as_str()))
                                .expect("strings convert"),
                        )]),
                    ),
                };
                (
                    r.id.clone(),
                    r.auth.action.clone(),
                    subject,
                    epoch_seconds(r.obtained),
                    epoch_seconds(r.expires_at()),
                )
            })
            .collect())
    }

    async fn revoke_temporary_authorizations(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        subject: SubjectArg,
    ) -> Result<()> {
        let session = self.temporary_session(&header, conn, &subject).await?;
        if self.state.store().revoke_scope(&session) > 0 {
            self.state.changed.notify_one();
        }
        Ok(())
    }

    async fn revoke_temporary_authorization_by_id(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        id: String,
    ) -> Result<()> {
        let caller = State::bus_process(conn, sender(&header)?.clone().into()).await?;
        let remembered = self.state.store().get(&id, Instant::now());
        let Some(remembered) = remembered else {
            return Err(PolkitError::Failed(format!(
                "No such temporary authorization with id {id}"
            )));
        };
        let session = remembered.scope.unwrap_or_default();
        if !self.may_act_on(&caller, &session).await {
            return Err(PolkitError::NotAuthorized(
                "Can only revoke temporary authorizations of the caller's own session".into(),
            ));
        }
        self.state.store().revoke(&id);
        self.state.changed.notify_one();
        Ok(())
    }

    /// Actions or temporary authorizations changed.
    #[zbus(signal)]
    pub async fn changed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}
