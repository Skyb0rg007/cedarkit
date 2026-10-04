//! `cedarkitd`: the CedarKit authority daemon.
//!
//! Exposes `org.cedarkit.Authority1` on the system bus (or the session bus,
//! for development) and answers authorization checks using Cedar policies
//! (docs/design.md, section 9.5).

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use anyhow::Context as _;
use cedarkit_core::{
    AttrValue, AuthStore, Authority, CheckRequest, Decision, Directory, Layout, Nss, ProcessId,
    Resource, Subject, User,
};
use cedarkit_logind::Logind;
use clap::Parser;
use tracing_subscriber::EnvFilter;
use zbus::fdo;
use zbus::message::Header;
use zbus::names::BusName;
use zbus::zvariant::{OwnedValue, Value};

const BUS_NAME: &str = "org.cedarkit.Authority1";
const OBJECT_PATH: &str = "/org/cedarkit/Authority1";

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Directory of vendor files, one directory per application.
    #[arg(long, default_value = "/usr/share/cedarkit")]
    vendor: PathBuf,

    /// Directory of the local admin's files.
    #[arg(long, default_value = "/etc/cedarkit")]
    admin: PathBuf,

    /// The generated subject schema.
    #[arg(long, default_value = "/var/lib/cedarkit/subject.cedarschema")]
    subject_schema: PathBuf,

    /// Serve on the session bus instead of the system bus.
    #[arg(long)]
    session: bool,
}

/// A polkit-style subject: a kind, and its details.
type SubjectArg = (String, HashMap<String, OwnedValue>);

/// A resource: its id in Cedar syntax, attributes, and parents.
type ResourceArg = (String, HashMap<String, OwnedValue>, Vec<String>);

/// A user who could pass a challenge: uid, name, and whether a remembered
/// authentication by them would be accepted.
type OptionArg = (u32, String, bool);

struct AuthorityService {
    authority: Authority,
    logind: Option<Logind>,
    store: Mutex<AuthStore>,
}

/// The process a check is for.
struct Process {
    id: ProcessId,
    uid: u32,
}

fn invalid(e: impl std::fmt::Display) -> fdo::Error {
    fdo::Error::InvalidArgs(e.to_string())
}

impl AuthorityService {
    /// The process making a D-Bus call, from the bus's credentials.
    async fn bus_process(conn: &zbus::Connection, name: BusName<'_>) -> fdo::Result<Process> {
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

    /// The subject: the caller, unless the caller is root and names another
    /// process.
    async fn subject_process(
        conn: &zbus::Connection,
        caller: &Process,
        (kind, fields): &SubjectArg,
    ) -> fdo::Result<Process> {
        if kind.is_empty() {
            return Ok(Process { ..*caller });
        }
        // TODO: also let mechanisms check for other processes, once they can
        // be bound to namespaces (docs/design.md, open question 1).
        if caller.uid != 0 {
            return Err(fdo::Error::AccessDenied(
                "only root may check on behalf of another process".into(),
            ));
        }
        let field = |key: &str| fields.get(key).map(|v| &**v);
        match kind.as_str() {
            "unix-process" => {
                let pid = match field("pid") {
                    Some(Value::U32(pid)) => *pid,
                    _ => return Err(invalid("unix-process needs a pid")),
                };
                let process = process(pid, None)?;
                match field("start-time") {
                    Some(Value::U64(t)) if *t != process.id.start_time => {
                        Err(invalid("the process has exited"))
                    }
                    _ => Ok(process),
                }
            }
            "system-bus-name" => match field("name") {
                Some(Value::Str(name)) => {
                    let name = BusName::try_from(name.as_str()).map_err(invalid)?;
                    Self::bus_process(conn, name).await
                }
                _ => Err(invalid("system-bus-name needs a name")),
            },
            _ => Err(invalid(format!("unknown kind of subject {kind:?}"))),
        }
    }
}

#[zbus::interface(name = "org.cedarkit.Authority1")]
impl AuthorityService {
    /// Checks whether `subject` may perform `action` on `resource`.
    ///
    /// `subject` is polkit-style: `("", {})` for the caller, or for root,
    /// `("unix-process", {pid, start-time})` or `("system-bus-name",
    /// {name})`. `resource` is an id in Cedar syntax, attributes and parents;
    /// only root may pass attributes and parents. `details` are typed values.
    ///
    /// Returns `allow`, `deny` or `challenge`, and for a challenge, who could
    /// authenticate: `(uid, name, keep)`.
    // TODO: authentication agents, and remembering what they report.
    #[allow(clippy::too_many_arguments)]
    async fn check_authorization(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        subject: SubjectArg,
        action: String,
        resource: ResourceArg,
        details: HashMap<String, OwnedValue>,
        _flags: u32,
    ) -> fdo::Result<(String, Vec<OptionArg>)> {
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::Failed("no sender".into()))?;
        let caller = Self::bus_process(conn, sender.clone().into()).await?;
        let process = Self::subject_process(conn, &caller, &subject).await?;

        let user = Nss
            .user(process.uid)
            .map_err(|e| fdo::Error::Failed(e.to_string()))?
            .unwrap_or_else(|| User::new(process.uid));
        let mut subject = Subject::new(user);
        if let Some(logind) = &self.logind {
            match logind.process(process.id.pid, process.uid).await {
                Ok(info) => subject = subject.with_facts(info.facts(process.id.pid)),
                Err(e) => tracing::warn!(pid = process.id.pid, "can't ask logind: {e}"),
            }
        }

        let (id, attrs, parents) = resource;
        if caller.uid != 0 && !(attrs.is_empty() && parents.is_empty()) {
            return Err(fdo::Error::AccessDenied(
                "only root may give a resource's attributes and parents".into(),
            ));
        }
        let mut resource = Resource::parse(&id).map_err(invalid)?;
        for (key, value) in &attrs {
            let value = attr_value(value)
                .ok_or_else(|| invalid(format!("unsupported value for attribute {key:?}")))?;
            resource = resource.with_attr(key.clone(), value);
        }
        for parent in &parents {
            resource = resource.with_parent(Resource::parse(parent).map_err(invalid)?.uid);
        }
        if let Some(logind) = &self.logind {
            logind.fill_resource(&mut resource).await.map_err(invalid)?;
        }

        let mut request = CheckRequest::new(subject, action, resource);
        for (key, value) in &details {
            let value = attr_value(value)
                .ok_or_else(|| invalid(format!("unsupported value for detail {key:?}")))?;
            request.details.insert(key.clone(), value);
        }
        request.authentications = self
            .store
            .lock()
            .expect("the store's lock isn't poisoned")
            .lookup(process.id, Instant::now());

        let outcome = self.authority.check(&request);
        tracing::info!(
            uid = process.uid,
            pid = process.id.pid,
            action = request.action_id,
            resource = %request.resource.uid,
            decision = outcome.decision.as_str(),
            reasons = ?outcome.reasons,
            "authorization check"
        );

        let options = match &outcome.decision {
            Decision::Challenge(options) => options
                .iter()
                .map(|o| (o.uid, o.name.clone().unwrap_or_default(), o.keep))
                .collect(),
            _ => Vec::new(),
        };
        Ok((outcome.decision.as_str().to_owned(), options))
    }

    #[zbus(property)]
    fn backend_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
}

/// Process `pid`, as identified by its start time, and its real uid if not
/// already known.
fn process(pid: u32, uid: Option<u32>) -> fdo::Result<Process> {
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

/// Converts a D-Bus value into a Cedar attribute value.
fn attr_value(value: &Value) -> Option<AttrValue> {
    Some(match value {
        Value::Bool(b) => AttrValue::Bool(*b),
        Value::U8(n) => AttrValue::Long((*n).into()),
        Value::I16(n) => AttrValue::Long((*n).into()),
        Value::U16(n) => AttrValue::Long((*n).into()),
        Value::I32(n) => AttrValue::Long((*n).into()),
        Value::U32(n) => AttrValue::Long((*n).into()),
        Value::I64(n) => AttrValue::Long(*n),
        Value::U64(n) => AttrValue::Long((*n).try_into().ok()?),
        Value::Str(s) => AttrValue::String(s.to_string()),
        Value::Value(inner) => attr_value(inner)?,
        Value::Structure(s) => match s.fields() {
            [Value::Str(ty), Value::Str(id)] => {
                AttrValue::Entity(cedarkit_core::entity_uid(ty, id).ok()?)
            }
            _ => return None,
        },
        Value::Array(items) => AttrValue::Set(items.iter().map(attr_value).collect::<Option<_>>()?),
        _ => return None,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let layout = Layout {
        vendor: args.vendor,
        admin: args.admin,
        subject_schema: args.subject_schema,
    };

    let loaded = Authority::load(&layout).context("loading policies")?;
    for warning in &loaded.warnings {
        tracing::warn!("{warning}");
    }
    let logind = match Logind::system().await {
        Ok(logind) => Some(logind),
        Err(e) => {
            tracing::warn!("can't connect to logind, so it reports no facts: {e}");
            None
        }
    };
    let service = AuthorityService {
        authority: loaded.authority,
        logind,
        store: Mutex::default(),
    };

    let builder = if args.session {
        zbus::connection::Builder::session()?
    } else {
        zbus::connection::Builder::system()?
    };
    let _conn = builder
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, service)?
        .build()
        .await
        .context("connecting to D-Bus")?;

    tracing::info!(name = BUS_NAME, path = OBJECT_PATH, "cedarkitd ready");
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
