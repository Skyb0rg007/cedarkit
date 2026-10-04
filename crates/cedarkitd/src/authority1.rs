//! The native interface, `org.cedarkit.Authority1` (docs/design.md, section
//! 9.5).

use std::collections::HashMap;
use std::sync::Arc;

use cedarkit_core::{AttrValue, CheckRequest, Decision, Resource};
use zbus::fdo;
use zbus::message::Header;
use zbus::zvariant::{OwnedValue, Value};

use crate::state::{State, SubjectArg, invalid};

pub const BUS_NAME: &str = "org.cedarkit.Authority1";
pub const PATH: &str = "/org/cedarkit/Authority1";

/// The `CheckAuthorization` flag allowing CedarKit to ask the user to
/// authenticate, as polkit's `AllowUserInteraction`.
pub const ALLOW_USER_INTERACTION: u32 = 1;

/// A resource: its id in Cedar syntax, attributes, and parents.
type ResourceArg = (String, HashMap<String, OwnedValue>, Vec<String>);

/// A user who could pass a challenge: uid, name, and whether a remembered
/// authentication by them would be accepted.
type OptionArg = (u32, String, bool);

pub struct AuthorityService {
    pub state: Arc<State>,
}

#[zbus::interface(name = "org.cedarkit.Authority1")]
impl AuthorityService {
    /// Checks whether `subject` may perform `action` on `resource`.
    ///
    /// `subject` is polkit-style: `("", {})` for the caller,
    /// `("unix-process", {pid, start-time})`, `("unix-session",
    /// {session-id})` or `("system-bus-name", {name})`. Only root, the
    /// subject's own user, and the action's `@owners` may check for another
    /// process. `resource` is an id in Cedar syntax, attributes and parents;
    /// only root may pass attributes and parents. `details` are typed values.
    ///
    /// With `AllowUserInteraction` (1) in `flags`, a challenge is passed to
    /// the authentication agent for the subject's session, and the call
    /// returns once the user has authenticated or given up. It's denied
    /// early if the caller leaves the bus, the subject process exits, or the
    /// caller passes `cancellation_id` to `CancelCheckAuthorization`.
    ///
    /// Returns `allow`, `deny` or `challenge`, and for a challenge, who could
    /// authenticate: `(uid, name, keep)`.
    #[allow(clippy::too_many_arguments)]
    async fn check_authorization(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        subject: SubjectArg,
        action: String,
        resource: ResourceArg,
        details: HashMap<String, OwnedValue>,
        flags: u32,
        cancellation_id: String,
    ) -> fdo::Result<(String, Vec<OptionArg>)> {
        let state = &self.state;
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::Failed("no sender".into()))?;
        let registration = match cancellation_id.as_str() {
            "" => None,
            id => Some(state.cancellations.register(sender, id)?),
        };
        let caller = State::bus_process(conn, sender.clone().into()).await?;
        let target = state.target(conn, &caller, &subject).await?;
        if !state.may_check(&caller, &target, &action) {
            return Err(fdo::Error::AccessDenied(
                "only root, and the action's owners, may check for other users' processes".into(),
            ));
        }
        let (subject, session) = state.subject(&target).await?;

        let (id, attrs, parents) = resource;
        if !state.trusted(caller.uid) && !(attrs.is_empty() && parents.is_empty()) {
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
        if let Some(logind) = &state.logind {
            logind.fill_resource(&mut resource).await.map_err(invalid)?;
        }

        let mut request = CheckRequest::new(subject, action, resource);
        for (key, value) in &details {
            let value = attr_value(value)
                .ok_or_else(|| invalid(format!("unsupported value for detail {key:?}")))?;
            request.details.insert(key.clone(), value);
        }

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
                HashMap::new(),
            )
            .await;
        let decision = decided.outcome.decision;
        let options = match &decision {
            Decision::Challenge(options) => options
                .iter()
                .map(|o| (o.uid, o.name.clone().unwrap_or_default(), o.keep))
                .collect(),
            _ => Vec::new(),
        };
        Ok((decision.as_str().to_owned(), options))
    }

    /// Cancels the caller's check with `cancellation_id`, which is then
    /// denied.
    fn cancel_check_authorization(
        &self,
        #[zbus(header)] header: Header<'_>,
        cancellation_id: String,
    ) -> fdo::Result<()> {
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::Failed("no sender".into()))?;
        self.state.cancellations.cancel(sender, &cancellation_id)
    }

    #[zbus(property)]
    fn backend_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
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
