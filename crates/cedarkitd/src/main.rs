//! `cedarkitd`: the CedarKit authority daemon.
//!
//! Exposes `org.cedarkit.Authority1` on the system bus (or the session bus,
//! for development) and answers authorization checks using Cedar policies.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Context as _;
use cedarkit_core::{AttrValue, Authentication, Authority, CheckRequest, Resource, Subject};
use clap::Parser;
use tracing_subscriber::EnvFilter;
use zbus::fdo;
use zbus::zvariant::{OwnedValue, Value};

const BUS_NAME: &str = "org.cedarkit.Authority1";
const OBJECT_PATH: &str = "/org/cedarkit/Authority1";

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Directory to load `*.cedar` policy files from.
    #[arg(long, default_value = cedarkit_core::DEFAULT_POLICY_DIR)]
    policies: PathBuf,

    /// Serve on the session bus instead of the system bus.
    #[arg(long)]
    session: bool,
}

struct AuthorityService {
    authority: Authority,
}

#[zbus::interface(name = "org.cedarkit.Authority1")]
impl AuthorityService {
    /// Checks whether the user `uid` may perform `action_id` on `resource`.
    ///
    /// `resource` is in Cedar syntax (e.g. `Unit::"sshd.service"`).
    /// `resource_attrs` values may be booleans, integers, strings, `(ss)`
    /// entity references (type, id), or arrays of those. `resource_parents`
    /// are entities the resource is a member of, in Cedar syntax.
    ///
    /// Returns one of `"allow"`, `"deny"`, `"auth_self"`, `"auth_self_keep"`,
    /// `"auth_admin"` or `"auth_admin_keep"`.
    // TODO: verify the caller is a trusted mechanism, and actually run the
    // authentication challenge via a registered agent.
    async fn check_authorization(
        &self,
        uid: u32,
        action_id: String,
        resource: String,
        resource_attrs: HashMap<String, OwnedValue>,
        resource_parents: Vec<String>,
        details: HashMap<String, String>,
    ) -> fdo::Result<String> {
        let invalid = |e: &dyn std::fmt::Display| fdo::Error::InvalidArgs(e.to_string());

        let subject = Subject::from_uid(uid).map_err(|e| invalid(&e))?;
        let mut resource = Resource::parse(&resource).map_err(|e| invalid(&e))?;
        for (key, value) in &resource_attrs {
            let value = attr_value(value)
                .ok_or_else(|| invalid(&format!("unsupported value for attribute {key:?}")))?;
            resource = resource.with_attr(key.clone(), value);
        }
        for parent in &resource_parents {
            resource = resource.with_parent(Resource::parse(parent).map_err(|e| invalid(&e))?.uid);
        }
        let request = CheckRequest {
            subject,
            action_id,
            resource,
            details,
            // TODO: pass on authentication done through an agent.
            auth: Authentication::NONE,
        };

        let decision = self
            .authority
            .check(&request)
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        tracing::info!(
            uid,
            action = %request.action_id,
            resource = %request.resource.uid,
            ?decision,
            "authorization check"
        );

        Ok(decision.polkit_result().to_owned())
    }

    #[zbus(property)]
    fn backend_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
}

/// Converts a D-Bus attribute value into a Cedar attribute value.
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

    let authority = Authority::from_dir(&args.policies)
        .with_context(|| format!("loading policies from {}", args.policies.display()))?;
    let service = AuthorityService { authority };

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
