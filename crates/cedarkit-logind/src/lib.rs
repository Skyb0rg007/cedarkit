//! logind's fact provider for CedarKit (docs/design.md, section 6.5).
//!
//! Tells CedarKit what logind knows about a process, as
//! `context.subject.logind`, and builds `logind::Session` resources. Its
//! types are declared in `policies/logind/logind.cedarschema`.

use cedarkit_core::{AttrValue, EntityUid, Facts, Resource, entity_uid};
use zbus::zvariant::OwnedObjectPath;
use zbus::{Connection, Proxy};

/// The provider's namespace.
pub const NAMESPACE: &str = "logind";

const DESTINATION: &str = "org.freedesktop.login1";

/// A login session, as logind reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    /// The session's user.
    pub uid: u32,
    pub seat: Option<String>,
    pub remote: bool,
    /// "user", "greeter", "lock-screen", "background", "manager", ...
    pub class: String,
    /// "tty", "x11", "wayland", "unspecified", ...
    pub type_: String,
    pub active: bool,
}

impl Session {
    /// `logind::Session::"<id>"`, with its attributes.
    pub fn resource(&self) -> Resource {
        let mut r = Resource::new(uid("Session", &self.id))
            .with_attr("user", user(self.uid))
            .with_attr("remote", AttrValue::Bool(self.remote))
            .with_attr("class", AttrValue::String(self.class.clone()))
            .with_attr("type", AttrValue::String(self.type_.clone()))
            .with_attr("active", AttrValue::Bool(self.active));
        if let Some(seat) = &self.seat {
            r = r.with_attr("seat", AttrValue::Entity(uid("Seat", seat)));
        }
        r
    }

    /// The session and its seat.
    fn entities(&self) -> Vec<Resource> {
        let mut entities = vec![self.resource()];
        if let Some(seat) = &self.seat {
            entities.push(Resource::new(uid("Seat", seat)));
        }
        entities
    }
}

/// What logind knows about a process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessInfo {
    /// The process's own session, if it's in one.
    pub session: Option<Session>,
    /// Its user's graphical session, if any.
    pub display: Option<Session>,
    /// Whether some session of the user is active.
    pub user_active: bool,
}

impl ProcessInfo {
    /// The facts for process `pid`, as `logind::Process::"<pid>"`.
    pub fn facts(&self, pid: u32) -> Facts {
        self.facts_for(&pid.to_string())
    }

    /// The facts, as `logind::Process::"<id>"`.
    pub fn facts_for(&self, id: &str) -> Facts {
        let mut process = Resource::new(uid("Process", id))
            .with_attr("user_active", AttrValue::Bool(self.user_active));
        let mut related = Vec::new();
        for (attr, session) in [("session", &self.session), ("display", &self.display)] {
            if let Some(session) = session {
                process = process.with_attr(attr, AttrValue::Entity(uid("Session", &session.id)));
                for entity in session.entities() {
                    if !related.iter().any(|r: &Resource| r.uid == entity.uid) {
                        related.push(entity);
                    }
                }
            }
        }
        Facts {
            provider: NAMESPACE.into(),
            process,
            related,
        }
    }
}

fn uid(ty: &str, id: &str) -> EntityUid {
    entity_uid(&format!("{NAMESPACE}::{ty}"), id).expect("logind's type names are valid")
}

fn user(uid: u32) -> AttrValue {
    AttrValue::Entity(entity_uid("User", &uid.to_string()).expect("User is a valid type name"))
}

/// A connection to logind.
pub struct Logind {
    conn: Connection,
}

impl Logind {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    /// Connects to logind on the system bus.
    pub async fn system() -> zbus::Result<Self> {
        Ok(Self::new(Connection::system().await?))
    }

    async fn proxy(
        &self,
        path: &OwnedObjectPath,
        interface: &'static str,
    ) -> zbus::Result<Proxy<'_>> {
        Proxy::new(&self.conn, DESTINATION, path.clone(), interface).await
    }

    async fn manager(&self) -> zbus::Result<Proxy<'_>> {
        Proxy::new(
            &self.conn,
            DESTINATION,
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await
    }

    /// The session with this id, if there is one.
    pub async fn session(&self, id: &str) -> zbus::Result<Option<Session>> {
        match self.manager().await?.call("GetSession", &(id,)).await {
            Ok(path) => self.session_at(&path).await.map(Some),
            Err(e) if is_missing(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn session_at(&self, path: &OwnedObjectPath) -> zbus::Result<Session> {
        let p = self.proxy(path, "org.freedesktop.login1.Session").await?;
        let (uid, _): (u32, OwnedObjectPath) = p.get_property("User").await?;
        let (seat, _): (String, OwnedObjectPath) = p.get_property("Seat").await?;
        Ok(Session {
            id: p.get_property("Id").await?,
            uid,
            seat: (!seat.is_empty()).then_some(seat),
            remote: p.get_property("Remote").await?,
            class: p.get_property("Class").await?,
            type_: p.get_property("Type").await?,
            active: p.get_property("Active").await?,
        })
    }

    /// What logind knows about process `pid`, running as `uid`.
    pub async fn process(&self, pid: u32, uid: u32) -> zbus::Result<ProcessInfo> {
        let manager = self.manager().await?;
        let session = match manager.call("GetSessionByPID", &(pid,)).await {
            Ok(path) => Some(self.session_at(&path).await?),
            Err(e) if is_missing(&e) => None,
            Err(e) => return Err(e),
        };

        let user: OwnedObjectPath = match manager.call("GetUser", &(uid,)).await {
            Ok(path) => path,
            // Not logged in.
            Err(e) if is_missing(&e) => {
                return Ok(ProcessInfo {
                    session,
                    ..ProcessInfo::default()
                });
            }
            Err(e) => return Err(e),
        };
        let p = self.proxy(&user, "org.freedesktop.login1.User").await?;
        let (display, display_path): (String, OwnedObjectPath) = p.get_property("Display").await?;
        let state: String = p.get_property("State").await?;
        let display = match display.is_empty() {
            true => None,
            false => Some(self.session_at(&display_path).await?),
        };
        Ok(ProcessInfo {
            session,
            display,
            user_active: state == "active",
        })
    }

    /// What logind knows about a session, as if about a process in it: for
    /// polkit's `unix-session` subjects. `None` if there's no such session.
    pub async fn session_info(&self, id: &str) -> zbus::Result<Option<ProcessInfo>> {
        let Some(session) = self.session(id).await? else {
            return Ok(None);
        };
        let manager = self.manager().await?;
        let user: OwnedObjectPath = match manager.call("GetUser", &(session.uid,)).await {
            Ok(path) => path,
            Err(e) if is_missing(&e) => {
                return Ok(Some(ProcessInfo {
                    session: Some(session),
                    ..ProcessInfo::default()
                }));
            }
            Err(e) => return Err(e),
        };
        let p = self.proxy(&user, "org.freedesktop.login1.User").await?;
        let state: String = p.get_property("State").await?;
        Ok(Some(ProcessInfo {
            session: Some(session),
            display: None,
            user_active: state == "active",
        }))
    }

    /// Fills in a `logind::Session` resource from logind. Other resources
    /// are left alone.
    pub async fn fill_resource(&self, resource: &mut Resource) -> zbus::Result<()> {
        if resource.uid.type_name().to_string() != format!("{NAMESPACE}::Session") {
            return Ok(());
        }
        let id = resource.uid.id().unescaped().to_owned();
        match self.session(&id).await? {
            Some(session) => *resource = session.resource(),
            None => return Err(zbus::Error::Failure(format!("no session {id:?}"))),
        }
        Ok(())
    }
}

/// Whether logind says the session, user or process has no session.
fn is_missing(e: &zbus::Error) -> bool {
    matches!(e, zbus::Error::MethodError(name, _, _)
        if name.as_str().starts_with("org.freedesktop.login1.No"))
}
