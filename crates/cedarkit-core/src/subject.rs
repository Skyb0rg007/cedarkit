use std::ffi::CString;

use nix::unistd::{Group, Uid, User, getgrouplist};

use crate::{Error, Result};

/// The user an authorization check is being made for.
#[derive(Debug, Clone)]
pub struct Subject {
    pub uid: u32,
    pub name: String,
    pub groups: Vec<String>,
    /// Whether the subject's session is on a local seat.
    pub local: bool,
    /// Whether the subject's session is the active one on its seat.
    pub active: bool,
}

impl Subject {
    /// Resolves a subject from the user database.
    ///
    /// Session state (`local`/`active`) is left `false`; callers are expected
    /// to fill it in from logind.
    // TODO: query org.freedesktop.login1 for session state.
    pub fn from_uid(uid: u32) -> Result<Self> {
        let user = User::from_uid(Uid::from_raw(uid))?.ok_or(Error::UnknownUid(uid))?;
        Self::from_user(user)
    }

    /// Resolves the user running this process.
    pub fn current() -> Result<Self> {
        Self::from_uid(Uid::current().as_raw())
    }

    pub fn from_name(name: &str) -> Result<Self> {
        let user = User::from_name(name)?.ok_or_else(|| Error::UnknownUser(name.to_owned()))?;
        Self::from_user(user)
    }

    fn from_user(user: User) -> Result<Self> {
        let cname =
            CString::new(user.name.as_str()).map_err(|_| Error::UnknownUser(user.name.clone()))?;
        let groups = getgrouplist(&cname, user.gid)?
            .into_iter()
            .filter_map(|gid| Group::from_gid(gid).ok().flatten())
            .map(|g| g.name)
            .collect();

        Ok(Self {
            uid: user.uid.as_raw(),
            name: user.name,
            groups,
            local: false,
            active: false,
        })
    }
}
