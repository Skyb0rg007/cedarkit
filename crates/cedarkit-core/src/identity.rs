use std::ffi::CString;

use nix::unistd::{self, Uid, getgrouplist};

use crate::Result;

/// A user account, as policies see it: `User::"<uid>"`, a member of each of
/// its groups (docs/design.md, section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    /// Absent for accounts without a name.
    pub name: Option<String>,
    /// Every group the account database reports, including the primary group.
    pub groups: Vec<Group>,
}

impl User {
    /// A user the account database knows nothing about: just a uid.
    pub fn new(uid: u32) -> Self {
        Self {
            uid,
            name: None,
            groups: Vec::new(),
        }
    }
}

/// A group, as policies see it: `Group::"<name>"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Group {
    pub name: String,
    pub gid: Option<u32>,
}

impl Group {
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            gid: None,
        }
    }
}

/// Looks up accounts: the users requests refer to, and who could pass a
/// challenge.
pub trait Directory: Send + Sync {
    /// The user with this uid, if there is one.
    fn user(&self, uid: u32) -> Result<Option<User>>;

    /// The user called `name`, if there is one.
    fn user_by_name(&self, name: &str) -> Result<Option<User>>;

    /// The uids of the members of the group called `name`.
    fn group_members(&self, name: &str) -> Result<Vec<u32>>;
}

/// The system's account database, via NSS.
pub struct Nss;

impl Nss {
    fn convert(user: unistd::User) -> Result<User> {
        let groups = match CString::new(user.name.as_str()) {
            Ok(name) => getgrouplist(&name, user.gid)?,
            Err(_) => vec![user.gid],
        };
        let mut groups: Vec<Group> = groups
            .into_iter()
            .filter_map(|gid| unistd::Group::from_gid(gid).ok().flatten())
            .map(|g| Group {
                name: g.name,
                gid: Some(g.gid.as_raw()),
            })
            .collect();
        groups.sort();
        groups.dedup();

        Ok(User {
            uid: user.uid.as_raw(),
            name: Some(user.name),
            groups,
        })
    }
}

impl Directory for Nss {
    fn user(&self, uid: u32) -> Result<Option<User>> {
        unistd::User::from_uid(Uid::from_raw(uid))?
            .map(Self::convert)
            .transpose()
    }

    fn user_by_name(&self, name: &str) -> Result<Option<User>> {
        unistd::User::from_name(name)?
            .map(Self::convert)
            .transpose()
    }

    // Only lists supplementary members, and users whose primary group it is
    // if NSS reports them as members too.
    fn group_members(&self, name: &str) -> Result<Vec<u32>> {
        let Some(group) = unistd::Group::from_name(name)? else {
            return Ok(Vec::new());
        };
        let mut uids = Vec::new();
        for member in &group.mem {
            if let Some(user) = unistd::User::from_name(member)? {
                uids.push(user.uid.as_raw());
            }
        }
        Ok(uids)
    }
}
