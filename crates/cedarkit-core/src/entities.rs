//! Entity data files: role memberships, and nothing else (docs/design.md,
//! section 8.3).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::schema::{CORE_APP, Declarations};

/// An entity that can be in a role.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Member {
    User(u32),
    Group(String),
    Role(String),
}

impl std::fmt::Display for Member {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User(uid) => write!(f, "User::\"{uid}\""),
            Self::Group(name) => write!(f, "Group::{name:?}"),
            Self::Role(name) => write!(f, "Role::{name:?}"),
        }
    }
}

/// The role memberships from all entity data files, combined.
#[derive(Debug, Default, Clone)]
pub(crate) struct Memberships {
    roles: BTreeMap<Member, BTreeSet<String>>,
}

impl Memberships {
    /// Adds the memberships in an entity data file, adding a message to
    /// `errors` for each one that breaks the rules. `app` is the vendor
    /// application the file belongs to, if it's a vendor file.
    pub fn add_file(
        &mut self,
        label: &str,
        app: Option<&str>,
        decls: &Declarations,
        text: &str,
        errors: &mut Vec<String>,
    ) {
        let mut problem = |msg: String| errors.push(format!("{label}: {msg}"));
        let json: Value = match serde_json::from_str(text) {
            Ok(json) => json,
            Err(e) => return problem(e.to_string()),
        };
        let Some(entities) = json.as_array() else {
            return problem("expected an array of entities".into());
        };

        for entity in entities {
            let Some(fields) = entity.as_object() else {
                problem("expected an entity object".into());
                continue;
            };
            let member = match fields.get("uid").map(entity_ref) {
                Some(Ok(("User", id))) => match id.parse() {
                    Ok(uid) => Member::User(uid),
                    Err(_) => {
                        problem(format!("User::{id:?}: users are identified by uid"));
                        continue;
                    }
                },
                Some(Ok(("Group", id))) => Member::Group(id.to_owned()),
                Some(Ok(("Role", id))) => Member::Role(id.to_owned()),
                Some(Ok((ty, id))) => {
                    problem(format!(
                        "{ty}::{id:?}: only users, groups and roles may be listed"
                    ));
                    continue;
                }
                Some(Err(e)) => {
                    problem(e);
                    continue;
                }
                None => {
                    problem("entity without a uid".into());
                    continue;
                }
            };

            let mut roles = BTreeSet::new();
            for (key, value) in fields {
                match key.as_str() {
                    "uid" => {}
                    "attrs" | "tags" if value.as_object().is_some_and(|o| o.is_empty()) => {}
                    "attrs" | "tags" => problem(format!("{member}: may not have {key}")),
                    "parents" => {
                        for parent in value.as_array().into_iter().flatten() {
                            match entity_ref(parent) {
                                Ok(("Role", id)) => {
                                    roles.insert(id.to_owned());
                                }
                                Ok((ty, id)) => problem(format!(
                                    "{member}: may only be in roles, not {ty}::{id:?}"
                                )),
                                Err(e) => problem(e),
                            }
                        }
                    }
                    _ => problem(format!("{member}: unexpected {key:?}")),
                }
            }

            if let Some(app) = app.filter(|app| *app != CORE_APP) {
                for role in &roles {
                    if !decls.owns(app, role) {
                        problem(format!(
                            "{member}: Role::{role:?} isn't one of {app}'s roles"
                        ));
                    }
                }
            }
            self.roles.entry(member).or_default().extend(roles);
        }
    }

    /// The roles `member` is directly in.
    pub fn roles_of(&self, member: &Member) -> impl Iterator<Item = &String> {
        self.roles.get(member).into_iter().flatten()
    }

    /// Every entity listed.
    pub fn members(&self) -> impl Iterator<Item = &Member> {
        self.roles.keys()
    }

    /// The roles some user or group is in, directly or through other roles.
    pub fn populated_roles(&self) -> BTreeSet<&String> {
        let mut populated = BTreeSet::new();
        let mut todo: Vec<&String> = self
            .roles
            .iter()
            .filter(|(m, _)| !matches!(m, Member::Role(_)))
            .flat_map(|(_, roles)| roles)
            .collect();
        while let Some(role) = todo.pop() {
            if populated.insert(role) {
                todo.extend(self.roles_of(&Member::Role(role.clone())));
            }
        }
        populated
    }
}

/// Reads an entity reference, `{ "type": …, "id": … }` or the same wrapped
/// in `__entity`.
fn entity_ref(value: &Value) -> Result<(&str, &str), String> {
    let value = value.get("__entity").unwrap_or(value);
    match (value["type"].as_str(), value["id"].as_str()) {
        (Some(ty), Some(id)) => Ok((ty, id)),
        _ => Err(format!("invalid entity reference {value}")),
    }
}
