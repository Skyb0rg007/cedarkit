use std::collections::HashMap;
use std::str::FromStr;

use cedar_policy::{EntityId, EntityTypeName, EntityUid, RestrictedExpression};

use crate::{Error, Result};

/// The object an action operates on, e.g. `Unit::"sshd.service"`.
#[derive(Debug, Clone, PartialEq)]
pub struct Resource {
    pub uid: EntityUid,
    pub attrs: HashMap<String, AttrValue>,
    /// Entities this resource is a member of, e.g. the seat a session is on.
    pub parents: Vec<EntityUid>,
}

impl Resource {
    pub fn new(uid: EntityUid) -> Self {
        Self {
            uid,
            attrs: HashMap::new(),
            parents: Vec::new(),
        }
    }

    /// Parses a resource from Cedar entity syntax, e.g. `Unit::"sshd.service"`.
    pub fn parse(s: &str) -> Result<Self> {
        Ok(Self::new(parse_uid(s)?))
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: AttrValue) -> Self {
        self.attrs.insert(key.into(), value);
        self
    }

    pub fn with_parent(mut self, parent: EntityUid) -> Self {
        self.parents.push(parent);
        self
    }
}

/// An attribute value on a [`Resource`].
#[derive(Debug, Clone, PartialEq)]
pub enum AttrValue {
    Bool(bool),
    Long(i64),
    String(String),
    /// A reference to another entity, e.g. a session's owning `User`.
    Entity(EntityUid),
    Set(Vec<AttrValue>),
}

impl AttrValue {
    pub(crate) fn to_expr(&self) -> RestrictedExpression {
        match self {
            Self::Bool(b) => RestrictedExpression::new_bool(*b),
            Self::Long(n) => RestrictedExpression::new_long(*n),
            Self::String(s) => RestrictedExpression::new_string(s.clone()),
            Self::Entity(uid) => RestrictedExpression::new_entity_uid(uid.clone()),
            Self::Set(items) => RestrictedExpression::new_set(items.iter().map(Self::to_expr)),
        }
    }
}

impl FromStr for AttrValue {
    type Err = Error;

    /// Parses `true`/`false`, integers and `Type::"id"` entity references;
    /// anything else is a string.
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "true" => Self::Bool(true),
            "false" => Self::Bool(false),
            _ if s.contains("::") => Self::Entity(parse_uid(s)?),
            _ => s
                .parse()
                .map_or_else(|_| Self::String(s.to_owned()), Self::Long),
        })
    }
}

/// Builds an entity reference from a type name and id, e.g. `("Unit", "sshd.service")`.
pub fn entity_uid(ty: &str, id: &str) -> Result<EntityUid> {
    let ty = EntityTypeName::from_str(ty)
        .map_err(|e| Error::Request(format!("invalid entity type {ty:?}: {e}")))?;
    Ok(EntityUid::from_type_name_and_id(ty, EntityId::new(id)))
}

fn parse_uid(s: &str) -> Result<EntityUid> {
    EntityUid::from_str(s).map_err(|e| Error::Request(format!("invalid entity {s:?}: {e}")))
}
