//! polkit's result labels, for the polkit-compatible front end
//! (docs/design.md, section 11). They aren't part of the native result.

use std::collections::{BTreeMap, HashMap};

use crate::schema::DetailType;
use crate::{AttrValue, Authority, Decision, Error, Resource, Result, entity_uid};

/// The polkit result for a decision about `subject`'s request: `yes`, `no`,
/// or `auth_self` if the only option is the subject, otherwise `auth_admin`,
/// with `_keep` if a remembered authentication would be accepted.
pub fn result(decision: &Decision, subject: u32) -> &'static str {
    match decision {
        Decision::Allow => "yes",
        Decision::Deny => "no",
        Decision::Challenge(options) => {
            let own = matches!(options.as_slice(), [only] if only.uid == subject);
            let keep = options.iter().all(|o| o.keep);
            match (own, keep) {
                (true, true) => "auth_self_keep",
                (true, false) => "auth_self",
                (false, true) => "auth_admin_keep",
                (false, false) => "auth_admin",
            }
        }
    }
}

/// An action, as polkit's `EnumerateActions` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionDescription {
    pub id: String,
    pub description: String,
    /// What authentication agents show.
    pub message: String,
    pub vendor: String,
    pub vendor_url: String,
    pub icon: String,
    /// The defaults its polkit `.policy` file declared for any, inactive and
    /// active sessions, e.g. `auth_admin_keep`. Like polkit, these describe
    /// the action as shipped, not what the policies currently decide.
    pub defaults: [String; 3],
    /// polkit's annotations, e.g. `org.freedesktop.policykit.imply`.
    pub annotations: BTreeMap<String, String>,
}

impl Authority {
    fn annotation(&self, action: &str, key: &str) -> Option<&str> {
        self.decls
            .actions
            .get(action)?
            .annotations
            .get(key)
            .map(String::as_str)
    }

    /// What authentication agents show for `action`: its `@message`, or
    /// failing that its `@doc`, or its id.
    pub fn message<'a>(&'a self, action: &'a str) -> &'a str {
        self.annotation(action, "message")
            .or_else(|| self.annotation(action, "doc"))
            .unwrap_or(action)
    }

    /// The icon authentication agents show for `action`, if any.
    pub fn icon(&self, action: &str) -> Option<&str> {
        self.annotation(action, "icon")
    }

    /// Who besides root may check `action` for other users' processes, from
    /// `@owners`, as polkit's `org.freedesktop.policykit.owner`: identities
    /// such as `unix-user:systemd-network`.
    pub fn owners(&self, action: &str) -> Vec<&str> {
        self.annotation(action, "owners")
            .map(|o| o.split_whitespace().collect())
            .unwrap_or_default()
    }

    /// Every declared action, as polkit describes them, by id.
    pub fn polkit_actions(&self) -> Vec<ActionDescription> {
        let mut actions: Vec<ActionDescription> = self
            .decls
            .actions
            .iter()
            .map(|(id, info)| {
                let get = |key: &str| info.annotations.get(key).cloned().unwrap_or_default();
                let mut defaults = ["no", "no", "no"].map(String::from);
                for (column, value) in defaults.iter_mut().zip(get("defaults").split_whitespace()) {
                    *column = value.to_owned();
                }
                let mut annotations = BTreeMap::new();
                for (key, polkit) in [
                    ("implies", "org.freedesktop.policykit.imply"),
                    ("owners", "org.freedesktop.policykit.owner"),
                ] {
                    if let Some(value) = info.annotations.get(key) {
                        annotations.insert(polkit.to_owned(), value.clone());
                    }
                }
                ActionDescription {
                    id: id.clone(),
                    description: get("doc"),
                    message: self.message(id).to_owned(),
                    vendor: get("vendor"),
                    vendor_url: get("vendor_url"),
                    icon: get("icon"),
                    defaults,
                    annotations,
                }
            })
            .collect();
        actions.sort_by(|a, b| a.id.cmp(&b.id));
        actions
    }

    /// Builds the resource of a polkit check of `action` from its details,
    /// following the `@detail` annotations (docs/design.md, section 6.4).
    /// Each resource type the action applies to is tried in order; the
    /// first whose identifying details are all present is used, and failing
    /// that the action's `@singleton`. Users are identified by the `uid`
    /// detail; types whose attributes CedarKit fills in itself, such as
    /// `logind::Session`, only need their id.
    ///
    /// With `fill_missing`, for mechanisms that don't pass the details yet
    /// (such as unpatched systemd), a resource is made up rather than the
    /// check failing: missing details are taken to be empty strings. Users,
    /// and types CedarKit fills in itself such as `logind::Session`, can't
    /// be made up, so they're skipped, as are types needing a missing attribute that isn't a
    /// string. polkit's defaults don't depend on the resource, so these
    /// decide as polkit would; policies that look at the resource, such as
    /// ownership rules, see only what the details said.
    pub fn polkit_resource(
        &self,
        action: &str,
        details: &HashMap<String, String>,
        fill_missing: bool,
    ) -> Result<Resource> {
        let info = self
            .decls
            .actions
            .get(action)
            .ok_or_else(|| Error::Request(format!("action {action:?} isn't declared")))?;
        for ty in &info.resource_types {
            if let Some(resource) = self.resource_from_details(ty, details, false)? {
                return Ok(resource);
            }
        }
        if let Some(uid) = &info.singleton {
            return Ok(Resource::new(uid.clone()));
        }
        if fill_missing {
            for ty in &info.resource_types {
                if let Some(resource) = self.resource_from_details(ty, details, true)? {
                    tracing::debug!(action, resource = %resource.uid, "made up from missing details");
                    return Ok(resource);
                }
            }
        }
        Err(Error::Request(format!(
            "the details don't say which resource {action} acts on"
        )))
    }

    /// A resource of type `ty` from the details, or `None` if they don't
    /// describe one. With `fill_missing`, missing details are empty strings.
    fn resource_from_details(
        &self,
        ty: &str,
        details: &HashMap<String, String>,
        fill_missing: bool,
    ) -> Result<Option<Resource>> {
        if ty == "User" {
            return details
                .get("uid")
                .map(|uid| Ok(Resource::new(entity_uid("User", uid)?)))
                .transpose();
        }
        let Some(rt) = self.decls.resource_types.get(ty) else {
            return Ok(None);
        };
        let Some(template) = rt.detail.as_deref() else {
            return Ok(None);
        };
        let id = match expand(template, details) {
            Some(id) => id,
            None if fill_missing && !rt.filled_in => expand_or_empty(template, details),
            None => return Ok(None),
        };
        let mut resource = Resource::new(entity_uid(ty, &id)?);
        for attr in &rt.attrs {
            match details.get(&attr.detail) {
                Some(value) => {
                    let value = detail_value(&attr.ty, value).ok_or_else(|| {
                        Error::Request(format!(
                            "detail {:?}: {value:?} isn't a {:?}",
                            attr.detail, attr.ty
                        ))
                    })?;
                    resource = resource.with_attr(attr.name.clone(), value);
                }
                None if attr.required && fill_missing && attr.ty == DetailType::String => {
                    resource =
                        resource.with_attr(attr.name.clone(), AttrValue::String(String::new()));
                }
                None if attr.required => return Ok(None),
                None => {}
            }
        }
        Ok(Some(resource))
    }
}

/// Fills in a template as [`expand`] does, with empty strings for missing
/// details.
fn expand_or_empty(template: &str, details: &HashMap<String, String>) -> String {
    let get = |key: &str| details.get(key).cloned().unwrap_or_default();
    if !template.contains('{') {
        return get(template);
    }
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let Some(end) = rest[start..].find('}').map(|e| e + start) else {
            break;
        };
        out.push_str(&get(&rest[start + 1..end]));
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Fills in a `@detail` template: either a detail's name, or a pattern
/// naming several, such as `{class}:{image}`. `None` if a detail is missing.
fn expand(template: &str, details: &HashMap<String, String>) -> Option<String> {
    if !template.contains('{') {
        return details.get(template).cloned();
    }
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let end = rest[start..].find('}')? + start;
        out.push_str(details.get(&rest[start + 1..end])?);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// Converts a polkit detail, always a string, to an attribute's type.
pub(crate) fn detail_value(ty: &DetailType, value: &str) -> Option<AttrValue> {
    Some(match ty {
        DetailType::String => AttrValue::String(value.to_owned()),
        DetailType::Long => AttrValue::Long(value.parse().ok()?),
        DetailType::Bool => AttrValue::Bool(match value {
            "true" | "1" | "yes" => true,
            "false" | "0" | "no" => false,
            _ => return None,
        }),
        // A detail holding a user is a uid (docs/design.md, section 6.4).
        DetailType::Entity(name) if name == "User" => {
            AttrValue::Entity(entity_uid("User", &value.parse::<u32>().ok()?.to_string()).ok()?)
        }
        DetailType::Entity(_) if value.contains("::") => value.parse().ok()?,
        DetailType::Entity(name) => AttrValue::Entity(entity_uid(name, value).ok()?),
        DetailType::Other => return None,
    })
}
