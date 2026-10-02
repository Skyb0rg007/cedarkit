use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PartialEntities,
    PartialEntity, PartialEntityUid, PartialRequest, PolicySet, Request, RestrictedExpression,
    Schema, SchemaFragment, ValidationMode, Validator,
};

use crate::{Error, Resource, Result, Subject};

/// The outcome of an authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    /// Allowed, but only once the subject has authenticated.
    Challenge(Challenge),
}

impl Decision {
    /// The equivalent polkit result: `allow`, `deny`, or e.g. `auth_admin_keep`.
    pub fn polkit_result(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Challenge(c) => c.polkit_result(),
        }
    }
}

/// Who the subject has authenticated, or must authenticate, as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Identity {
    /// The subject themselves.
    Self_,
    /// An administrator.
    Admin,
}

/// How the subject has authenticated for a request. Policies see this as the
/// `Authentication` entity `context.auth`: `identity` is `"none"`, `"self"` or
/// `"admin"`, and `fresh` is whether the authentication was just entered
/// rather than remembered from an earlier one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authentication {
    pub identity: Option<Identity>,
    pub fresh: bool,
}

impl Authentication {
    pub const NONE: Self = Self {
        identity: None,
        fresh: false,
    };

    fn identity_str(self) -> &'static str {
        match self.identity {
            None => "none",
            Some(Identity::Self_) => "self",
            Some(Identity::Admin) => "admin",
        }
    }

    fn attrs(self) -> HashMap<String, RestrictedExpression> {
        HashMap::from([
            (
                "identity".to_owned(),
                RestrictedExpression::new_string(self.identity_str().to_owned()),
            ),
            (
                "fresh".to_owned(),
                RestrictedExpression::new_bool(self.fresh),
            ),
        ])
    }
}

impl Default for Authentication {
    fn default() -> Self {
        Self::NONE
    }
}

/// An authentication the subject must pass before an action is allowed,
/// mirroring polkit's `auth_self`, `auth_admin` and their `_keep` variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge {
    pub identity: Identity,
    /// Whether an authentication remembered from earlier is good enough
    /// (polkit's `_keep`), rather than one entered just now.
    pub keep: bool,
}

impl Challenge {
    pub const SELF: Self = Self {
        identity: Identity::Self_,
        keep: false,
    };
    pub const SELF_KEEP: Self = Self {
        identity: Identity::Self_,
        keep: true,
    };
    pub const ADMIN: Self = Self {
        identity: Identity::Admin,
        keep: false,
    };
    pub const ADMIN_KEEP: Self = Self {
        identity: Identity::Admin,
        keep: true,
    };

    /// Every challenge, from the least to the most demanding.
    const LADDER: [Self; 4] = [Self::SELF_KEEP, Self::SELF, Self::ADMIN_KEEP, Self::ADMIN];

    /// The weakest authentication that passes this challenge.
    fn authentication(self) -> Authentication {
        Authentication {
            identity: Some(self.identity),
            fresh: !self.keep,
        }
    }

    /// The equivalent polkit result, e.g. `auth_admin_keep`.
    pub fn polkit_result(self) -> &'static str {
        match self {
            Self::SELF => "auth_self",
            Self::SELF_KEEP => "auth_self_keep",
            Self::ADMIN => "auth_admin",
            Self::ADMIN_KEEP => "auth_admin_keep",
        }
    }
}

/// A request to check whether `subject` may perform `action_id` on `resource`.
#[derive(Debug, Clone)]
pub struct CheckRequest {
    pub subject: Subject,
    pub action_id: String,
    pub resource: Resource,
    /// polkit-style details. Only those declared in the action's context
    /// type, as `context.details`, are passed to policies.
    pub details: HashMap<String, String>,
    /// How the subject has already authenticated, if at all.
    pub auth: Authentication,
}

/// Human-readable problems found by [`validate`]. Warnings include policies
/// that can never apply, e.g. to a resource type their action doesn't act on.
#[derive(Debug, Default)]
pub struct Validation {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Validates policies against a Cedar schema.
pub fn validate(policies_src: &str, schema_src: &str) -> Result<Validation> {
    let policies = PolicySet::from_str(policies_src).map_err(Box::new)?;
    let (schema, schema_warnings) =
        Schema::from_cedarschema_str(schema_src).map_err(|e| Error::Schema(e.to_string()))?;
    let result = Validator::new(schema).validate(&policies, ValidationMode::default());
    Ok(Validation {
        errors: result.validation_errors().map(|e| e.to_string()).collect(),
        warnings: schema_warnings
            .map(|w| w.to_string())
            .chain(result.validation_warnings().map(|w| w.to_string()))
            .collect(),
    })
}

/// Holds the loaded policies and their schema, and evaluates requests
/// against them.
pub struct Authority {
    policies: PolicySet,
    schema: Schema,
    /// For each declared action, the details its context declares.
    details: HashMap<String, Vec<String>>,
    authorizer: Authorizer,
}

impl Authority {
    /// Loads every `*.cedar` policy and `*.cedarschema` schema file under `dir`.
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        Self::new(&read_tree(dir, "cedar")?, &read_tree(dir, "cedarschema")?)
    }

    /// Loads policies and their schema. The policies must validate against
    /// the schema.
    pub fn new(policies_src: &str, schema_src: &str) -> Result<Self> {
        let validation = validate(policies_src, schema_src)?;
        if !validation.errors.is_empty() {
            return Err(Error::Invalid(validation.errors.join("\n")));
        }

        let (schema, _) =
            Schema::from_cedarschema_str(schema_src).map_err(|e| Error::Schema(e.to_string()))?;
        Ok(Self {
            policies: PolicySet::from_str(policies_src).map_err(Box::new)?,
            schema,
            details: declared_details(schema_src)?,
            authorizer: Authorizer::new(),
        })
    }

    /// Decides whether the request is allowed as the subject has
    /// authenticated so far. If not, works out whether authenticating could
    /// help, and if so, which authentication is the weakest that would.
    pub fn check(&self, req: &CheckRequest) -> Result<Decision> {
        let Some(declared_details) = self.details.get(&req.action_id) else {
            tracing::warn!(action = req.action_id, "action not declared in the schema");
            return Ok(Decision::Deny);
        };

        let principal = uid("User", &req.subject.name);
        let action = uid("Action", &req.action_id);
        let auth = uid("Authentication", "request");
        let base = request_entities(&req.subject, &principal, &req.resource);
        let context = self.context(req, &action, &auth, declared_details)?;

        // The request with the subject authenticated as given.
        let concrete = |authentication: Authentication| -> Result<(Request, Entities)> {
            let entities = base.iter().cloned().chain([EntitySpec {
                uid: auth.clone(),
                attrs: authentication.attrs(),
                parents: HashSet::new(),
            }]);
            let entities = Entities::from_entities(
                entities
                    .map(EntitySpec::into_entity)
                    .collect::<Result<Vec<_>>>()?,
                Some(&self.schema),
            )
            .map_err(request_err)?;
            let request = Request::new(
                principal.clone(),
                action.clone(),
                req.resource.uid.clone(),
                context.clone(),
                Some(&self.schema),
            )
            .map_err(request_err)?;
            Ok((request, entities))
        };

        let (request, entities) = concrete(req.auth)?;
        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &entities);
        for err in response.diagnostics().errors() {
            tracing::warn!(%err, "policy evaluation error");
        }
        if response.decision() == cedar_policy::Decision::Allow {
            return Ok(Decision::Allow);
        }

        // Not allowed as things are. Evaluate again with the authentication
        // unknown: if that's denied, no authentication would help.
        let partial_request = PartialRequest::new(
            PartialEntityUid::from_concrete(principal.clone()),
            action.clone(),
            PartialEntityUid::from_concrete(req.resource.uid.clone()),
            Some(context.clone()),
            &self.schema,
        )
        .map_err(request_err)?;
        let partial_entities = PartialEntities::from_partial_entities(
            base.iter()
                .map(|e| e.to_partial(&self.schema))
                .chain([PartialEntity::new(
                    auth.clone(),
                    None,
                    Some(HashSet::new()),
                    None,
                    &self.schema,
                )
                .map_err(request_err)])
                .collect::<Result<Vec<_>>>()?,
            &self.schema,
        )
        .map_err(request_err)?;
        let residual = self
            .policies
            .tpe(&partial_request, &partial_entities, &self.schema)
            .map_err(request_err)?;
        if residual.decision() == Some(cedar_policy::Decision::Deny) {
            return Ok(Decision::Deny);
        }

        // Some authentication would help: find the weakest, by evaluating
        // only what's left of the policies.
        for challenge in Challenge::LADDER {
            let (request, entities) = concrete(challenge.authentication())?;
            let response = residual
                .reauthorize(&request, &entities)
                .map_err(request_err)?;
            if response.decision() == cedar_policy::Decision::Allow {
                return Ok(Decision::Challenge(challenge));
            }
        }
        Ok(Decision::Deny)
    }

    /// Builds the request context, typed as the action declares it.
    fn context(
        &self,
        req: &CheckRequest,
        action: &EntityUid,
        auth: &EntityUid,
        declared_details: &[String],
    ) -> Result<Context> {
        let mut context = serde_json::json!({
            "local": req.subject.local,
            "active": req.subject.active,
            "auth": { "__entity": { "type": auth.type_name().to_string(), "id": auth.id().unescaped() } },
        });
        if !declared_details.is_empty() {
            let details: serde_json::Map<_, _> = declared_details
                .iter()
                .map(|key| {
                    let value = req.details.get(key).ok_or_else(|| {
                        Error::Request(format!("missing detail {key:?} for {}", req.action_id))
                    })?;
                    Ok((key.clone(), value.clone().into()))
                })
                .collect::<Result<_>>()?;
            context["details"] = details.into();
        }
        Context::from_json_value(context, Some((&self.schema, action))).map_err(request_err)
    }
}

/// Describes a Cedar error including its causes, which say e.g. which
/// attribute an entity is missing.
fn request_err(e: impl std::error::Error) -> Error {
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        msg.push_str(": ");
        msg.push_str(&cause.to_string());
        source = cause.source();
    }
    Error::Request(msg)
}

/// Reads, from the schema's JSON form, the details each action's context
/// declares (the attributes of its `details` record).
fn declared_details(schema_src: &str) -> Result<HashMap<String, Vec<String>>> {
    let schema_err = |e: &dyn std::fmt::Display| Error::Schema(e.to_string());
    let (fragment, _) =
        SchemaFragment::from_cedarschema_str(schema_src).map_err(|e| schema_err(&e))?;
    let json = fragment.to_json_value().map_err(|e| schema_err(&e))?;

    let mut details = HashMap::new();
    for namespace in json.as_object().into_iter().flat_map(|m| m.values()) {
        let common = &namespace["commonTypes"];
        // A type is either written out, or a reference to a common type.
        let resolve = |ty: &serde_json::Value| -> serde_json::Value {
            let name = ty
                .get("name")
                .filter(|_| ty["type"] == "EntityOrCommon")
                .or_else(|| ty.get("type").filter(|t| t != &"Record"));
            match name.and_then(|n| n.as_str()).and_then(|n| common.get(n)) {
                Some(t) => t.clone(),
                None => ty.clone(),
            }
        };

        for (action, decl) in namespace["actions"].as_object().into_iter().flatten() {
            let context = resolve(&decl["appliesTo"]["context"]);
            let keys = resolve(&context["attributes"]["details"])["attributes"]
                .as_object()
                .map(|attrs| attrs.keys().cloned().collect())
                .unwrap_or_default();
            details.insert(action.clone(), keys);
        }
    }
    Ok(details)
}

/// Concatenates every file with extension `ext` under `dir`, recursively and
/// in lexical path order.
pub fn read_tree(dir: &Path, ext: &str) -> Result<String> {
    fn walk(dir: &Path, ext: &str, paths: &mut Vec<PathBuf>) -> Result<()> {
        let io_err = |source| Error::Io {
            path: dir.to_owned(),
            source,
        };
        for entry in fs::read_dir(dir).map_err(io_err)? {
            let path = entry.map_err(io_err)?.path();
            if path.is_dir() {
                walk(&path, ext, paths)?;
            } else if path.extension().is_some_and(|e| e == ext) {
                paths.push(path);
            }
        }
        Ok(())
    }

    let mut paths = Vec::new();
    walk(dir, ext, &mut paths)?;
    paths.sort();

    let mut src = String::new();
    for path in &paths {
        tracing::debug!(path = %path.display(), "loading file");
        let text = fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        src.push_str(&text);
        src.push('\n');
    }
    Ok(src)
}

fn uid(ty: &str, id: &str) -> EntityUid {
    let ty = EntityTypeName::from_str(ty).expect("entity type names are static and valid");
    EntityUid::from_type_name_and_id(ty, EntityId::new(id))
}

/// An entity for a request, before it's converted for concrete or partial
/// evaluation.
#[derive(Clone)]
struct EntitySpec {
    uid: EntityUid,
    attrs: HashMap<String, RestrictedExpression>,
    parents: HashSet<EntityUid>,
}

impl EntitySpec {
    fn into_entity(self) -> Result<Entity> {
        Entity::new(self.uid, self.attrs, self.parents).map_err(request_err)
    }

    fn to_partial(&self, schema: &Schema) -> Result<PartialEntity> {
        let attrs: BTreeMap<_, _> = self
            .attrs
            .iter()
            .map(|(k, v)| (k.as_str().into(), v.clone()))
            .collect();
        PartialEntity::new(
            self.uid.clone(),
            Some(attrs),
            Some(self.parents.clone()),
            Some(BTreeMap::new()),
            schema,
        )
        .map_err(request_err)
    }
}

/// The entities for a request: the principal and its groups, the resource,
/// and placeholders for any of the resource's parents.
fn request_entities(
    subject: &Subject,
    principal: &EntityUid,
    resource: &Resource,
) -> Vec<EntitySpec> {
    let groups: HashSet<EntityUid> = subject.groups.iter().map(|g| uid("Group", g)).collect();

    let mut entities: HashMap<EntityUid, EntitySpec> = groups
        .iter()
        .map(|g| {
            (
                g.clone(),
                EntitySpec {
                    uid: g.clone(),
                    attrs: HashMap::new(),
                    parents: HashSet::new(),
                },
            )
        })
        .collect();

    entities.insert(
        principal.clone(),
        EntitySpec {
            uid: principal.clone(),
            attrs: HashMap::from([
                (
                    "name".to_owned(),
                    RestrictedExpression::new_string(subject.name.clone()),
                ),
                (
                    "uid".to_owned(),
                    RestrictedExpression::new_long(subject.uid.into()),
                ),
            ]),
            parents: groups,
        },
    );

    // When the resource is the principal itself (e.g. a user acting on their
    // own account), the principal's entity already describes it.
    entities
        .entry(resource.uid.clone())
        .or_insert_with(|| EntitySpec {
            uid: resource.uid.clone(),
            attrs: resource
                .attrs
                .iter()
                .map(|(k, v)| (k.clone(), v.to_expr()))
                .collect(),
            parents: resource.parents.iter().cloned().collect(),
        });
    for parent in &resource.parents {
        entities
            .entry(parent.clone())
            .or_insert_with(|| EntitySpec {
                uid: parent.clone(),
                attrs: HashMap::new(),
                parents: HashSet::new(),
            });
    }

    entities.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttrValue;

    const SCHEMA: &str = r#"
        entity Group;
        entity User in [Group] { name: String, uid: Long };
        entity System;
        entity Seat;
        entity Session in [Seat] { owner: User };
        entity Authentication { identity: String, fresh: Bool };

        type Ctx = { local: Bool, active: Bool, auth: Authentication };

        action "org.example.action", "org.freedesktop.login1.reboot" appliesTo {
            principal: [User], resource: [System], context: Ctx,
        };
        action "org.freedesktop.login1.lock-sessions" appliesTo {
            principal: [User], resource: [Session], context: Ctx,
        };
        action "org.example.verb" appliesTo {
            principal: [User], resource: [System],
            context: { local: Bool, active: Bool, auth: Authentication, details: { verb: String } },
        };
    "#;

    const SELF_KEEP: &str = r#"["self", "admin"].contains(context.auth.identity)"#;
    const SELF: &str = r#"["self", "admin"].contains(context.auth.identity) && context.auth.fresh"#;
    const ADMIN_KEEP: &str = r#"context.auth.identity == "admin""#;
    const ADMIN: &str = r#"context.auth.identity == "admin" && context.auth.fresh"#;

    fn authority(policies: &str) -> Authority {
        Authority::new(policies, SCHEMA).unwrap()
    }

    fn request(groups: &[&str], action: &str, active: bool) -> CheckRequest {
        CheckRequest {
            subject: Subject {
                uid: 1000,
                name: "alice".into(),
                groups: groups.iter().map(|g| g.to_string()).collect(),
                local: true,
                active,
            },
            action_id: action.into(),
            resource: Resource::parse(r#"System::"local""#).unwrap(),
            details: HashMap::new(),
            auth: Authentication::NONE,
        }
    }

    fn authenticated(identity: Identity, fresh: bool) -> CheckRequest {
        CheckRequest {
            auth: Authentication {
                identity: Some(identity),
                fresh,
            },
            ..request(&[], "org.example.action", true)
        }
    }

    #[test]
    fn invalid_policies_are_refused() {
        // `System` has no `owner`.
        let err = Authority::new(
            "permit (principal, action, resource) when { resource.owner == principal };",
            SCHEMA,
        );
        assert!(matches!(err, Err(Error::Invalid(_))));
    }

    #[test]
    fn undeclared_actions_are_denied() {
        let authority = authority("permit (principal, action, resource);");
        assert_eq!(
            authority
                .check(&request(&[], "org.example.undeclared", true))
                .unwrap(),
            Decision::Deny
        );
    }

    #[test]
    fn resource_attrs_and_parents() {
        let authority = authority(
            r#"
            permit (principal, action, resource is Session in Seat::"seat0")
            when { resource.owner == principal };
            "#,
        );
        let alice = Resource::parse(r#"User::"alice""#).unwrap().uid;
        let bob = Resource::parse(r#"User::"bob""#).unwrap().uid;
        let seat0 = Resource::parse(r#"Seat::"seat0""#).unwrap().uid;
        let session = |owner, seat| {
            Resource::parse(r#"Session::"3""#)
                .unwrap()
                .with_attr("owner", AttrValue::Entity(owner))
                .with_parent(seat)
        };
        let check = |resource| {
            let req = CheckRequest {
                resource,
                ..request(&[], "org.freedesktop.login1.lock-sessions", true)
            };
            authority.check(&req).unwrap()
        };

        assert_eq!(
            check(session(alice.clone(), seat0.clone())),
            Decision::Allow
        );
        assert_eq!(check(session(bob, seat0)), Decision::Deny);
        assert_eq!(
            check(session(
                alice,
                Resource::parse(r#"Seat::"seat1""#).unwrap().uid
            )),
            Decision::Deny
        );
    }

    /// Each polkit result asks for the matching challenge, and is allowed once
    /// the subject has authenticated well enough.
    #[test]
    fn challenges() {
        let check = |condition: &str, req: &CheckRequest| {
            authority(&format!(
                "permit (principal, action, resource) when {{ {condition} }};"
            ))
            .check(req)
            .unwrap()
        };
        let none = request(&[], "org.example.action", true);

        assert_eq!(
            check(SELF_KEEP, &none),
            Decision::Challenge(Challenge::SELF_KEEP)
        );
        assert_eq!(check(SELF, &none), Decision::Challenge(Challenge::SELF));
        assert_eq!(
            check(ADMIN_KEEP, &none),
            Decision::Challenge(Challenge::ADMIN_KEEP)
        );
        assert_eq!(check(ADMIN, &none), Decision::Challenge(Challenge::ADMIN));

        // A remembered authentication satisfies _keep, but not the rest.
        assert_eq!(
            check(SELF_KEEP, &authenticated(Identity::Self_, false)),
            Decision::Allow
        );
        assert_eq!(
            check(SELF, &authenticated(Identity::Self_, false)),
            Decision::Challenge(Challenge::SELF)
        );
        // Authenticating as an admin also counts as authenticating yourself.
        assert_eq!(
            check(SELF, &authenticated(Identity::Admin, true)),
            Decision::Allow
        );
        assert_eq!(
            check(ADMIN_KEEP, &authenticated(Identity::Self_, true)),
            Decision::Challenge(Challenge::ADMIN_KEEP)
        );
    }

    /// When no authentication could help, the result is a denial rather than
    /// a prompt.
    #[test]
    fn deny_without_prompting() {
        let authority = authority(&format!(
            r#"
            permit (principal, action, resource) when {{ {ADMIN} }};
            forbid (principal, action, resource) unless {{ context.local }};
            "#
        ));
        let local = request(&[], "org.example.action", true);
        let remote = CheckRequest {
            subject: Subject {
                local: false,
                ..local.subject.clone()
            },
            ..local.clone()
        };

        assert_eq!(
            authority.check(&local).unwrap(),
            Decision::Challenge(Challenge::ADMIN)
        );
        assert_eq!(authority.check(&remote).unwrap(), Decision::Deny);
    }

    /// A `forbid ... unless` makes an action stricter.
    #[test]
    fn tightening() {
        let check = |permitted: &str, required: &str| {
            authority(&format!(
                r#"
                permit (principal, action, resource) when {{ {permitted} }};
                forbid (principal, action, resource) unless {{ {required} }};
                "#
            ))
            .check(&request(&[], "org.example.action", true))
            .unwrap()
        };

        assert_eq!(
            check(SELF_KEEP, ADMIN),
            Decision::Challenge(Challenge::ADMIN)
        );
        assert_eq!(
            check(ADMIN_KEEP, ADMIN),
            Decision::Challenge(Challenge::ADMIN)
        );
        assert_eq!(
            check("true", SELF_KEEP),
            Decision::Challenge(Challenge::SELF_KEEP)
        );
        // A weaker requirement doesn't loosen anything.
        assert_eq!(
            check(ADMIN, SELF_KEEP),
            Decision::Challenge(Challenge::ADMIN)
        );
        // Nor does a requirement allow anything by itself.
        assert_eq!(check("false", SELF_KEEP), Decision::Deny);
    }

    /// Only the details an action declares are passed to policies.
    #[test]
    fn declared_details() {
        let authority = authority(
            r#"
            permit (principal, action == Action::"org.example.verb", resource)
            when { context.details.verb == "terminate" };
            "#,
        );
        let with = |details: &[(&str, &str)]| CheckRequest {
            details: details
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..request(&[], "org.example.verb", true)
        };

        assert_eq!(
            authority
                .check(&with(&[("verb", "terminate"), ("machine", "box")]))
                .unwrap(),
            Decision::Allow
        );
        assert_eq!(
            authority.check(&with(&[("verb", "copy")])).unwrap(),
            Decision::Deny
        );
        assert!(authority.check(&with(&[])).is_err());
    }

    #[test]
    fn decisions() {
        let authority = authority(&format!(
            r#"
            permit (principal in Group::"wheel", action, resource)
            when {{ {SELF} }};

            permit (principal, action == Action::"org.freedesktop.login1.reboot", resource)
            when {{ context.local && context.active }};
            "#
        ));
        let check =
            |groups, action, active| authority.check(&request(groups, action, active)).unwrap();

        assert_eq!(
            check(&[], "org.freedesktop.login1.reboot", true),
            Decision::Allow
        );
        assert_eq!(
            check(&[], "org.freedesktop.login1.reboot", false),
            Decision::Deny
        );
        assert_eq!(
            check(&["wheel"], "org.example.action", false),
            Decision::Challenge(Challenge::SELF)
        );
        // A permit that needs no authentication wins over one that does.
        assert_eq!(
            check(&["wheel"], "org.freedesktop.login1.reboot", true),
            Decision::Allow
        );
    }
}
