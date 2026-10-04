use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityUid, PolicySet, Request, RestrictedExpression,
    Schema, ValidationMode, Validator,
};

use crate::entities::{Member, Memberships};
use crate::policies;
use crate::schema::{self, Declarations, Fragment};
use crate::sources::{self, Kind, Layout, Origin, Source};
use crate::{AttrValue, Directory, Error, Nss, Resource, Result, Subject, User, entity_uid};

/// An authentication by `user`, given for `action` on `resource`
/// (docs/design.md, section 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authentication {
    pub user: u32,
    /// Given during this check, rather than remembered from an earlier one.
    pub fresh: bool,
    pub action: String,
    pub resource: EntityUid,
}

impl Authentication {
    /// An authentication by `user` just given for this request.
    pub fn fresh(user: u32, req: &CheckRequest) -> Self {
        Self {
            user,
            fresh: true,
            action: req.action_id.clone(),
            resource: req.resource.uid.clone(),
        }
    }

    /// The same authentication, remembered for later requests.
    pub fn remembered(self) -> Self {
        Self {
            fresh: false,
            ..self
        }
    }
}

/// A request to check whether the subject may perform `action_id` on
/// `resource` (docs/design.md, section 4).
#[derive(Debug, Clone)]
pub struct CheckRequest {
    pub subject: Subject,
    pub action_id: String,
    pub resource: Resource,
    /// Details for `context.details`. Those the action doesn't declare are
    /// dropped.
    pub details: HashMap<String, AttrValue>,
    /// How the subject has authenticated: authentications remembered for
    /// the subject process, and any given just now.
    pub authentications: Vec<Authentication>,
}

impl CheckRequest {
    pub fn new(subject: Subject, action_id: impl Into<String>, resource: Resource) -> Self {
        Self {
            subject,
            action_id: action_id.into(),
            resource,
            details: HashMap::new(),
            authentications: Vec::new(),
        }
    }
}

/// The result of a check (docs/design.md, section 9.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    /// Allowed once one of these users authenticates. The subject is first,
    /// if listed.
    Challenge(Vec<ChallengeOption>),
}

impl Decision {
    /// `allow`, `deny` or `challenge`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Challenge(_) => "challenge",
        }
    }
}

/// A user whose authentication would pass a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeOption {
    pub uid: u32,
    pub name: Option<String>,
    /// Whether an authentication by them would also be accepted once
    /// remembered, rather than only when fresh.
    pub keep: bool,
}

/// A decision, and why it was made: for an allow, the policies that allowed
/// it; for a deny, the policies that forbade it, or what went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub decision: Decision,
    pub reasons: Vec<String>,
    /// For an allow, the authentication it needed, if any.
    pub authentication: Option<Authentication>,
}

impl Outcome {
    fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Deny,
            reasons: vec![reason.into()],
            authentication: None,
        }
    }
}

/// A loaded [`Authority`], and problems that didn't stop it loading.
pub struct Loaded {
    pub authority: Authority,
    pub warnings: Vec<String>,
}

/// Holds the loaded schema, policies and role memberships, and evaluates
/// requests against them.
pub struct Authority {
    policies: PolicySet,
    schema: Schema,
    pub(crate) decls: Declarations,
    /// The fact providers the subject schema declares.
    providers: BTreeSet<String>,
    memberships: Memberships,
    directory: Box<dyn Directory>,
    authorizer: Authorizer,
}

/// The id of the entities CedarKit builds once per request.
const REQUEST: &str = "";

impl Authority {
    /// Loads the files in `layout` (docs/design.md, section 8).
    pub fn load(layout: &Layout) -> Result<Loaded> {
        let sources = sources::read_sources(layout)?;
        let subject = sources::read_subject_schema(layout)?;
        Self::from_sources(
            &sources,
            &layout.subject_schema.display().to_string(),
            &subject,
        )
    }

    /// Loads schema, policy and entity data files, and the subject schema.
    /// Fails, naming every problem, if any file breaks the rules or any
    /// policy doesn't validate.
    pub fn from_sources(sources: &[Source], subject_label: &str, subject: &str) -> Result<Loaded> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let done = |errors: Vec<String>| {
            if errors.is_empty() {
                Ok(())
            } else {
                Err(Error::Load(errors))
            }
        };

        let (fragments, decls) = read_schemas(sources, &mut errors);
        let subject = Fragment::parse(subject_label.to_owned(), None, subject);
        done(std::mem::take(&mut errors))?;
        let subject = subject.map_err(|e| Error::Load(vec![e]))?;

        for f in &fragments {
            decls.check_vendor(f, &mut errors);
        }
        let providers = decls.check_subject(&subject, &mut errors, &mut warnings);
        done(std::mem::take(&mut errors))?;

        let schema = Schema::from_schema_fragments(
            fragments.into_iter().chain([subject]).map(|f| f.fragment),
        )
        .map_err(|e| Error::Load(vec![format!("schema: {}", describe(&e))]))?;

        let mut policies = PolicySet::new();
        let mut memberships = Memberships::default();
        for s in sources {
            let label = s.path.display().to_string();
            let app = match &s.origin {
                Origin::Vendor(app) => Some(app.as_str()),
                Origin::Admin => None,
            };
            match s.kind {
                Kind::Schema => {}
                Kind::Policies => {
                    policies::add_file(&mut policies, &label, app, &decls, &s.text, &mut errors)
                }
                Kind::Entities => {
                    memberships.add_file(&label, app, &decls, &s.text, &mut errors);
                }
            }
        }

        let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        errors.extend(validation.validation_errors().map(describe));
        warnings.extend(validation.validation_warnings().map(|w| w.to_string()));
        done(errors)?;

        Ok(Loaded {
            authority: Self {
                policies,
                schema,
                decls,
                providers,
                memberships,
                directory: Box::new(Nss),
                authorizer: Authorizer::new(),
            },
            warnings,
        })
    }

    /// Uses `directory` to look up users, rather than the system's account
    /// database.
    pub fn with_directory(mut self, directory: impl Directory + 'static) -> Self {
        self.directory = Box::new(directory);
        self
    }

    /// Whether `action` is declared, and so can be checked.
    pub fn is_declared(&self, action: &str) -> bool {
        self.decls.actions.contains_key(action)
    }

    /// The resource `action` always acts on, if it declares one.
    pub fn singleton(&self, action: &str) -> Option<&EntityUid> {
        self.decls.actions.get(action)?.singleton.as_ref()
    }

    /// What `action` does, from its `@doc` annotation.
    pub fn description(&self, action: &str) -> Option<&str> {
        self.decls.actions.get(action)?.description.as_deref()
    }

    /// Converts string details, such as polkit's, to the types `action`
    /// declares for them. Details it doesn't declare are dropped.
    pub fn parse_details(
        &self,
        action: &str,
        details: &HashMap<String, String>,
    ) -> Result<HashMap<String, AttrValue>> {
        let Some(declared) = self
            .decls
            .actions
            .get(action)
            .and_then(|a| a.details.as_ref())
        else {
            return Ok(HashMap::new());
        };
        let mut out = HashMap::new();
        for (key, value) in details {
            let Some(ty) = declared.get(key) else {
                continue;
            };
            let parsed = crate::polkit::detail_value(ty, value).ok_or_else(|| {
                Error::Request(format!("detail {key:?}: {value:?} isn't a {ty:?}"))
            })?;
            out.insert(key.clone(), parsed);
        }
        Ok(out)
    }

    /// Warnings about policies that are valid but probably not what was
    /// meant (docs/design.md, section 8.4), beyond those from loading.
    pub fn lint(&self) -> Vec<String> {
        policies::lint(&self.policies, &self.memberships.populated_roles())
    }

    /// Decides whether the request is allowed, denied, or allowed once
    /// someone authenticates (docs/design.md, section 9).
    pub fn check(&self, req: &CheckRequest) -> Outcome {
        let outcome = self.try_check(req).unwrap_or_else(Outcome::deny);
        tracing::debug!(
            action = req.action_id,
            resource = %req.resource.uid,
            decision = outcome.decision.as_str(),
            reasons = ?outcome.reasons,
            "checked"
        );
        outcome
    }

    fn try_check(&self, req: &CheckRequest) -> Result<Outcome, String> {
        let prepared = self.prepare(req)?;

        let unauthenticated = AuthState {
            user: None,
            fresh: false,
            action: req.action_id.clone(),
            same_resource: true,
        };
        // Any evaluation error denies: a forbid that fails to evaluate must
        // not stop forbidding.
        let forbidden = match self.evaluate(&prepared, &unauthenticated)? {
            Eval::Allow(reasons) => {
                return Ok(Outcome {
                    decision: Decision::Allow,
                    reasons,
                    authentication: None,
                });
            }
            Eval::Deny(forbids) => forbids,
        };

        for auth in &req.authentications {
            let user = match self.resolve(&prepared.users, auth.user) {
                Ok(user) => user,
                Err(e) => {
                    tracing::warn!("ignoring authentication: {e}");
                    continue;
                }
            };
            let state = AuthState {
                user: Some(user),
                fresh: auth.fresh,
                action: auth.action.clone(),
                same_resource: auth.resource == req.resource.uid,
            };
            match self.evaluate(&prepared, &state) {
                Ok(Eval::Allow(mut reasons)) => {
                    reasons.push(format!(
                        "{} authentication by uid {}",
                        if auth.fresh { "fresh" } else { "remembered" },
                        auth.user
                    ));
                    return Ok(Outcome {
                        decision: Decision::Allow,
                        reasons,
                        authentication: Some(auth.clone()),
                    });
                }
                Ok(Eval::Deny(_)) => {}
                Err(e) => tracing::warn!(uid = auth.user, "authentication not accepted: {e}"),
            }
        }

        let mut options = Vec::new();
        for uid in self.candidates(req, &prepared) {
            let user = match self.resolve(&prepared.users, uid) {
                Ok(user) => user,
                Err(e) => {
                    tracing::debug!("not asking uid {uid}: {e}");
                    continue;
                }
            };
            let passes = |fresh| {
                let state = AuthState {
                    user: Some(user.clone()),
                    fresh,
                    action: req.action_id.clone(),
                    same_resource: true,
                };
                matches!(self.evaluate(&prepared, &state), Ok(Eval::Allow(_)))
            };
            let keep = passes(false);
            if keep || passes(true) {
                options.push(ChallengeOption {
                    uid,
                    name: user.name.clone(),
                    keep,
                });
            }
        }

        if options.is_empty() {
            let mut reasons: Vec<String> = forbidden
                .into_iter()
                .map(|id| format!("forbidden by {id}"))
                .collect();
            if reasons.is_empty() {
                reasons.push("no policy allows it, even with authentication".into());
            }
            return Ok(Outcome {
                decision: Decision::Deny,
                reasons,
                authentication: None,
            });
        }
        Ok(Outcome {
            decision: Decision::Challenge(options),
            reasons: Vec::new(),
            authentication: None,
        })
    }

    /// The users who might pass a challenge: the subject, every member of a
    /// role, and the users the request's entities refer to, such as the
    /// resource's owner. The subject is first.
    fn candidates(&self, req: &CheckRequest, prepared: &Prepared) -> Vec<u32> {
        let mut uids = BTreeSet::new();
        for member in self.memberships.members() {
            match member {
                Member::User(uid) => {
                    uids.insert(*uid);
                }
                Member::Group(name) => match self.directory.group_members(name) {
                    Ok(members) => uids.extend(members),
                    Err(e) => tracing::warn!(group = name, "can't list members: {e}"),
                },
                Member::Role(_) => {}
            }
        }
        uids.extend(prepared.users.keys());

        let subject = req.subject.user.uid;
        uids.remove(&subject);
        [subject].into_iter().chain(uids).collect()
    }

    /// A user, from those already resolved for the request or from the
    /// directory.
    fn resolve(&self, users: &BTreeMap<u32, User>, uid: u32) -> Result<User, String> {
        if let Some(user) = users.get(&uid) {
            return Ok(user.clone());
        }
        match self.directory.user(uid) {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(format!("there's no user with uid {uid}")),
            Err(e) => Err(format!("can't look up uid {uid}: {e}")),
        }
    }

    /// Builds the request and the entities that don't depend on how the
    /// subject has authenticated.
    fn prepare(&self, req: &CheckRequest) -> Result<Prepared, String> {
        let Some(info) = self.decls.actions.get(&req.action_id) else {
            return Err(format!("action {:?} isn't declared", req.action_id));
        };

        let mut specs = Specs::default();
        for member in self.memberships.members() {
            let roles: HashSet<EntityUid> = self
                .memberships
                .roles_of(member)
                .map(|r| uid("Role", r))
                .collect();
            for role in &roles {
                specs.add(Spec::new(role.clone()));
            }
            let entity = match member {
                Member::Group(name) => uid("Group", name),
                Member::Role(name) => uid("Role", name),
                Member::User(_) => continue,
            };
            specs.add(Spec {
                uid: entity,
                attrs: HashMap::new(),
                parents: roles,
            });
        }

        // The users the request's entities refer to, which CedarKit builds
        // itself.
        let mut referenced = BTreeSet::new();

        let mut subject_attrs = HashMap::new();
        for facts in &req.subject.facts {
            if !self.providers.contains(&facts.provider) {
                tracing::debug!(provider = facts.provider, "ignoring facts from provider");
                continue;
            }
            let expected = &self.decls.providers[&facts.provider];
            if facts.process.uid.type_name().to_string() != *expected {
                return Err(format!(
                    "{}'s facts must be a {expected}, not {}",
                    facts.provider, facts.process.uid
                ));
            }
            for entity in [&facts.process].into_iter().chain(&facts.related) {
                let ty = entity.uid.type_name().to_string();
                if !ty.starts_with(&format!("{}::", facts.provider)) {
                    return Err(format!(
                        "{} may only report entities in its namespace, not {}",
                        facts.provider, entity.uid
                    ));
                }
                specs.add(Spec::from_resource(entity));
                users_in(&entity.attrs, &mut referenced);
            }
            subject_attrs.insert(
                facts.provider.clone(),
                RestrictedExpression::new_entity_uid(facts.process.uid.clone()),
            );
        }
        specs.add(Spec {
            uid: uid("Subject", REQUEST),
            attrs: subject_attrs,
            parents: HashSet::new(),
        });

        let resource = &req.resource;
        if resource.uid.type_name().to_string() == "User" {
            referenced.insert(resource.uid.id().unescaped().to_owned());
        } else {
            specs.add(Spec::from_resource(resource));
            for parent in &resource.parents {
                specs.add(Spec::new(parent.clone()));
            }
            users_in(&resource.attrs, &mut referenced);
        }

        let mut users = BTreeMap::from([(req.subject.user.uid, req.subject.user.clone())]);
        for id in referenced {
            let uid = id
                .parse()
                .map_err(|_| format!("User::{id:?}: users are identified by uid"))?;
            let user = self.resolve(&users, uid)?;
            users.insert(uid, user);
        }
        for user in users.values() {
            self.add_user(&mut specs, user);
        }

        let mut context = serde_json::json!({
            "subject": entity_json(&uid("Subject", REQUEST)),
            "auth": entity_json(&uid("Authentication", REQUEST)),
        });
        if let Some(declared) = &info.details {
            let details: serde_json::Map<_, _> = req
                .details
                .iter()
                .filter(|(key, _)| declared.contains_key(*key))
                .map(|(key, value)| (key.clone(), value.to_json()))
                .collect();
            context["details"] = details.into();
        }
        let action = uid("Action", &req.action_id);
        let context = Context::from_json_value(context, Some((&self.schema, &action)))
            .map_err(|e| format!("invalid details: {}", describe(&e)))?;
        let request = Request::new(
            uid("User", &req.subject.user.uid.to_string()),
            action,
            resource.uid.clone(),
            context,
            Some(&self.schema),
        )
        .map_err(|e| format!("invalid request: {}", describe(&e)))?;

        Ok(Prepared {
            request,
            specs,
            users,
        })
    }

    /// Adds a user, their groups, and the roles they and their groups are in.
    fn add_user(&self, specs: &mut Specs, user: &User) {
        let mut parents: HashSet<EntityUid> = self
            .memberships
            .roles_of(&Member::User(user.uid))
            .map(|r| uid("Role", r))
            .collect();
        for group in &user.groups {
            let group_uid = uid("Group", &group.name);
            parents.insert(group_uid.clone());
            let mut attrs = HashMap::new();
            if let Some(gid) = group.gid {
                attrs.insert("gid".into(), RestrictedExpression::new_long(gid.into()));
            }
            specs.add(Spec {
                uid: group_uid,
                attrs,
                parents: self
                    .memberships
                    .roles_of(&Member::Group(group.name.clone()))
                    .map(|r| uid("Role", r))
                    .collect(),
            });
        }

        let mut attrs = HashMap::from([(
            "uid".to_owned(),
            RestrictedExpression::new_long(user.uid.into()),
        )]);
        if let Some(name) = &user.name {
            attrs.insert(
                "name".into(),
                RestrictedExpression::new_string(name.clone()),
            );
        }
        specs.add(Spec {
            uid: uid("User", &user.uid.to_string()),
            attrs,
            parents,
        });
    }

    /// Evaluates the request with the subject authenticated as `auth`.
    fn evaluate(&self, prepared: &Prepared, auth: &AuthState) -> Result<Eval, String> {
        let mut specs = prepared.specs.clone();
        let mut attrs = HashMap::from([
            (
                "fresh".to_owned(),
                RestrictedExpression::new_bool(auth.fresh),
            ),
            (
                "action".to_owned(),
                RestrictedExpression::new_entity_uid(uid("Action", &auth.action)),
            ),
            (
                "same_resource".to_owned(),
                RestrictedExpression::new_bool(auth.same_resource),
            ),
        ]);
        if let Some(user) = &auth.user {
            if !prepared.users.contains_key(&user.uid) {
                self.add_user(&mut specs, user);
            }
            attrs.insert(
                "user".into(),
                RestrictedExpression::new_entity_uid(uid("User", &user.uid.to_string())),
            );
        }
        specs.add(Spec {
            uid: uid("Authentication", REQUEST),
            attrs,
            parents: HashSet::new(),
        });

        let entities = Entities::from_entities(
            specs
                .0
                .into_values()
                .map(|s| Entity::new(s.uid, s.attrs, s.parents).map_err(|e| describe(&e)))
                .collect::<Result<Vec<_>, _>>()?,
            Some(&self.schema),
        )
        .map_err(|e| format!("invalid entities: {}", describe(&e)))?;

        let response = self
            .authorizer
            .is_authorized(&prepared.request, &self.policies, &entities);
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();
        if !errors.is_empty() {
            return Err(format!("policy evaluation failed: {}", errors.join("; ")));
        }
        let mut reasons: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| id.to_string())
            .collect();
        reasons.sort();
        Ok(match response.decision() {
            cedar_policy::Decision::Allow => Eval::Allow(reasons),
            cedar_policy::Decision::Deny => Eval::Deny(reasons),
        })
    }
}

/// Generates the subject schema for the installed providers (docs/design.md,
/// section 6.5).
pub fn subject_schema(sources: &[Source]) -> Result<String> {
    let mut errors = Vec::new();
    let (_, decls) = read_schemas(sources, &mut errors);
    if !errors.is_empty() {
        return Err(Error::Load(errors));
    }
    Ok(schema::subject_schema(&decls.providers))
}

/// Parses the core schema and the schema files.
fn read_schemas(sources: &[Source], errors: &mut Vec<String>) -> (Vec<Fragment>, Declarations) {
    let mut fragments = Vec::new();
    let core = Fragment::parse("core schema".into(), None, schema::CORE);
    for f in [core]
        .into_iter()
        .chain(sources.iter().filter(|s| s.kind == Kind::Schema).map(|s| {
            let app = match &s.origin {
                Origin::Vendor(app) => Some(app.clone()),
                Origin::Admin => None,
            };
            Fragment::parse(s.path.display().to_string(), app, &s.text)
        }))
    {
        match f {
            Ok(f) => fragments.push(f),
            Err(e) => errors.push(e),
        }
    }
    let decls = Declarations::read(&fragments, errors);
    (fragments, decls)
}

/// How the subject has authenticated, as `context.auth` sees it.
struct AuthState {
    user: Option<User>,
    fresh: bool,
    action: String,
    same_resource: bool,
}

enum Eval {
    /// Allowed, by these policies.
    Allow(Vec<String>),
    /// Denied, by these `forbid`s if any.
    Deny(Vec<String>),
}

struct Prepared {
    request: Request,
    /// The request's entities, apart from the authentication.
    specs: Specs,
    /// The users in `specs`.
    users: BTreeMap<u32, User>,
}

/// An entity, before it's handed to Cedar.
#[derive(Clone)]
struct Spec {
    uid: EntityUid,
    attrs: HashMap<String, RestrictedExpression>,
    parents: HashSet<EntityUid>,
}

impl Spec {
    fn new(uid: EntityUid) -> Self {
        Self {
            uid,
            attrs: HashMap::new(),
            parents: HashSet::new(),
        }
    }

    fn from_resource(r: &Resource) -> Self {
        Self {
            uid: r.uid.clone(),
            attrs: r
                .attrs
                .iter()
                .map(|(k, v)| (k.clone(), v.to_expr()))
                .collect(),
            parents: r.parents.iter().cloned().collect(),
        }
    }
}

#[derive(Clone, Default)]
struct Specs(HashMap<EntityUid, Spec>);

impl Specs {
    /// Adds an entity. If it's already there, its parents are combined, and
    /// the attributes of the first one with any are kept.
    fn add(&mut self, spec: Spec) {
        match self.0.get_mut(&spec.uid) {
            Some(existing) => {
                existing.parents.extend(spec.parents);
                if existing.attrs.is_empty() {
                    existing.attrs = spec.attrs;
                }
            }
            None => {
                self.0.insert(spec.uid.clone(), spec);
            }
        }
    }
}

/// The ids of the users referred to by attributes.
fn users_in(attrs: &HashMap<String, AttrValue>, out: &mut BTreeSet<String>) {
    fn visit(value: &AttrValue, out: &mut BTreeSet<String>) {
        match value {
            AttrValue::Entity(uid) if uid.type_name().to_string() == "User" => {
                out.insert(uid.id().unescaped().to_owned());
            }
            AttrValue::Set(items) => items.iter().for_each(|v| visit(v, out)),
            _ => {}
        }
    }
    attrs.values().for_each(|v| visit(v, out));
}

fn uid(ty: &str, id: &str) -> EntityUid {
    entity_uid(ty, id).expect("entity type names are static and valid")
}

fn entity_json(uid: &EntityUid) -> serde_json::Value {
    serde_json::json!({ "__entity": { "type": uid.type_name().to_string(), "id": uid.id().unescaped() } })
}

/// Describes a Cedar error including its causes and related errors, which
/// say e.g. which attribute an entity is missing.
pub(crate) fn describe(e: &(impl miette::Diagnostic + ?Sized)) -> String {
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        msg.push_str(": ");
        msg.push_str(&cause.to_string());
        source = cause.source();
    }
    if let Some(help) = e.help() {
        msg.push_str(&format!(" ({help})"));
    }
    for related in e.related().into_iter().flatten() {
        msg.push_str("; ");
        msg.push_str(&related.to_string());
    }
    msg
}
