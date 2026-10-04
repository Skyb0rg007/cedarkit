//! Reading what the schema files declare: actions and their details,
//! application namespaces and their action prefixes, and fact providers.
//! Cedar's schema API doesn't expose these, so they're read from each file's
//! JSON form.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{EntityUid, SchemaFragment};
use serde_json::Value;

/// The core schema, version 1 (docs/design.md, section 5).
pub(crate) const CORE: &str = include_str!("cedarkit.cedarschema");

/// The application whose vendor files are CedarKit's own, and unrestricted.
pub(crate) const CORE_APP: &str = "cedarkit";

/// A parsed schema file.
pub(crate) struct Fragment {
    /// The file's path, for messages.
    pub label: String,
    /// The vendor application the file belongs to, if it's a vendor file.
    pub app: Option<String>,
    pub fragment: SchemaFragment,
    pub json: Value,
}

impl Fragment {
    pub fn parse(label: String, app: Option<String>, text: &str) -> Result<Self, String> {
        let (fragment, warnings) = SchemaFragment::from_cedarschema_str(text)
            .map_err(|e| format!("{label}: {}", crate::authority::describe(&e)))?;
        for w in warnings {
            tracing::debug!(file = label, "schema warning: {w}");
        }
        let json = fragment
            .clone()
            .to_json_value()
            .map_err(|e| format!("{label}: {e}"))?;
        Ok(Self {
            label,
            app,
            fragment,
            json,
        })
    }

    fn namespaces(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.json
            .as_object()
            .into_iter()
            .flatten()
            .map(|(k, v)| (k.as_str(), v))
    }
}

/// How a detail is typed, for converting polkit's string details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DetailType {
    String,
    Long,
    Bool,
    /// An entity of the named type, e.g. `systemd::Machine`.
    Entity(String),
    /// Sets, records and extension types, which strings aren't converted to.
    Other,
}

/// What CedarKit needs to know about a declared action.
#[derive(Debug, Clone, Default)]
pub(crate) struct ActionInfo {
    /// The details its context declares, if it declares `details`.
    pub details: Option<BTreeMap<String, DetailType>>,
    /// Its `@singleton` resource.
    pub singleton: Option<EntityUid>,
    /// What it does, from `@doc`.
    pub description: Option<String>,
    /// The resource types it applies to, fully qualified, in order.
    pub resource_types: Vec<String>,
    /// Its annotations, such as polkit's `@message`.
    pub annotations: BTreeMap<String, String>,
}

/// How the polkit-compatible front end builds a resource of some type from
/// polkit's details (`@detail`, docs/design.md, section 6.4).
#[derive(Debug, Clone, Default)]
pub(crate) struct ResourceType {
    /// The detail that identifies it, or a template naming several, such as
    /// `{class}:{image}`.
    pub detail: Option<String>,
    /// The attributes details supply.
    pub attrs: Vec<DetailAttr>,
}

#[derive(Debug, Clone)]
pub(crate) struct DetailAttr {
    pub name: String,
    pub detail: String,
    pub ty: DetailType,
    pub required: bool,
}

/// What the schema files declare, beyond what Cedar's schema API exposes.
#[derive(Debug, Default)]
pub(crate) struct Declarations {
    /// Requestable actions, by id.
    pub actions: HashMap<String, ActionInfo>,
    /// Each application's action prefixes, from `@prefixes` on its namespace.
    pub prefixes: BTreeMap<String, Vec<String>>,
    /// Each fact provider's `@subject` type, by namespace.
    pub providers: BTreeMap<String, String>,
    /// Entity types, fully qualified, with how polkit's details describe them.
    pub resource_types: HashMap<String, ResourceType>,
}

impl Declarations {
    /// Reads the declarations of `fragments`, adding a message to `errors`
    /// for each one that breaks the rules.
    pub fn read(fragments: &[Fragment], errors: &mut Vec<String>) -> Self {
        let types = Types::new(fragments);
        let mut decls = Self::default();

        for f in fragments {
            for (ns, decl) in f.namespaces() {
                if let Some(prefixes) = decl["annotations"]["prefixes"].as_str() {
                    decls
                        .prefixes
                        .entry(ns.to_owned())
                        .or_default()
                        .extend(prefixes.split_whitespace().map(str::to_owned));
                }
                for (name, ty) in decl["entityTypes"].as_object().into_iter().flatten() {
                    decls
                        .resource_types
                        .insert(qualified(ns, name), resource_type(&types, ty, ns));
                    if ty["annotations"].get("subject").is_none() {
                        continue;
                    }
                    if ns.is_empty() {
                        errors.push(format!(
                            "{}: @subject type {name} isn't in a provider's namespace",
                            f.label
                        ));
                    } else if let Some(other) = decls
                        .providers
                        .insert(ns.to_owned(), format!("{ns}::{name}"))
                    {
                        errors.push(format!(
                            "{}: namespace {ns} has two @subject types, {other} and {ns}::{name}",
                            f.label
                        ));
                    }
                }
            }

            let root_actions = f.json[""]["actions"].as_object().into_iter().flatten();
            for (id, decl) in root_actions {
                let applies = &decl["appliesTo"];
                if applies["principalTypes"]
                    .as_array()
                    .is_none_or(|p| p.is_empty())
                {
                    // An action group, which isn't requested itself.
                    continue;
                }
                match action_info(&types, decl) {
                    Ok(info) => {
                        decls.actions.insert(id.clone(), info);
                    }
                    Err(e) => errors.push(format!("{}: action {id:?}: {e}", f.label)),
                }
            }
        }

        // An action may only be owned by one application.
        let all: Vec<(&String, &String)> = decls
            .prefixes
            .iter()
            .flat_map(|(app, ps)| ps.iter().map(move |p| (app, p)))
            .collect();
        for (a, p) in &all {
            if !p.ends_with('.') {
                errors.push(format!(
                    "namespace {a}: action prefix {p:?} must end in a dot"
                ));
            }
            for (b, q) in &all {
                if a != b && q.starts_with(p.as_str()) {
                    errors.push(format!(
                        "action prefix {q:?} of namespace {b} overlaps {p:?} of namespace {a}"
                    ));
                }
            }
        }
        decls
    }

    /// Whether the action or role `id` belongs to application `app`.
    pub fn owns(&self, app: &str, id: &str) -> bool {
        self.prefixes
            .get(app)
            .is_some_and(|ps| ps.iter().any(|p| id.starts_with(p.as_str())))
    }

    /// Checks that a vendor schema file only declares the application's own
    /// namespace and actions (docs/design.md, section 8.2).
    pub fn check_vendor(&self, f: &Fragment, errors: &mut Vec<String>) {
        let Some(app) = f.app.as_deref().filter(|app| *app != CORE_APP) else {
            return;
        };
        let mut problem = |msg: String| errors.push(format!("{}: {msg}", f.label));
        for (ns, decl) in f.namespaces() {
            if ns == app {
                if decl["actions"].as_object().is_some_and(|a| !a.is_empty()) {
                    problem(format!(
                        "actions must be declared in the root namespace, not {ns}"
                    ));
                }
                continue;
            }
            if !ns.is_empty() {
                problem(format!("may only declare namespace {app}, not {ns}"));
                continue;
            }
            for key in ["entityTypes", "commonTypes"] {
                for name in decl[key].as_object().into_iter().flatten().map(|(k, _)| k) {
                    problem(format!("may not declare {name} in the root namespace"));
                }
            }
            for (id, action) in decl["actions"].as_object().into_iter().flatten() {
                if !self.owns(app, id) {
                    problem(format!("action {id:?} isn't one of {app}'s"));
                }
                for parent in action["memberOf"].as_array().into_iter().flatten() {
                    let pid = parent["id"].as_str().unwrap_or_default();
                    let ty = parent["type"].as_str().unwrap_or("Action");
                    if ty != "Action" || !self.owns(app, pid) {
                        problem(format!(
                            "action {id:?} is in {pid:?}, which isn't one of {app}'s"
                        ));
                    }
                }
                let implies = action["annotations"]["implies"]
                    .as_str()
                    .unwrap_or_default();
                for implied in implies.split_whitespace() {
                    if !self.owns(app, implied) {
                        problem(format!(
                            "action {id:?} implies {implied:?}, which isn't one of {app}'s"
                        ));
                    }
                }
            }
        }
    }

    /// Checks the generated subject schema against the installed providers,
    /// returning those it declares (docs/design.md, section 6.5).
    pub fn check_subject(
        &self,
        f: &Fragment,
        errors: &mut Vec<String>,
        warnings: &mut Vec<String>,
    ) -> BTreeSet<String> {
        let mut enabled = BTreeSet::new();
        let mut problem = |msg: String| errors.push(format!("{}: {msg}", f.label));
        for (ns, decl) in f.namespaces() {
            let names: Vec<_> = ["entityTypes", "commonTypes", "actions"]
                .iter()
                .flat_map(|key| decl[key].as_object().into_iter().flatten())
                .map(|(k, _)| k.as_str())
                .filter(|k| !(ns.is_empty() && *k == "Subject"))
                .collect();
            if !names.is_empty() || (!ns.is_empty()) {
                problem(format!(
                    "may only declare Subject, not {}",
                    if names.is_empty() { ns } else { names[0] }
                ));
            }
        }

        let attrs = &f.json[""]["entityTypes"]["Subject"]["shape"]["attributes"];
        for (name, ty) in attrs.as_object().into_iter().flatten() {
            let declared = ty["name"]
                .as_str()
                .or(ty["type"].as_str())
                .unwrap_or_default();
            match self.providers.get(name) {
                Some(expected) if expected == declared => {
                    if ty["required"] != false {
                        problem(format!("{name} must be optional"));
                    }
                    enabled.insert(name.clone());
                }
                Some(expected) => problem(format!(
                    "{name} is {declared}, but provider {name}'s subject facts are {expected}; \
                     run `cedarctl schema update`"
                )),
                None => problem(format!(
                    "names provider {name}, which isn't installed; run `cedarctl schema update`"
                )),
            }
        }
        for provider in self.providers.keys() {
            if !enabled.contains(provider) {
                warnings.push(format!(
                    "{}: fact provider {provider} isn't in the subject schema, so its facts are \
                     ignored; run `cedarctl schema update`",
                    f.label
                ));
            }
        }
        enabled
    }
}

/// The subject schema for these providers (docs/design.md, section 6.5).
pub(crate) fn subject_schema(providers: &BTreeMap<String, String>) -> String {
    let mut out = String::from(
        "// Generated by `cedarctl schema update`. Do not edit.\n\
         // What each installed fact provider knows about the calling process\n\
         // (docs/design.md, section 6.5).\n",
    );
    if providers.is_empty() {
        out.push_str("entity Subject;\n");
    } else {
        out.push_str("entity Subject {\n");
        for (ns, ty) in providers {
            out.push_str(&format!("  {ns}?: {ty},\n"));
        }
        out.push_str("};\n");
    }
    out
}

/// The entity and common types declared across all schema files.
struct Types<'a> {
    common: HashMap<String, &'a Value>,
    entities: HashSet<String>,
}

fn qualified(ns: &str, name: &str) -> String {
    if ns.is_empty() {
        name.to_owned()
    } else {
        format!("{ns}::{name}")
    }
}

/// The namespace of a qualified name.
fn namespace_of(name: &str) -> &str {
    name.rsplit_once("::").map_or("", |(ns, _)| ns)
}

impl<'a> Types<'a> {
    fn new(fragments: &'a [Fragment]) -> Self {
        let mut types = Self {
            common: HashMap::new(),
            entities: HashSet::new(),
        };
        for f in fragments {
            for (ns, decl) in f.namespaces() {
                for (name, ty) in decl["commonTypes"].as_object().into_iter().flatten() {
                    types.common.insert(qualified(ns, name), ty);
                }
                for (name, _) in decl["entityTypes"].as_object().into_iter().flatten() {
                    types.entities.insert(qualified(ns, name));
                }
            }
        }
        types
    }

    /// The fully qualified name `name` refers to from namespace `ns`, if it's
    /// one of `known`.
    fn lookup<T>(&self, name: &str, ns: &str, known: &HashMap<String, T>) -> Option<String> {
        if name.contains("::") {
            return known.contains_key(name).then(|| name.to_owned());
        }
        [qualified(ns, name), name.to_owned()]
            .into_iter()
            .find(|q| known.contains_key(q))
    }

    /// Follows references to common types, returning the type written out,
    /// and the namespace it was declared in.
    fn resolve(&self, ty: &'a Value, ns: &str) -> (&'a Value, String) {
        let name = match ty["type"].as_str() {
            Some("EntityOrCommon") => ty["name"].as_str(),
            Some("Record" | "Set" | "Entity" | "Extension" | "String" | "Long" | "Boolean") => None,
            other => other,
        };
        match name.and_then(|n| self.lookup(n, ns, &self.common)) {
            Some(q) => self.resolve(self.common[&q], namespace_of(&q)),
            None => (ty, ns.to_owned()),
        }
    }

    fn entity(&self, name: &str, ns: &str) -> String {
        let q = qualified(ns, name);
        if !name.contains("::") && self.entities.contains(&q) {
            q
        } else {
            name.to_owned()
        }
    }

    fn detail_type(&self, ty: &'a Value, ns: &str) -> DetailType {
        let (ty, ns) = self.resolve(ty, ns);
        let name = ty["name"].as_str().unwrap_or_default();
        match ty["type"].as_str().unwrap_or_default() {
            "String" => DetailType::String,
            "Long" => DetailType::Long,
            "Boolean" => DetailType::Bool,
            "Entity" => DetailType::Entity(self.entity(name, &ns)),
            "EntityOrCommon" => match name.trim_start_matches("__cedar::") {
                "String" => DetailType::String,
                "Long" => DetailType::Long,
                "Bool" | "Boolean" => DetailType::Bool,
                _ => DetailType::Entity(self.entity(name, &ns)),
            },
            _ => DetailType::Other,
        }
    }
}

/// Reads an action's details and singleton, checking its context has the
/// required shape (docs/design.md, section 6.3).
fn action_info(types: &Types, decl: &Value) -> Result<ActionInfo, String> {
    let (context, ns) = types.resolve(&decl["appliesTo"]["context"], "");
    let attrs = context["attributes"]
        .as_object()
        .ok_or("its context must be Context, or a record with subject, auth and details")?;
    for (key, ty) in attrs {
        let expected = match key.as_str() {
            "subject" => "Subject",
            "auth" => "Authentication",
            "details" => continue,
            _ => return Err(format!("its context may not have {key:?}")),
        };
        let name = ty["name"].as_str().unwrap_or_default();
        if types.entity(name, &ns) != expected || ty["required"] == false {
            return Err(format!("context.{key} must be a {expected}"));
        }
    }
    if !attrs.contains_key("subject") || !attrs.contains_key("auth") {
        return Err("its context must have subject and auth".into());
    }

    let details = match attrs.get("details") {
        None => None,
        Some(ty) => {
            if ty["required"] == false {
                return Err("context.details may not be optional".into());
            }
            let (record, record_ns) = types.resolve(ty, &ns);
            let fields = record["attributes"]
                .as_object()
                .ok_or("context.details must be a record")?;
            let mut details = BTreeMap::new();
            for (name, ty) in fields {
                if ty["required"] != false {
                    return Err(format!("detail {name:?} must be optional"));
                }
                details.insert(name.clone(), types.detail_type(ty, &record_ns));
            }
            Some(details)
        }
    };

    let singleton = match decl["annotations"]["singleton"].as_str() {
        None => None,
        Some(s) => {
            Some(EntityUid::from_str(s).map_err(|e| format!("invalid @singleton {s:?}: {e}"))?)
        }
    };
    let description = decl["annotations"]["doc"].as_str().map(str::to_owned);
    let resource_types = decl["appliesTo"]["resourceTypes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| t.as_str())
        .map(|t| types.entity(t, ""))
        .collect();
    let annotations = decl["annotations"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
        .collect();
    Ok(ActionInfo {
        details,
        singleton,
        description,
        resource_types,
        annotations,
    })
}

/// How polkit's details describe an entity type.
fn resource_type(types: &Types, decl: &Value, ns: &str) -> ResourceType {
    let attrs = decl["shape"]["attributes"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(name, ty)| {
            Some(DetailAttr {
                name: name.clone(),
                detail: ty["annotations"]["detail"].as_str()?.to_owned(),
                ty: types.detail_type(ty, ns),
                required: ty["required"] != false,
            })
        })
        .collect();
    ResourceType {
        detail: decl["annotations"]["detail"].as_str().map(str::to_owned),
        attrs,
    }
}
