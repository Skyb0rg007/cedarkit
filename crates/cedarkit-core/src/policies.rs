//! Policy files: loading them with unique ids, the vendor rules for them, and
//! the warnings `cedarctl validate` gives.

use std::collections::BTreeSet;
use std::str::FromStr;

use cedar_policy::{ActionConstraint, Policy, PolicyId, PolicySet};
use serde_json::Value;

use crate::authority::describe;
use crate::schema::{CORE_APP, Declarations};

/// Adds the policies in a file to `set`, adding a message to `errors` for
/// each one that breaks the rules. Each policy is identified by its `@id`,
/// or failing that by the file and its position in it.
pub(crate) fn add_file(
    set: &mut PolicySet,
    label: &str,
    app: Option<&str>,
    decls: &Declarations,
    text: &str,
    errors: &mut Vec<String>,
) {
    let parsed = match PolicySet::from_str(text) {
        Ok(parsed) => parsed,
        Err(e) => return errors.push(format!("{label}: {}", describe(&e))),
    };
    if parsed.templates().next().is_some() {
        errors.push(format!("{label}: templates aren't supported"));
    }

    let mut policies: Vec<&Policy> = parsed.policies().collect();
    // Cedar numbers policies as it parses them: policy0, policy1, ...
    policies.sort_by_key(|p| {
        let id = p.id().to_string();
        (id.len(), id)
    });
    for policy in policies {
        let fallback = format!("{label}:{}", policy.id());
        let id = match policy.annotation("id") {
            Some(id) if set.policy(&PolicyId::new(id)).is_none() => id.to_owned(),
            Some(id) => {
                tracing::warn!(file = label, "policy id {id:?} is used more than once");
                fallback
            }
            None => fallback,
        };

        if let Some(app) = app.filter(|app| *app != CORE_APP) {
            check_vendor(policy, &id, app, decls, errors);
        }
        if let Err(e) = set.add(policy.new_id(PolicyId::new(&id))) {
            errors.push(format!("{id}: {e}"));
        }
    }
}

/// A vendor policy may only apply to the application's own actions
/// (docs/design.md, section 8.2).
fn check_vendor(
    policy: &Policy,
    id: &str,
    app: &str,
    decls: &Declarations,
    errors: &mut Vec<String>,
) {
    let actions = match policy.action_constraint() {
        ActionConstraint::Any => {
            errors.push(format!("{id}: must name the actions it applies to"));
            return;
        }
        ActionConstraint::Eq(uid) => vec![uid],
        ActionConstraint::In(uids) => uids,
    };
    for uid in actions {
        let action = uid.id().unescaped();
        if uid.type_name().to_string() != "Action" || !decls.owns(app, action) {
            errors.push(format!("{id}: action {uid} isn't one of {app}'s"));
        }
    }
}

/// Warnings about policies that are valid but probably not what was meant
/// (docs/design.md, section 8.4). `populated` are the roles with members.
pub(crate) fn lint(policies: &PolicySet, populated: &BTreeSet<&String>) -> Vec<String> {
    let mut warnings = Vec::new();
    for policy in policies.policies() {
        let id = policy.id();
        let Ok(json) = policy.to_json() else {
            continue;
        };

        let mut roles = BTreeSet::new();
        roles_in(&json, &mut roles);
        for role in roles {
            if !populated.contains(&role) {
                warnings.push(format!("{id}: Role::{role:?} has no members"));
            }
        }

        for condition in json["conditions"].as_array().into_iter().flatten() {
            let mut conjuncts = Vec::new();
            conjunction(&condition["body"], &mut conjuncts);
            if let Some(problem) = auth_pattern(&conjuncts) {
                warnings.push(format!(
                    "{id}: the authentication condition doesn't match the patterns \
                     in docs/design.md, section 7.1: {problem}"
                ));
            }
        }
    }
    warnings
}

/// Every `Role` entity a policy names.
fn roles_in(json: &Value, roles: &mut BTreeSet<String>) {
    match json {
        Value::Object(fields) => {
            if fields.get("type").and_then(Value::as_str) == Some("Role")
                && let Some(id) = fields.get("id").and_then(Value::as_str)
            {
                roles.insert(id.to_owned());
            }
            fields.values().for_each(|v| roles_in(v, roles));
        }
        Value::Array(items) => items.iter().for_each(|v| roles_in(v, roles)),
        _ => {}
    }
}

/// Splits an expression into the terms of a chain of `&&`s.
fn conjunction<'a>(expr: &'a Value, out: &mut Vec<&'a Value>) {
    match expr.get("&&") {
        Some(and) => {
            conjunction(&and["left"], out);
            conjunction(&and["right"], out);
        }
        None => out.push(expr),
    }
}

/// `context.auth`
fn is_auth(expr: &Value) -> bool {
    let dot = &expr["."];
    dot["attr"] == "auth" && dot["left"]["Var"] == "context"
}

/// `context.auth.<attr>`
fn is_auth_attr(expr: &Value, attr: &str) -> bool {
    let dot = &expr["."];
    dot["attr"] == attr && is_auth(&dot["left"])
}

fn mentions_auth(expr: &Value) -> bool {
    is_auth(expr)
        || match expr {
            Value::Object(fields) => fields.values().any(mentions_auth),
            Value::Array(items) => items.iter().any(mentions_auth),
            _ => false,
        }
}

/// What's wrong with the authentication terms of a condition, if anything.
fn auth_pattern(conjuncts: &[&Value]) -> Option<String> {
    #[derive(Default)]
    struct Seen {
        has_user: bool,
        who: bool,
        fresh: bool,
        same_action: bool,
        same_resource: bool,
        action_in: bool,
    }
    let mut seen = Seen::default();
    let mut any = false;

    for term in conjuncts.iter().filter(|t| mentions_auth(t)) {
        any = true;
        let eq = &term["=="];
        let is_in = &term["in"];
        if term["has"]["attr"] == "user" && is_auth(&term["has"]["left"]) {
            seen.has_user = true;
        } else if (is_auth_attr(&eq["left"], "user") && eq["right"]["Var"] == "principal")
            || (is_auth_attr(&is_in["left"], "user")
                && is_in["right"]["Value"]["__entity"]["type"] == "Role")
        {
            seen.who = true;
        } else if is_auth_attr(term, "fresh") {
            seen.fresh = true;
        } else if is_auth_attr(term, "same_resource") {
            seen.same_resource = true;
        } else if is_auth_attr(&eq["left"], "action") && eq["right"]["Var"] == "action" {
            seen.same_action = true;
        } else if is_auth_attr(&is_in["left"], "action")
            || (is_auth_attr(&eq["left"], "action")
                && eq["right"]["Value"]["__entity"]["type"] == "Action")
        {
            seen.action_in = true;
        } else {
            return Some(format!("unexpected term {term}"));
        }
    }

    if !any {
        None
    } else if !seen.has_user || !seen.who {
        Some("it should check `context.auth has user` and who the user is".into())
    } else if !(seen.fresh || (seen.same_action && seen.same_resource) || seen.action_in) {
        Some("it should require a fresh authentication, or say which remembered ones count".into())
    } else {
        None
    }
}
