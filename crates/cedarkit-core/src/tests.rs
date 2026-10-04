use std::collections::HashMap;

use crate::*;

/// The example application's schema: a vendor file of app `example`.
const SCHEMA: &str = r#"
    @prefixes("org.example.")
    namespace example {
        entity System;
        entity Machine { owner: User };
        type VerbContext = { subject: Subject, auth: Authentication, details: { verb?: String, count?: Long } };
    }

    action "org.example.settings";
    action "org.example.action", "org.example.other" in ["org.example.settings"] appliesTo {
        principal: [User], resource: [example::System, example::Machine], context: Context,
    };
    action "org.example.verb" appliesTo {
        principal: [User], resource: [example::System, example::Machine], context: example::VerbContext,
    };
"#;

/// A fact provider.
const PROVIDER: &str = r#"
    namespace fake {
        entity Seat;
        @subject entity Process { seat?: Seat };
    }
"#;

const SUBJECT: &str = "entity Subject { fake?: fake::Process };";

const SELF_KEEP: &str = "context.auth has user && context.auth.user == principal && \
    context.auth.action == action && context.auth.same_resource";
const SELF: &str = "context.auth has user && context.auth.user == principal && context.auth.fresh";
const ADMIN_KEEP: &str = r#"context.auth has user && context.auth.user in Role::"org.example.admin" &&
    context.auth.action == action && context.auth.same_resource"#;
const ADMIN: &str = r#"context.auth has user && context.auth.user in Role::"org.example.admin" && context.auth.fresh"#;

/// `wheel` is in `Role::"admin"`, which is in the application's admin role.
const ROLES: &str = r#"[
    { "uid": { "type": "Group", "id": "wheel" }, "attrs": {},
      "parents": [{ "type": "Role", "id": "admin" }] }
]"#;
const APP_ROLES: &str = r#"[
    { "uid": { "type": "Role", "id": "admin" },
      "parents": [{ "type": "Role", "id": "org.example.admin" }] }
]"#;

const ALICE: u32 = 1000;
const BOB: u32 = 1001;
const CAROL: u32 = 1002;
const DAVE: u32 = 1003;

/// alice is in nothing, bob in wheel, carol in netadmin, dave in nothing.
struct TestDirectory;

fn test_user(uid: u32) -> Option<User> {
    let (name, groups): (&str, &[&str]) = match uid {
        ALICE => ("alice", &[]),
        BOB => ("bob", &["wheel"]),
        CAROL => ("carol", &["netadmin"]),
        DAVE => ("dave", &[]),
        _ => return None,
    };
    Some(User {
        uid,
        name: Some(name.into()),
        groups: groups.iter().map(|g| Group::named(*g)).collect(),
    })
}

impl Directory for TestDirectory {
    fn user(&self, uid: u32) -> Result<Option<User>> {
        Ok(test_user(uid))
    }

    fn user_by_name(&self, name: &str) -> Result<Option<User>> {
        Ok((ALICE..=DAVE)
            .filter_map(test_user)
            .find(|u| u.name.as_deref() == Some(name)))
    }

    fn group_members(&self, name: &str) -> Result<Vec<u32>> {
        Ok(match name {
            "wheel" => vec![BOB],
            "netadmin" => vec![CAROL],
            _ => vec![],
        })
    }
}

fn vendor(path: &str, text: &str) -> Source {
    let app = path.split('/').next().unwrap();
    Source::new(path, Origin::Vendor(app.into()), text).unwrap()
}

fn admin(path: &str, text: &str) -> Source {
    Source::new(path, Origin::Admin, text).unwrap()
}

/// The example application with these vendor policies, plus `extra` files.
fn sources(policies: &str, extra: Vec<Source>) -> Vec<Source> {
    let mut sources = vec![
        vendor("cedarkit/admin.entities.json", ROLES),
        vendor("example/example.cedarschema", SCHEMA),
        vendor("example/example.cedar", policies),
        vendor("example/example.entities.json", APP_ROLES),
        vendor("fake/fake.cedarschema", PROVIDER),
    ];
    sources.extend(extra);
    sources
}

fn load(sources: &[Source]) -> Result<Loaded> {
    Authority::from_sources(sources, "subject.cedarschema", SUBJECT)
}

fn authority_with(policies: &str, extra: Vec<Source>) -> Authority {
    load(&sources(policies, extra))
        .unwrap()
        .authority
        .with_directory(TestDirectory)
}

fn authority(policies: &str) -> Authority {
    authority_with(policies, vec![])
}

/// The load errors, which must mention `needle`.
fn load_error(sources: &[Source], needle: &str) {
    match load(sources) {
        Err(Error::Load(errors)) => assert!(
            errors.iter().any(|e| e.contains(needle)),
            "expected an error about {needle:?}, got {errors:#?}"
        ),
        Err(e) => panic!("unexpected error {e}"),
        Ok(_) => panic!("loaded, but expected an error about {needle:?}"),
    }
}

fn system() -> Resource {
    Resource::parse(r#"example::System::"local""#).unwrap()
}

fn machine(owner: u32) -> Resource {
    Resource::parse(r#"example::Machine::"box""#)
        .unwrap()
        .with_attr(
            "owner",
            AttrValue::Entity(entity_uid("User", &owner.to_string()).unwrap()),
        )
}

fn request(uid: u32, action: &str) -> CheckRequest {
    CheckRequest::new(Subject::new(test_user(uid).unwrap()), action, system())
}

fn permit(condition: &str) -> String {
    format!(
        r#"permit (principal, action in Action::"org.example.settings", resource) when {{ {condition} }};"#
    )
}

fn option(uid: u32, keep: bool) -> ChallengeOption {
    ChallengeOption {
        uid,
        name: test_user(uid).unwrap().name,
        keep,
    }
}

fn challenge(options: &[(u32, bool)]) -> Decision {
    Decision::Challenge(options.iter().map(|&(u, k)| option(u, k)).collect())
}

fn decide(authority: &Authority, req: &CheckRequest) -> Decision {
    authority.check(req).decision
}

#[test]
fn invalid_policies_are_refused() {
    // `System` has no `owner`.
    load_error(
        &sources(
            r#"permit (principal, action == Action::"org.example.action", resource is example::System)
               when { resource.owner == principal };"#,
            vec![],
        ),
        "owner",
    );
}

/// Entity data holds role memberships and nothing else, so it can't forge
/// facts about requests.
#[test]
fn entity_data_is_only_memberships() {
    let file = |json: &str| sources("", vec![admin("local/x.entities.json", json)]);
    load_error(
        &file(
            r#"[{ "uid": { "type": "example::Machine", "id": "box" },
                   "attrs": { "owner": { "__entity": { "type": "User", "id": "1000" } } } }]"#,
        ),
        "only users, groups and roles",
    );
    load_error(
        &file(r#"[{ "uid": { "type": "User", "id": "1000" }, "attrs": { "uid": 0 } }]"#),
        "may not have attrs",
    );
    load_error(
        &file(
            r#"[{ "uid": { "type": "Role", "id": "admin" },
                   "parents": [{ "type": "Group", "id": "wheel" }] }]"#,
        ),
        "may only be in roles",
    );
    load_error(
        &file(r#"[{ "uid": { "type": "User", "id": "alice" }, "parents": [] }]"#),
        "identified by uid",
    );
}

/// Vendor files can only affect their own namespace, actions and roles.
#[test]
fn vendor_files_are_confined() {
    let schema = |text: &str| sources("", vec![vendor("other/other.cedarschema", text)]);
    let other = r#"@prefixes("org.other.") namespace other {}"#;

    load_error(
        &schema("namespace example2 { entity X; }"),
        "may only declare namespace other",
    );
    load_error(&schema("entity Sneaky;"), "may not declare Sneaky");
    load_error(
        &schema(&format!(
            r#"{other} action "org.example.mine" appliesTo {{ principal: [User], resource: [example::System], context: Context }};"#
        )),
        "isn't one of other's",
    );
    load_error(
        &schema(&format!(
            r#"{other} @implies("org.example.action") action "org.other.a" appliesTo {{ principal: [User], resource: [example::System], context: Context }};"#
        )),
        "implies \"org.example.action\"",
    );
    load_error(
        &schema(r#"@prefixes("org.example.sub.") namespace other {}"#),
        "overlaps",
    );

    // Policies must name their own actions.
    load_error(
        &sources("permit (principal, action, resource);", vec![]),
        "must name the actions",
    );
    load_error(
        &sources(
            "",
            vec![
                vendor("other/_namespace.cedarschema", other),
                vendor(
                    "other/other.cedar",
                    r#"permit (principal, action == Action::"org.example.action", resource);"#,
                ),
            ],
        ),
        "isn't one of other's",
    );

    // Entity data may only add members to their own roles.
    load_error(
        &sources(
            "",
            vec![
                vendor("other/_namespace.cedarschema", other),
                vendor(
                    "other/other.entities.json",
                    r#"[{ "uid": { "type": "User", "id": "1000" },
                          "parents": [{ "type": "Role", "id": "org.example.admin" }] }]"#,
                ),
            ],
        ),
        "isn't one of other's roles",
    );

    // The local admin may do all of these.
    let authority = authority_with(
        "",
        vec![
            admin(
                "local/everything.cedar",
                "permit (principal, action, resource);",
            ),
            admin(
                "local/alice.entities.json",
                r#"[{ "uid": { "type": "User", "id": "1000" },
                      "parents": [{ "type": "Role", "id": "org.example.admin" }] }]"#,
            ),
        ],
    );
    assert_eq!(
        decide(&authority, &request(ALICE, "org.example.action")),
        Decision::Allow
    );
}

#[test]
fn undeclared_actions_are_denied() {
    let authority = authority_with(
        "",
        vec![admin(
            "local/all.cedar",
            "permit (principal, action, resource);",
        )],
    );
    let outcome = authority.check(&request(ALICE, "org.example.undeclared"));
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.reasons[0].contains("isn't declared"));
}

/// Who can pass a challenge, and whether a remembered authentication would do.
#[test]
fn challenges() {
    let alice = request(ALICE, "org.example.action");
    let check = |condition: &str, req: &CheckRequest| decide(&authority(&permit(condition)), req);

    assert_eq!(check(SELF_KEEP, &alice), challenge(&[(ALICE, true)]));
    assert_eq!(check(SELF, &alice), challenge(&[(ALICE, false)]));
    assert_eq!(check(ADMIN_KEEP, &alice), challenge(&[(BOB, true)]));
    assert_eq!(check(ADMIN, &alice), challenge(&[(BOB, false)]));

    // An admin can use their own password, and is listed first.
    let bob = request(BOB, "org.example.action");
    let decision = check(ADMIN_KEEP, &bob);
    assert_eq!(decision, challenge(&[(BOB, true)]));
    assert_eq!(polkit::result(&decision, BOB), "auth_self_keep");
    assert_eq!(polkit::result(&check(ADMIN, &alice), ALICE), "auth_admin");
}

#[test]
fn authenticating() {
    let authority = authority(&format!("{}\n{}", permit(ADMIN_KEEP), permit(SELF)));
    let with = |auth: Authentication| {
        let mut req = request(ALICE, "org.example.action");
        req.authentications.push(auth);
        decide(&authority, &req)
    };
    let req = request(ALICE, "org.example.action");
    let bob = Authentication::fresh(BOB, &req);

    assert_eq!(with(bob.clone()), Decision::Allow);
    assert_eq!(with(bob.clone().remembered()), Decision::Allow);
    assert_eq!(with(Authentication::fresh(ALICE, &req)), Decision::Allow);
    // A remembered password of the subject's doesn't do for auth_self.
    let still = with(Authentication::fresh(ALICE, &req).remembered());
    assert!(matches!(still, Decision::Challenge(_)));
    // By default, a remembered authentication only counts for the same
    // action on the same resource.
    let elsewhere = Authentication {
        resource: machine(ALICE).uid,
        ..bob.clone().remembered()
    };
    assert!(matches!(with(elsewhere), Decision::Challenge(_)));
    let other_action = Authentication {
        action: "org.example.other".into(),
        ..bob.clone().remembered()
    };
    assert!(matches!(with(other_action), Decision::Challenge(_)));
    // Someone outside the role doesn't help.
    assert!(matches!(
        with(Authentication::fresh(DAVE, &req)),
        Decision::Challenge(_)
    ));
}

/// Policies decide when a remembered authentication counts for more
/// (docs/design.md, section 7.4).
#[test]
fn remembered_for_a_group() {
    let authority = authority(&permit(
        r#"context.auth has user && context.auth.user in Role::"org.example.admin" &&
           context.auth.action in Action::"org.example.settings""#,
    ));
    let mut req = request(ALICE, "org.example.action");
    req.authentications.push(Authentication {
        user: BOB,
        fresh: false,
        action: "org.example.other".into(),
        resource: machine(ALICE).uid,
    });
    assert_eq!(decide(&authority, &req), Decision::Allow);
}

/// Applications ask for their own role; the local admin decides who's in
/// it, here the general admins plus the netadmin group and dave.
#[test]
fn application_roles() {
    let authority = authority_with(
        &permit(ADMIN_KEEP),
        vec![admin(
            "local/roles.entities.json",
            r#"[{ "uid": { "type": "Group", "id": "netadmin" },
                  "parents": [{ "type": "Role", "id": "org.example.admin" }] },
                { "uid": { "type": "User", "id": "1003" },
                  "parents": [{ "type": "Role", "id": "org.example.admin" }] }]"#,
        )],
    );
    assert_eq!(
        decide(&authority, &request(ALICE, "org.example.action")),
        challenge(&[(BOB, true), (CAROL, true), (DAVE, true)])
    );
}

/// auth_self, but only for members of wheel: others are denied without a
/// prompt.
#[test]
fn self_for_some_groups() {
    let authority = authority(&format!(
        r#"permit (principal in Group::"wheel", action == Action::"org.example.action", resource)
           when {{ {SELF_KEEP} }};"#
    ));
    assert_eq!(
        decide(&authority, &request(BOB, "org.example.action")),
        challenge(&[(BOB, true)])
    );
    assert_eq!(
        decide(&authority, &request(ALICE, "org.example.action")),
        Decision::Deny
    );
}

/// If nobody who might authenticate would pass, there's no one to ask.
#[test]
fn nobody_qualifies() {
    let empty_role = authority(&permit(
        r#"context.auth has user && context.auth.user in Role::"org.example.empty" && context.auth.fresh"#,
    ));
    // Only an admin's own password, but the subject isn't one.
    let admin_self = authority(&permit(&format!("{SELF} && {ADMIN}")));
    for authority in [empty_role, admin_self] {
        assert_eq!(
            decide(&authority, &request(ALICE, "org.example.action")),
            Decision::Deny
        );
    }
}

/// Users the resource refers to are resolved, and asked too.
#[test]
fn resource_users() {
    let authority = authority(
        r#"permit (principal, action == Action::"org.example.action", resource is example::Machine)
           when { context.auth has user && context.auth.user == resource.owner && context.auth.fresh };"#,
    );
    let on = |resource| CheckRequest {
        resource,
        ..request(ALICE, "org.example.action")
    };
    assert_eq!(
        decide(&authority, &on(machine(DAVE))),
        challenge(&[(DAVE, false)])
    );

    // A user nobody knows can't be resolved, so the request is denied.
    let outcome = authority.check(&on(machine(4242)));
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.reasons[0].contains("4242"), "{:?}", outcome.reasons);

    // Users are identified by uid.
    let by_name = Resource::parse(r#"example::Machine::"box""#)
        .unwrap()
        .with_attr(
            "owner",
            AttrValue::Entity(entity_uid("User", "dave").unwrap()),
        );
    assert_eq!(decide(&authority, &on(by_name)), Decision::Deny);
}

/// A forbid that fails to evaluate still denies.
#[test]
fn evaluation_errors_deny() {
    let authority = authority(
        r#"permit (principal, action == Action::"org.example.action", resource);
           forbid (principal, action == Action::"org.example.action", resource)
           unless { principal.uid + 9223372036854775807 < 0 };"#,
    );
    let outcome = authority.check(&request(ALICE, "org.example.action"));
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(
        outcome.reasons[0].contains("evaluation"),
        "{:?}",
        outcome.reasons
    );
}

/// A `forbid ... unless` makes an action stricter, never looser.
#[test]
fn tightening() {
    let check = |permitted: &str, required: &str| {
        decide(
            &authority(&format!(
                r#"{}
                   forbid (principal, action == Action::"org.example.action", resource)
                   unless {{ {required} }};"#,
                permit(permitted)
            )),
            &request(ALICE, "org.example.action"),
        )
    };
    assert_eq!(check(ADMIN_KEEP, ADMIN), challenge(&[(BOB, false)]));
    assert_eq!(check("true", SELF_KEEP), challenge(&[(ALICE, true)]));
    assert_eq!(check(ADMIN, ADMIN_KEEP), challenge(&[(BOB, false)]));
    assert_eq!(check("false", SELF_KEEP), Decision::Deny);
}

/// A permit that needs no authentication wins over one that does.
#[test]
fn least_demanding_wins() {
    let authority = authority(&format!(
        "{}\n{}",
        permit(ADMIN),
        permit("principal in Group::\"wheel\"")
    ));
    assert_eq!(
        decide(&authority, &request(BOB, "org.example.action")),
        Decision::Allow
    );
    assert_eq!(
        decide(&authority, &request(ALICE, "org.example.action")),
        challenge(&[(BOB, false)])
    );
}

/// Details are typed and optional, and only those declared reach policies.
#[test]
fn details() {
    let authority = authority(
        r#"permit (principal, action == Action::"org.example.verb", resource)
           when { context.details has verb && context.details.verb == "terminate" };"#,
    );
    let with = |details: &[(&str, &str)]| {
        let details: HashMap<String, String> = details
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        CheckRequest {
            details: authority
                .parse_details("org.example.verb", &details)
                .unwrap(),
            ..request(ALICE, "org.example.verb")
        }
    };

    assert_eq!(
        decide(&authority, &with(&[("verb", "terminate"), ("other", "x")])),
        Decision::Allow
    );
    assert_eq!(
        decide(&authority, &with(&[("verb", "copy")])),
        Decision::Deny
    );
    assert_eq!(decide(&authority, &with(&[])), Decision::Deny);
    assert_eq!(with(&[("count", "3")]).details["count"], AttrValue::Long(3));
    assert!(
        authority
            .parse_details(
                "org.example.verb",
                &HashMap::from([("count".into(), "x".into())])
            )
            .is_err()
    );

    // A detail of the wrong type is a request that doesn't match the schema.
    let mut wrong = request(ALICE, "org.example.verb");
    wrong.details.insert("verb".into(), AttrValue::Long(1));
    assert_eq!(decide(&authority, &wrong), Decision::Deny);
}

fn fake_facts(seat: Option<&str>) -> Facts {
    let mut process = Resource::parse(r#"fake::Process::"42""#).unwrap();
    let mut related = Vec::new();
    if let Some(seat) = seat {
        let seat = entity_uid("fake::Seat", seat).unwrap();
        process = process.with_attr("seat", AttrValue::Entity(seat.clone()));
        related.push(Resource::new(seat));
    }
    Facts {
        provider: "fake".into(),
        process,
        related,
    }
}

/// Policies see what fact providers know about the subject.
#[test]
fn subject_facts() {
    let authority = authority(
        r#"permit (principal, action == Action::"org.example.action", resource)
           when { context.subject has fake && context.subject.fake has seat };"#,
    );
    let with = |facts: Option<Facts>| {
        let mut req = request(ALICE, "org.example.action");
        req.subject.facts.extend(facts);
        decide(&authority, &req)
    };
    assert_eq!(with(Some(fake_facts(Some("seat0")))), Decision::Allow);
    assert_eq!(with(Some(fake_facts(None))), Decision::Deny);
    assert_eq!(with(None), Decision::Deny);

    // A provider may only report entities in its own namespace.
    let mut forged = fake_facts(Some("seat0"));
    forged.related.push(machine(ALICE));
    assert_eq!(with(Some(forged)), Decision::Deny);
}

#[test]
fn subject_schema_is_checked() {
    let sources = sources("", vec![]);
    assert_eq!(
        subject_schema(&sources)
            .unwrap()
            .lines()
            .find(|l| l.contains("fake")),
        Some("  fake?: fake::Process,")
    );

    // A provider that isn't installed.
    let stale = "entity Subject { fake?: fake::Process, gone?: fake::Process };";
    match Authority::from_sources(&sources, "subject", stale) {
        Err(Error::Load(e)) => assert!(e[0].contains("gone"), "{e:?}"),
        _ => panic!("loaded a stale subject schema"),
    }

    // A provider missing from it is ignored, with a warning.
    let loaded = Authority::from_sources(&sources, "subject", "entity Subject;").unwrap();
    assert!(
        loaded.warnings.iter().any(|w| w.contains("fake")),
        "{:?}",
        loaded.warnings
    );
}

#[test]
fn lint() {
    let noisy = authority(&format!(
        "{}\n{}",
        permit(
            r#"context.auth has user && context.auth.user in Role::"org.example.nobody" && context.auth.fresh"#
        ),
        permit("context.auth has user && context.auth.user == principal"),
    ));
    let warnings = noisy.lint();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("org.example.nobody") && w.contains("no members")),
        "{warnings:?}"
    );
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("doesn't match the patterns")),
        "{warnings:?}"
    );

    let clean = authority(&format!("{}\n{}", permit(ADMIN_KEEP), permit(SELF)));
    assert_eq!(clean.lint(), Vec::<String>::new());
}

/// An admin file replaces the vendor file with the same relative path.
#[test]
fn admin_files_mask_vendor_files() {
    let root = std::env::temp_dir().join(format!("cedarkit-test-{}", std::process::id()));
    let write = |path: &str, text: &str| {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write("usr/example/a.cedar", "// vendor");
    write("usr/example/b.cedar", "// vendor");
    write("etc/example/b.cedar", "// admin");
    write("etc/local/c.cedar", "// local");
    write("usr/example/notes.txt", "ignored");

    let layout = Layout {
        vendor: root.join("usr"),
        admin: root.join("etc"),
        subject_schema: root.join("subject.cedarschema"),
    };
    let sources = read_sources(&layout).unwrap();
    std::fs::remove_dir_all(&root).unwrap();

    let found: Vec<(String, Origin, &str)> = sources
        .iter()
        .map(|s| {
            let rel = s.path.strip_prefix(&root).unwrap().display().to_string();
            (rel, s.origin.clone(), s.text.as_str())
        })
        .collect();
    assert_eq!(
        found,
        [
            (
                "usr/example/a.cedar".into(),
                Origin::Vendor("example".into()),
                "// vendor"
            ),
            ("etc/example/b.cedar".into(), Origin::Admin, "// admin"),
            ("etc/local/c.cedar".into(), Origin::Admin, "// local"),
        ]
    );
}
