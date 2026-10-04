//! Checks the translated systemd policies: polkit's defaults for each kind of
//! session, plus the ownership rules systemd applies before asking polkit.

use std::collections::HashMap;
use std::path::Path;

use cedarkit_core::{
    AttrValue, Authority, CheckRequest, Decision, Directory, Group, Layout, Origin, Resource,
    Source, Subject, User, entity_uid, polkit, read_sources, read_subject_schema,
};
use cedarkit_logind::{ProcessInfo, Session};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// An action, its resource, request details, and polkit's result.
type Case = (
    &'static str,
    Resource,
    &'static [(&'static str, &'static str)],
    &'static str,
);

const ALICE: u32 = 1000;
const BOB: u32 = 1001;

/// bob is in wheel, which the policies' role data makes an admin.
struct TestDirectory;

impl Directory for TestDirectory {
    fn user(&self, uid: u32) -> cedarkit_core::Result<Option<User>> {
        Ok(match uid {
            ALICE => Some(user(ALICE, "alice", &[])),
            BOB => Some(user(BOB, "bob", &["wheel"])),
            _ => None,
        })
    }

    fn user_by_name(&self, _: &str) -> cedarkit_core::Result<Option<User>> {
        Ok(None)
    }

    fn group_members(&self, name: &str) -> cedarkit_core::Result<Vec<u32>> {
        Ok(if name == "wheel" { vec![BOB] } else { vec![] })
    }
}

fn user(uid: u32, name: &str, groups: &[&str]) -> User {
    User {
        uid,
        name: Some(name.into()),
        groups: groups.iter().map(|g| Group::named(*g)).collect(),
    }
}

fn layout() -> Layout {
    let root = Path::new(ROOT);
    Layout {
        vendor: root.join("policies"),
        admin: root.join("tests/no-admin-files"),
        subject_schema: root.join("state/subject.cedarschema"),
    }
}

fn load(extra: Vec<Source>) -> Authority {
    let layout = layout();
    let mut sources = read_sources(&layout).unwrap();
    sources.extend(extra);
    let subject = read_subject_schema(&layout).unwrap();
    Authority::from_sources(&sources, "subject.cedarschema", &subject)
        .unwrap()
        .authority
        .with_directory(TestDirectory)
}

fn resource(ty: &str, id: &str) -> Resource {
    Resource::new(entity_uid(ty, id).unwrap())
}

fn owner(uid: u32) -> AttrValue {
    AttrValue::Entity(entity_uid("User", &uid.to_string()).unwrap())
}

/// What logind says about alice's process in each of polkit's columns:
/// `allow_any` (not in a session), `allow_inactive`, `allow_active`.
fn sessions() -> [Option<ProcessInfo>; 3] {
    let local = |active| ProcessInfo {
        session: Some(Session {
            id: "3".into(),
            uid: ALICE,
            seat: Some("seat0".into()),
            remote: false,
            class: "user".into(),
            type_: "wayland".into(),
            active,
        }),
        display: None,
        user_active: active,
    };
    [None, Some(local(false)), Some(local(true))]
}

fn check(
    authority: &Authority,
    action: &str,
    resource: Resource,
    session: Option<&ProcessInfo>,
    details: &[(&str, &str)],
) -> &'static str {
    let mut subject = Subject::new(user(ALICE, "alice", &[]));
    if let Some(info) = session {
        subject = subject.with_facts(info.facts(4242));
    }
    let details: HashMap<String, String> = details
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let request = CheckRequest {
        details: authority.parse_details(action, &details).unwrap(),
        ..CheckRequest::new(subject, action, resource)
    };
    let outcome = authority.check(&request);
    polkit::result(&outcome.decision, ALICE)
}

/// Each case: an action, its resource, and polkit's result for each column.
fn check_columns(authority: &Authority, cases: &[(&str, Resource, [&str; 3])]) {
    for (action, resource, expected) in cases {
        for (session, want) in sessions().iter().zip(expected) {
            let got = check(authority, action, resource.clone(), session.as_ref(), &[]);
            assert_eq!(
                got,
                *want,
                "{action} {:?}",
                session.as_ref().map(|s| s.user_active)
            );
        }
    }
}

#[test]
fn matches_polkit_defaults() {
    let authority = load(vec![]);
    check_columns(
        &authority,
        &[
            (
                "org.freedesktop.login1.reboot",
                resource("systemd::System", "local"),
                ["auth_admin_keep", "auth_admin_keep", "yes"],
            ),
            (
                "org.freedesktop.timedate1.set-time",
                resource("systemd::Clock", "system"),
                ["auth_admin_keep"; 3],
            ),
            (
                "org.freedesktop.login1.inhibit-handle-power-key",
                resource("systemd::InhibitTarget", "handle-power-key"),
                ["no", "yes", "yes"],
            ),
            (
                "org.freedesktop.systemd1.reply-password",
                resource("systemd::System", "local"),
                ["no", "no", "auth_admin_keep"],
            ),
            (
                "org.freedesktop.systemd1.manage-units",
                resource("systemd::Unit", "sshd.service"),
                ["auth_admin", "auth_admin", "auth_admin_keep"],
            ),
            (
                "io.systemd.cryptenroll.enroll",
                resource("systemd::Device", "/dev/sda2"),
                ["auth_admin", "auth_admin", "auth_admin_keep"],
            ),
            // Implied by reboot, which is allowed in active local sessions.
            (
                "org.freedesktop.login1.set-wall-message",
                resource("systemd::System", "local"),
                ["auth_admin_keep", "auth_admin_keep", "yes"],
            ),
            (
                "org.example.undeclared",
                resource("systemd::System", "local"),
                ["no"; 3],
            ),
        ],
    );
}

#[test]
fn owners_skip_authentication() {
    let authority = load(vec![]);

    let session = |uid| {
        Session {
            id: "3".into(),
            uid,
            seat: None,
            remote: true,
            class: "user".into(),
            type_: "tty".into(),
            active: true,
        }
        .resource()
    };
    let machine = |uid| resource("systemd::Machine", "box").with_attr("owner", owner(uid));
    let home = |uid| resource("systemd::Home", "home").with_attr("owner", owner(uid));
    let credential = |scope: &str, uid: Option<u32>| {
        let c = resource("systemd::Credential", "secret")
            .with_attr("scope", AttrValue::String(scope.into()));
        match uid {
            Some(uid) => c.with_attr("owner", owner(uid)),
            None => c,
        }
    };

    let cases: &[Case] = &[
        ("org.freedesktop.login1.manage", session(ALICE), &[], "yes"),
        (
            "org.freedesktop.login1.manage",
            session(BOB),
            &[],
            "auth_admin_keep",
        ),
        (
            "org.freedesktop.login1.lock-sessions",
            session(ALICE),
            &[],
            "yes",
        ),
        (
            "org.freedesktop.login1.manage",
            resource("User", "1000"),
            &[],
            "yes",
        ),
        (
            "org.freedesktop.login1.manage",
            resource("User", "1001"),
            &[],
            "auth_admin_keep",
        ),
        // Seats have no owner.
        (
            "org.freedesktop.login1.manage",
            resource("logind::Seat", "seat0"),
            &[],
            "auth_admin_keep",
        ),
        ("org.freedesktop.home1.passwd-home", home(ALICE), &[], "yes"),
        (
            "org.freedesktop.home1.passwd-home",
            home(BOB),
            &[],
            "auth_admin_keep",
        ),
        // Owners can't remove their own home without an admin.
        (
            "org.freedesktop.home1.remove-home",
            home(ALICE),
            &[],
            "auth_admin_keep",
        ),
        ("org.freedesktop.machine1.shell", machine(ALICE), &[], "yes"),
        (
            "org.freedesktop.machine1.shell",
            machine(BOB),
            &[],
            "auth_admin",
        ),
        (
            "org.freedesktop.machine1.manage-machines",
            machine(ALICE),
            &[("verb", "terminate")],
            "yes",
        ),
        // Owners may stop their machine, but not copy files out of it.
        (
            "org.freedesktop.machine1.manage-machines",
            machine(ALICE),
            &[("verb", "copy")],
            "auth_admin",
        ),
        (
            "org.freedesktop.resolve1.unregister-service",
            resource("systemd::DnssdService", "web").with_attr("owner", owner(ALICE)),
            &[],
            "yes",
        ),
        // A home whose UID isn't allocated yet has no owner to skip authentication.
        (
            "org.freedesktop.home1.passwd-home",
            resource("systemd::Home", "carol"),
            &[],
            "auth_admin_keep",
        ),
        (
            "io.systemd.credentials.decrypt",
            credential("user", Some(ALICE)),
            &[("timestamp_fresh", "1")],
            "yes",
        ),
        // A backdated timestamp needs authentication even for one's own credentials.
        (
            "io.systemd.credentials.decrypt",
            credential("user", Some(ALICE)),
            &[("timestamp_fresh", "0")],
            "auth_admin_keep",
        ),
        (
            "io.systemd.credentials.encrypt",
            credential("user", Some(BOB)),
            &[("timestamp_fresh", "1")],
            "auth_admin_keep",
        ),
        (
            "io.systemd.credentials.encrypt",
            credential("system", None),
            &[("timestamp_fresh", "1")],
            "auth_admin_keep",
        ),
    ];

    for (action, resource, details, want) in cases {
        let id = resource.uid.to_string();
        assert_eq!(
            check(&authority, action, resource.clone(), None, details),
            *want,
            "{action} {id}"
        );
    }
}

#[test]
fn admins_can_tighten_defaults() {
    let authority = load(vec![
        Source::new(
            "local/tighten.cedar",
            Origin::Admin,
            r#"
            // Always ask for an admin password to set the time, never remember it.
            @id("local/set-time")
            forbid (principal, action == Action::"org.freedesktop.timedate1.set-time", resource)
            unless {
              context.auth has user &&
              context.auth.user in Role::"org.freedesktop.timedate1.admin" &&
              context.auth.fresh
            };

            // Make even active local users enter their own password, or an
            // admin's, to reboot.
            @id("local/reboot")
            forbid (principal, action == Action::"org.freedesktop.login1.reboot", resource)
            unless {
              context.auth has user &&
              (context.auth.user == principal ||
               context.auth.user in Role::"org.freedesktop.login1.admin")
            };
            "#,
        )
        .unwrap(),
    ]);

    check_columns(
        &authority,
        &[
            (
                "org.freedesktop.timedate1.set-time",
                resource("systemd::Clock", "system"),
                ["auth_admin"; 3],
            ),
            // Even in an active session, alice's password or an admin's.
            (
                "org.freedesktop.login1.reboot",
                resource("systemd::System", "local"),
                ["auth_admin_keep", "auth_admin_keep", "auth_admin_keep"],
            ),
            // Other actions are unaffected.
            (
                "org.freedesktop.timedate1.set-ntp",
                resource("systemd::Clock", "ntp"),
                ["auth_admin_keep"; 3],
            ),
        ],
    );

    let subject =
        Subject::new(user(ALICE, "alice", &[])).with_facts(sessions()[2].clone().unwrap().facts(1));
    let req = CheckRequest::new(
        subject,
        "org.freedesktop.login1.reboot",
        resource("systemd::System", "local"),
    );
    let Decision::Challenge(options) = authority.check(&req).decision else {
        panic!("expected a challenge");
    };
    let uids: Vec<u32> = options.iter().map(|o| o.uid).collect();
    assert_eq!(uids, [ALICE, BOB]);
}
