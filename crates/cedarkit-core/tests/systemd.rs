//! Checks the translated systemd policies: polkit's defaults for each kind of
//! session, plus the ownership rules systemd applies before asking polkit.

use std::collections::HashMap;
use std::path::Path;

use cedarkit_core::{
    AttrValue, Authentication, Authority, Challenge, CheckRequest, Decision, Resource, Subject,
    entity_uid, read_tree,
};

const ADMIN: Decision = Decision::Challenge(Challenge::ADMIN);
const ADMIN_KEEP: Decision = Decision::Challenge(Challenge::ADMIN_KEEP);
const ALLOW: Decision = Decision::Allow;
const DENY: Decision = Decision::Deny;

/// An action, the resource it acts on, request details, and the expected decision.
type Case = (
    &'static str,
    Resource,
    &'static [(&'static str, &'static str)],
    Decision,
);

/// Session kinds, in polkit's `allow_any`, `allow_inactive`, `allow_active` order.
const SESSIONS: [(bool, bool); 3] = [(false, false), (true, false), (true, true)];

const POLICIES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies");

fn authority() -> Authority {
    Authority::from_dir(POLICIES).unwrap()
}

fn resource(ty: &str, id: &str) -> Resource {
    Resource::new(entity_uid(ty, id).unwrap())
}

fn user(name: &str) -> AttrValue {
    AttrValue::Entity(entity_uid("User", name).unwrap())
}

fn check(
    authority: &Authority,
    action: &str,
    resource: Resource,
    (local, active): (bool, bool),
    details: &[(&str, &str)],
) -> Decision {
    let request = CheckRequest {
        subject: Subject {
            uid: 1000,
            name: "alice".into(),
            groups: vec![],
            local,
            active,
        },
        action_id: action.into(),
        resource,
        details: details
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>(),
        auth: Authentication::NONE,
    };
    authority.check(&request).unwrap()
}

#[test]
fn matches_polkit_defaults() {
    let authority = authority();
    let cases = [
        (
            "org.freedesktop.login1.reboot",
            resource("System", "local"),
            [ADMIN_KEEP, ADMIN_KEEP, ALLOW],
        ),
        (
            "org.freedesktop.timedate1.set-time",
            resource("Clock", "system"),
            [ADMIN_KEEP; 3],
        ),
        (
            "org.freedesktop.login1.inhibit-handle-power-key",
            resource("InhibitTarget", "handle-power-key"),
            [DENY, ALLOW, ALLOW],
        ),
        (
            "org.freedesktop.systemd1.reply-password",
            resource("System", "local"),
            [DENY, DENY, ADMIN_KEEP],
        ),
        (
            "org.freedesktop.systemd1.manage-units",
            resource("Unit", "sshd.service"),
            [ADMIN, ADMIN, ADMIN_KEEP],
        ),
        (
            "io.systemd.cryptenroll.enroll",
            resource("Device", "/dev/sda2"),
            [ADMIN, ADMIN, ADMIN_KEEP],
        ),
        (
            "org.example.undeclared",
            resource("System", "local"),
            [DENY; 3],
        ),
    ];

    for (action, resource, expected) in cases {
        for (session, want) in SESSIONS.into_iter().zip(expected) {
            let got = check(&authority, action, resource.clone(), session, &[]);
            assert_eq!(got, want, "{action} {session:?}");
        }
    }
}

#[test]
fn owners_skip_authentication() {
    let authority = authority();
    let remote = (false, false);

    let session = |owner| resource("Session", "3").with_attr("owner", user(owner));
    let machine = |owner| resource("Machine", "box").with_attr("owner", user(owner));
    let home = |owner| resource("Home", owner).with_attr("owner", user(owner));
    let credential = |scope: &str, owner: Option<&str>| {
        let c =
            resource("Credential", "secret").with_attr("scope", AttrValue::String(scope.into()));
        match owner {
            Some(owner) => c.with_attr("owner", user(owner)),
            None => c,
        }
    };

    let cases: [Case; 19] = [
        (
            "org.freedesktop.login1.manage",
            session("alice"),
            &[],
            ALLOW,
        ),
        (
            "org.freedesktop.login1.manage",
            session("bob"),
            &[],
            ADMIN_KEEP,
        ),
        (
            "org.freedesktop.login1.lock-sessions",
            session("alice"),
            &[],
            ALLOW,
        ),
        (
            "org.freedesktop.login1.manage",
            resource("User", "alice"),
            &[],
            ALLOW,
        ),
        (
            "org.freedesktop.login1.manage",
            resource("User", "bob")
                .with_attr("name", AttrValue::String("bob".into()))
                .with_attr("uid", AttrValue::Long(1001)),
            &[],
            ADMIN_KEEP,
        ),
        // Seats have no owner.
        (
            "org.freedesktop.login1.manage",
            resource("Seat", "seat0"),
            &[],
            ADMIN_KEEP,
        ),
        (
            "org.freedesktop.home1.passwd-home",
            home("alice"),
            &[],
            ALLOW,
        ),
        (
            "org.freedesktop.home1.passwd-home",
            home("bob"),
            &[],
            ADMIN_KEEP,
        ),
        // Owners can't remove their own home without an admin.
        (
            "org.freedesktop.home1.remove-home",
            home("alice"),
            &[],
            ADMIN_KEEP,
        ),
        (
            "org.freedesktop.machine1.shell",
            machine("alice"),
            &[],
            ALLOW,
        ),
        ("org.freedesktop.machine1.shell", machine("bob"), &[], ADMIN),
        (
            "org.freedesktop.machine1.manage-machines",
            machine("alice"),
            &[("verb", "terminate")],
            ALLOW,
        ),
        // Owners may stop their machine, but not copy files out of it.
        (
            "org.freedesktop.machine1.manage-machines",
            machine("alice"),
            &[("verb", "copy")],
            ADMIN,
        ),
        (
            "org.freedesktop.resolve1.unregister-service",
            resource("DnssdService", "web").with_attr("owner", user("alice")),
            &[],
            ALLOW,
        ),
        // A home whose UID isn't allocated yet has no owner to skip authentication.
        (
            "org.freedesktop.home1.passwd-home",
            resource("Home", "carol"),
            &[],
            ADMIN_KEEP,
        ),
        (
            "io.systemd.credentials.decrypt",
            credential("user", Some("alice")),
            &[("timestamp_fresh", "1")],
            ALLOW,
        ),
        // A backdated timestamp needs authentication even for one's own credentials.
        (
            "io.systemd.credentials.decrypt",
            credential("user", Some("alice")),
            &[("timestamp_fresh", "0")],
            ADMIN_KEEP,
        ),
        (
            "io.systemd.credentials.encrypt",
            credential("user", Some("bob")),
            &[("timestamp_fresh", "1")],
            ADMIN_KEEP,
        ),
        (
            "io.systemd.credentials.encrypt",
            credential("system", None),
            &[("timestamp_fresh", "1")],
            ADMIN_KEEP,
        ),
    ];

    for (action, resource, details, want) in cases {
        let id = resource.uid.to_string();
        assert_eq!(
            check(&authority, action, resource, remote, details),
            want,
            "{action} {id}"
        );
    }
}

#[test]
fn admins_can_tighten_defaults() {
    let mut src = read_tree(Path::new(POLICIES), "cedar").unwrap();
    src.push_str(
        r#"
        // Always ask for an admin password to set the time, never remember it.
        forbid (principal, action == Action::"org.freedesktop.timedate1.set-time", resource)
        unless { context.auth.identity == "admin" && context.auth.fresh };

        // Make even active local users enter their own password to reboot.
        forbid (principal, action == Action::"org.freedesktop.login1.reboot", resource)
        unless { ["self", "admin"].contains(context.auth.identity) };
        "#,
    );
    let schema = read_tree(Path::new(POLICIES), "cedarschema").unwrap();
    let authority = Authority::new(&src, &schema).unwrap();
    const SELF_KEEP: Decision = Decision::Challenge(Challenge::SELF_KEEP);

    let cases = [
        (
            "org.freedesktop.timedate1.set-time",
            resource("Clock", "system"),
            [ADMIN; 3],
        ),
        (
            "org.freedesktop.login1.reboot",
            resource("System", "local"),
            [ADMIN_KEEP, ADMIN_KEEP, SELF_KEEP],
        ),
        // Other actions are unaffected.
        (
            "org.freedesktop.timedate1.set-ntp",
            resource("Clock", "ntp"),
            [ADMIN_KEEP; 3],
        ),
    ];
    for (action, resource, expected) in cases {
        for (session, want) in SESSIONS.into_iter().zip(expected) {
            let got = check(&authority, action, resource.clone(), session, &[]);
            assert_eq!(got, want, "{action} {session:?}");
        }
    }
}
