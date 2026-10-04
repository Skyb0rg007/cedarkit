#!/usr/bin/env python3
"""Translate polkit .policy action files into CedarKit schema and policies.

For each `<name>.policy` (or `<name>.policy.in`) found under SRC, writes
`<name>.cedarschema` (action declarations) and `<name>.cedar` (the polkit
defaults as Cedar policies) into OUT, which is the application's directory
in a CedarKit vendor root (docs/design.md, section 8.1). It also writes
`_namespace.cedarschema`, declaring the application's namespace NAMESPACE and
the action prefixes it owns.

polkit's auth_admin results ask for the role `Role::"<name>.admin"`, so that
the local admin decides who may approve each application's actions. For
these, it also writes `<name>.entities.json`, putting the general
`Role::"admin"` in that role by default.

polkit's `imply` annotation becomes extra permits for the implied actions
(docs/design.md, section 7.5).

Every action must have an entry in the resource map, giving the resource
types it applies to, optionally a context type, and the id of the singleton
resource it acts on, if any:

    {"org.freedesktop.login1.chvt": {"resource": ["logind::Seat"]},
     "org.freedesktop.timedate1.set-ntp": {"resource": ["systemd::Clock"],
                                           "id": "systemd::Clock::\"ntp\""},
     ...}

Usage: polkit2cedar.py SRC OUT NAMESPACE LABEL RESOURCE_MAP
  e.g. polkit2cedar.py ~/src/systemd policies/systemd systemd "systemd 262" tools/systemd-resources.json
"""

import json
import os
import sys
import xml.etree.ElementTree as ET

COLS = ("any", "inactive", "active")

# polkit picks exactly one column: `allow_active` for local active sessions,
# `allow_inactive` for other local sessions, and `allow_any` for everything
# else. Cedar instead combines every policy that applies, and the least
# demanding permit wins. So each column becomes a policy for every session it
# could apply to, which gives polkit's answer as long as each column is at
# least as permissive as the broader one before it. check_ordered() enforces
# that.
#
# polkit's "local" and "active", from logind's facts about the subject: the
# session is the process's own session, or the user's graphical session if it
# has none.
LOCAL = (
    "context.subject has logind &&\n"
    "  ((context.subject.logind has session && context.subject.logind.session has seat) ||\n"
    "   (!(context.subject.logind has session) &&\n"
    "    context.subject.logind has display && context.subject.logind.display has seat))"
)
SESSIONS = {
    "any": (None, "any session"),
    "inactive": (LOCAL, "local sessions"),
    "active": (f"{LOCAL} &&\n  context.subject.logind.user_active", "active local sessions"),
}

# polkit's results, as conditions on how the subject has authenticated
# (`context.auth`): auth_self asks for the subject's own password, and
# auth_admin for that of anyone in `role`. `_keep` also accepts an
# authentication remembered for the same action, on any resource, as polkit's
# temporary authorizations.
WHO = {
    "self": "context.auth has user && context.auth.user == principal",
    "admin": "context.auth has user && context.auth.user in Role::{role}",
}


def who(result, role):
    return WHO["admin" if result.startswith("auth_admin") else "self"].format(role=q(role))


def auth_condition(result, role):
    if result == "yes":
        return None
    if result.endswith("_keep"):
        return f"{who(result, role)} && context.auth.action == action"
    return f"{who(result, role)} && context.auth.fresh"


RESULT_ORDER = ["yes", "auth_self_keep", "auth_self", "auth_admin_keep", "auth_admin"]

# The kinds of authentication (who, fresh) that satisfy each result, to
# compare how permissive results are: the subject's own password when they
# aren't in the role ("self"), when they are ("self_admin"), or someone else
# in the role ("admin").
_AUTHS = [(w, f) for w in ("none", "self", "self_admin", "admin") for f in (False, True)]
SATISFIED_BY = {
    "yes": set(_AUTHS),
    "auth_self_keep": {a for a in _AUTHS if a[0] in ("self", "self_admin")},
    "auth_self": {a for a in _AUTHS if a[0] in ("self", "self_admin") and a[1]},
    "auth_admin_keep": {a for a in _AUTHS if a[0] in ("admin", "self_admin")},
    "auth_admin": {a for a in _AUTHS if a[0] in ("admin", "self_admin") and a[1]},
    "no": set(),
}


def q(s):
    return json.dumps(s)


def find_policy_files(src):
    found = {}
    for root, _, files in os.walk(src):
        for f in files:
            for ext in (".policy", ".policy.in"):
                if f.endswith(ext):
                    found[f[: -len(ext)]] = os.path.join(root, f)
    return dict(sorted(found.items()))


def parse_actions(path):
    actions = []
    root = ET.parse(path).getroot()
    for a in root.findall("action"):
        d = a.find("defaults")
        defaults = {
            c: ((d.findtext(f"allow_{c}") or "no").strip() if d is not None else "no")
            for c in COLS
        }
        ann = {x.get("key"): (x.text or "").strip() for x in a.findall("annotate")}
        actions.append(
            dict(
                id=a.get("id"),
                desc=(a.findtext("description") or "").strip(),
                message=(a.findtext("message") or "").strip(),
                vendor=(a.findtext("vendor") or root.findtext("vendor") or "").strip(),
                vendor_url=(a.findtext("vendor_url") or root.findtext("vendor_url") or "").strip(),
                icon=(a.findtext("icon_name") or root.findtext("icon_name") or "").strip(),
                defaults=defaults,
                implies=ann.get("org.freedesktop.policykit.imply", "").split(),
                owners=ann.get("org.freedesktop.policykit.owner", "").split(),
            )
        )
    return actions


def write_schema(path, header, actions, resources):
    out = [header]
    for a in actions:
        r = resources[a["id"]]
        out.append("")
        out.append(f"@doc({q(a['desc'])})")
        # For the polkit-compatible front end (docs/design.md, section 11).
        if a["message"]:
            out.append(f"@message({q(a['message'])})")
        out.append(f"@defaults({q(' '.join(a['defaults'][c] for c in COLS))})")
        if a["owners"]:
            out.append(f"@owners({q(' '.join(a['owners']))})")
        for key in ("vendor", "vendor_url", "icon"):
            if a[key]:
                out.append(f"@{key}({q(a[key])})")
        if a["implies"]:
            out.append(f"@implies({q(' '.join(a['implies']))})")
        if "id" in r:
            out.append(f"@singleton({q(r['id'])})")
        out.append(f"action {q(a['id'])} appliesTo {{")
        out.append("  principal: [User],")
        out.append(f"  resource: [{', '.join(r['resource'])}],")
        out.append(f"  context: {r.get('context', 'Context')},")
        out.append("};")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")


def write_entities(path, role):
    """Puts the general admin role in the application's admin role."""
    entities = [
        {
            "uid": {"type": "Role", "id": "admin"},
            "attrs": {},
            "parents": [{"type": "Role", "id": role}],
        }
    ]
    with open(path, "w") as f:
        json.dump(entities, f, indent=2)
        f.write("\n")


def check_ordered(action):
    """Exits unless each column is at least as permissive as the broader one."""
    d = action["defaults"]
    for c in COLS:
        if d[c] not in SATISFIED_BY:
            sys.exit(f"{action['id']}: unknown polkit result {d[c]!r}")
    for broad, narrow in zip(COLS, COLS[1:]):
        if not SATISFIED_BY[d[broad]] <= SATISFIED_BY[d[narrow]]:
            sys.exit(
                f"{action['id']}: allow_{broad} ({d[broad]}) isn't at least as restrictive "
                f"as allow_{narrow} ({d[narrow]}), which this translation doesn't support"
            )


def columns(action):
    """The (result, column) pairs that need a policy: a column with the same
    result as the broader one is already covered by it."""
    out = []
    broader = None
    for c in COLS:
        result = action["defaults"][c]
        if result not in ("no", broader):
            out.append((result, c))
        broader = result
    return out


def permit(out, policy_id, comment, ids, clauses):
    out.append("")
    out.append(f"// {comment}")
    out.append(f"@id({q(policy_id)})")
    out.append("permit (\n  principal,")
    if len(ids) == 1:
        out.append(f"  action == Action::{q(ids[0])},")
    else:
        out.append("  action in [")
        out.append(",\n".join(f"    Action::{q(i)}" for i in ids))
        out.append("  ],")
    out.append("  resource\n)" + "".join(f"\nwhen {{\n  {c}\n}}" for c in clauses if c) + ";")


def write_policies(path, header, name, actions, implied_by, everything, roles):
    # Group actions sharing a result for the same column.
    groups = {}
    for a in actions:
        check_ordered(a)
        for result, col in columns(a):
            groups.setdefault((result, col), []).append(a["id"])

    def sort_key(k):
        return (RESULT_ORDER.index(k[0]), COLS.index(k[1]))

    role = roles[name]
    out = [header]
    for result, col in sorted(groups, key=sort_key):
        session, sessions = SESSIONS[col]
        verb = "Allowed" if result == "yes" else f"Requires {result}"
        permit(
            out,
            f"{name}/{result}/{col}",
            f"{verb} for {sessions}.",
            groups[(result, col)],
            [session, auth_condition(result, role)],
        )

    # imply: being allowed an implying action A also allows the implied one,
    # either by A's defaults without authentication, or by an authentication
    # remembered for A (for A's _keep results).
    for a in actions:
        for implier in implied_by.get(a["id"], []):
            source = everything[implier]
            for result, col in columns(source):
                if result.startswith("auth_") and not result.endswith("_keep"):
                    continue
                session, sessions = SESSIONS[col]
                auth = None
                if result != "yes":
                    auth = (
                        f"{who(result, roles[source['service']])} &&\n"
                        f"  context.auth.action == Action::{q(implier)}"
                    )
                how = "allowed" if result == "yes" else f"remembered for it ({result})"
                permit(
                    out,
                    f"{a['id']}/implied-by/{implier}/{col}",
                    f"Implied by {implier}, {how}, for {sessions}.",
                    [a["id"]],
                    [session, auth],
                )

    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")


def write_namespace(path, header, namespace, prefixes):
    with open(path, "w") as f:
        f.write(f"{header}\n\n")
        f.write("// The action prefixes this application owns (docs/design.md, section 8.2).\n")
        f.write(f"@prefixes({q(' '.join(sorted(prefixes)))})\n")
        f.write(f"namespace {namespace} {{}}\n")


def main():
    if len(sys.argv) != 6:
        sys.exit(__doc__)
    src, out_dir, namespace, label, resource_map = sys.argv[1:]
    with open(resource_map) as f:
        resources = json.load(f)
    os.makedirs(out_dir, exist_ok=True)

    files = {name: (path, parse_actions(path)) for name, path in find_policy_files(src).items()}
    everything = {}
    for name, (_, actions) in files.items():
        missing = [a["id"] for a in actions if a["id"] not in resources]
        if missing:
            sys.exit(f"{name}: no resource mapping for {', '.join(missing)}")
        for a in actions:
            everything[a["id"]] = dict(a, service=name)
    roles = {name: f"{name}.admin" for name in files}

    # Actions implied by each action; undeclared ones are ignored.
    implied_by = {}
    for a in everything.values():
        for target in a["implies"]:
            if target in everything and target != a["id"]:
                implied_by.setdefault(target, []).append(a["id"])

    prefixes = set()
    for name, (path, actions) in files.items():
        header = (
            f"// Generated by tools/polkit2cedar.py from {label} {os.path.basename(path)}.\n"
            "// Do not edit; regenerate instead."
        )
        # The file's name prefixes its role, and usually its actions.
        prefixes.add(name + ".")
        prefixes.update(a["id"].rsplit(".", 1)[0] + "." for a in actions)
        write_schema(os.path.join(out_dir, name + ".cedarschema"), header, actions, resources)
        write_policies(
            os.path.join(out_dir, name + ".cedar"),
            header,
            name,
            actions,
            implied_by,
            everything,
            roles,
        )
        entities_path = os.path.join(out_dir, name + ".entities.json")
        if any(r.startswith("auth_admin") for a in actions for r in a["defaults"].values()):
            write_entities(entities_path, roles[name])
        elif os.path.exists(entities_path):
            os.remove(entities_path)

    write_namespace(
        os.path.join(out_dir, "_namespace.cedarschema"),
        f"// Generated by tools/polkit2cedar.py from {label}.\n// Do not edit; regenerate instead.",
        namespace,
        {p for p in prefixes if not any(p != q and p.startswith(q) for q in prefixes)},
    )

    stale = sorted(set(resources) - set(everything))
    if stale:
        print(f"warning: resource map has unknown actions: {', '.join(stale)}", file=sys.stderr)
    print(f"translated {len(everything)} actions")


if __name__ == "__main__":
    main()
