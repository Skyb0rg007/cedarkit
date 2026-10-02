#!/usr/bin/env python3
"""Translate polkit .policy action files into CedarKit schema and policies.

For each `<name>.policy` (or `<name>.policy.in`) found under SRC, writes
`<name>.cedarschema` (action declarations) and `<name>.cedar` (the polkit
defaults as Cedar policies) into OUT.

Every action must have an entry in the resource map, giving the resource
types it applies to, optionally a context type, and the id of the singleton
resource it acts on, if any:

    {"org.freedesktop.login1.chvt": {"resource": ["Seat"]},
     "org.freedesktop.timedate1.set-ntp": {"resource": ["Clock"], "id": "Clock::\"ntp\""},
     ...}

Usage: polkit2cedar.py SRC OUT LABEL RESOURCE_MAP
  e.g. polkit2cedar.py ~/src/systemd policies/systemd "systemd 262" tools/systemd-resources.json
"""

import json
import os
import sys
import xml.etree.ElementTree as ET

COLS = ("any", "inactive", "active")

# polkit picks `allow_active` for local active sessions, `allow_inactive` for
# other local sessions, and `allow_any` for everything else.
CONDITIONS = {
    frozenset({"any", "inactive", "active"}): None,
    frozenset({"inactive", "active"}): "context.local",
    frozenset({"active"}): "context.local && context.active",
    frozenset({"inactive"}): "context.local && !context.active",
    frozenset({"any"}): "!context.local",
    frozenset({"any", "inactive"}): "!(context.local && context.active)",
    frozenset({"any", "active"}): "!context.local || context.active",
}
COND_DESC = {
    None: "any session",
    "context.local": "local sessions",
    "context.local && context.active": "active local sessions",
    "context.local && !context.active": "inactive local sessions",
    "!context.local": "non-local sessions",
    "!(context.local && context.active)": "inactive or non-local sessions",
    "!context.local || context.active": "active or non-local sessions",
}
RESULT_ORDER = ["yes", "auth_self", "auth_self_keep", "auth_admin", "auth_admin_keep"]
# polkit's authentication results, as conditions on how the subject has
# authenticated (`context.auth`). Authenticating as an admin also counts as
# authenticating as yourself; `_keep` accepts a remembered authentication.
AUTH_CONDITIONS = {
    "auth_self_keep": '["self", "admin"].contains(context.auth.identity)',
    "auth_self": '["self", "admin"].contains(context.auth.identity) && context.auth.fresh',
    "auth_admin_keep": 'context.auth.identity == "admin"',
    "auth_admin": 'context.auth.identity == "admin" && context.auth.fresh',
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
    for a in ET.parse(path).getroot().findall("action"):
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
                defaults=defaults,
                implies=ann.get("org.freedesktop.policykit.imply", "").split(),
            )
        )
    return actions


def write_schema(path, header, actions, resources):
    out = [header]
    for a in actions:
        r = resources[a["id"]]
        out.append("")
        out.append(f"@doc({q(a['desc'])})")
        if a["implies"]:
            out.append(f"@implies({q(' '.join(a['implies']))})")
        if "id" in r:
            out.append(f"@singleton({q(r['id'])})")
        out.append(f"action {q(a['id'])} appliesTo {{")
        out.append("  principal: [User],")
        out.append(f"  resource: [{', '.join(r['resource'])}],")
        out.append(f"  context: {r.get('context', 'SessionContext')},")
        out.append("};")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")


def write_policies(path, header, actions):
    # Group actions sharing a result for the same set of session kinds.
    groups = {}
    for a in actions:
        by_result = {}
        for c in COLS:
            by_result.setdefault(a["defaults"][c], set()).add(c)
        for result, cols in by_result.items():
            if result == "no":
                continue
            if result not in RESULT_ORDER:
                sys.exit(f"{a['id']}: unknown polkit result {result!r}")
            groups.setdefault((result, frozenset(cols)), []).append(a["id"])

    def sort_key(k):
        return (RESULT_ORDER.index(k[0]), [c in k[1] for c in COLS][::-1])

    out = [header]
    for result, cols in sorted(groups, key=sort_key):
        cond = CONDITIONS[cols]
        ids = groups[(result, cols)]
        verb = "Allowed" if result == "yes" else f"Requires {result}"
        out.append("")
        out.append(f"// {verb} for {COND_DESC[cond]}.")
        out.append("permit (\n  principal,")
        if len(ids) == 1:
            out.append(f"  action == Action::{q(ids[0])},")
        else:
            out.append("  action in [")
            out.append(",\n".join(f"    Action::{q(i)}" for i in ids))
            out.append("  ],")
        clauses = [f"when {{ {c} }}" for c in (cond, AUTH_CONDITIONS.get(result)) if c]
        out.append("  resource\n)" + "".join(f"\n{c}" for c in clauses) + ";")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    src, out_dir, label, resource_map = sys.argv[1:]
    with open(resource_map) as f:
        resources = json.load(f)
    os.makedirs(out_dir, exist_ok=True)

    seen = set()
    for name, path in find_policy_files(src).items():
        actions = parse_actions(path)
        missing = [a["id"] for a in actions if a["id"] not in resources]
        if missing:
            sys.exit(f"{name}: no resource mapping for {', '.join(missing)}")
        seen.update(a["id"] for a in actions)

        header = (
            f"// Generated by tools/polkit2cedar.py from {label} {os.path.basename(path)}.\n"
            "// Do not edit; regenerate instead."
        )
        write_schema(os.path.join(out_dir, name + ".cedarschema"), header, actions, resources)
        write_policies(os.path.join(out_dir, name + ".cedar"), header, actions)

    stale = sorted(set(resources) - seen)
    if stale:
        print(f"warning: resource map has unknown actions: {', '.join(stale)}", file=sys.stderr)
    print(f"translated {len(seen)} actions")


if __name__ == "__main__":
    main()
