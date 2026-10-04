#!/usr/bin/env python3
"""List the polkit details each resource type needs, and check the model is complete.

Reads the `@detail` annotations from the Cedar schemas under POLICIES and the
action map, and fails if an action applies to a resource type that is neither
identified by a detail nor given a fixed id in the map. Types in the
namespaces of built-in fact providers (logind) are built by CedarKit itself,
so their attributes need no details; nor do users, which are identified by
a uid. Prints a Markdown
table of the details that identify each resource type and its attributes.

Usage: details.py POLICIES RESOURCE_MAP
  e.g. details.py policies tools/systemd-resources.json
"""

import json
import os
import re
import sys

ENTITY = re.compile(r"((?:@\w+\(\"[^\"]*\"\)\s*)*)entity\s+(\w+)[^{;]*(\{.*?\})?\s*;", re.S)
ATTR = re.compile(r"((?:@\w+\(\"[^\"]*\"\)\s*)*)(\w+)(\??)\s*:")
DETAIL = re.compile(r"@detail\(\"([^\"]*)\"\)")
NAMESPACE = re.compile(r"namespace\s+(\w+)\s*\{(.*)\}", re.S)
BUILT_IN = {"logind"}


def strip_comments(src):
    return re.sub(r"//[^\n]*", "", src)


def load_entities(policies):
    entities = {}
    for root, _, files in os.walk(policies):
        for f in sorted(files):
            if f.endswith(".cedarschema"):
                src = strip_comments(open(os.path.join(root, f)).read())
                prefix = ""
                ns = NAMESPACE.search(src)
                if ns:
                    prefix, src = ns.group(1) + "::", ns.group(2)
                for ann, name, body in ENTITY.findall(src):
                    name = prefix + name
                    ident = DETAIL.search(ann)
                    attrs = [
                        (attr, opt == "?", DETAIL.search(a).group(1) if DETAIL.search(a) else None)
                        for a, attr, opt in ATTR.findall(body or "")
                    ]
                    entities[name] = (ident.group(1) if ident else None, attrs)
    return entities


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    policies, resource_map = sys.argv[1:]
    entities = load_entities(policies)
    # Users are core types, which CedarKit builds itself from a uid detail.
    entities["User"] = ("uid", [])
    with open(resource_map) as f:
        actions = json.load(f)

    errors = []
    used = {}
    for action, r in actions.items():
        fixed = r.get("id", "").rsplit("::", 1)[0]
        for ty in r["resource"]:
            if ty not in entities:
                errors.append(f"{action}: unknown resource type {ty}")
            elif ty != fixed and entities[ty][0] is None:
                errors.append(f"{action}: {ty} has neither a @detail nor a fixed id")
            used.setdefault(ty, []).append(action)

    for ty, (_, attrs) in entities.items():
        for attr, _, detail in attrs:
            if ty in used and detail is None and ty.split("::")[0] not in BUILT_IN:
                errors.append(f"{ty}.{attr} has no @detail")

    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    if errors:
        sys.exit(1)

    print("| Resource | Identified by | Attributes | Actions |")
    print("|----------|---------------|------------|---------|")
    for ty in sorted(used):
        ident, attrs = entities[ty]
        if ident is None:
            ident_s = "fixed per action"
        else:
            ident_s = ", ".join(f"`{k}`" for k in re.findall(r"\{(\w+)\}", ident)) or f"`{ident}`"
        attrs_s = ", ".join(
            f"{a}{'?' if opt else ''} ← " + (f"`{d}`" if d else "built in") for a, opt, d in attrs
        ) or "–"
        print(f"| `{ty}` | {ident_s} | {attrs_s} | {len(used[ty])} |")


if __name__ == "__main__":
    main()
