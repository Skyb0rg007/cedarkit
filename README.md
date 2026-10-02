# CedarKit

This project is a polkit alternative, which uses the [Cedar](https://www.cedarpolicy.com/) policy language.


## Building

Use `nix-shell` to download the needed programs.

```sh
nix-shell
cargo build
cargo test
```


## Layout

| Path                    | What it is                                                     |
|-------------------------|----------------------------------------------------------------|
| `crates/cedarkit-core`  | The authorization engine: loads policies, evaluates requests   |
| `crates/cedarkitd`      | D-Bus daemon exposing `org.cedarkit.Authority1`                |
| `crates/cedarctl`       | CLI for checking requests and validating policies locally      |
| `policies/`             | Core Cedar schema (`cedarkit.cedarschema`)                     |
| `policies/systemd/`     | systemd's polkit actions translated to Cedar (see below)       |
| `tools/`                | `polkit2cedar.py` and the systemd action → resource map        |
| `data/`                 | D-Bus system bus configuration                                 |


## Policy model

Each check is turned into a Cedar request:

- **principal**: `User::"<name>"`, a member of each of its `Group::"<name>"`s
- **action**: `Action::"<action id>"`, using polkit-style ids such as `org.freedesktop.login1.reboot`
- **resource**: the object the action acts on, e.g. `Unit::"sshd.service"` or `Session::"3"`, with its attributes (such as its `owner`) and any entities it belongs to
- **context**: `{ local: Bool, active: Bool, auth: Authentication }`, plus `details: { ... }` holding the polkit details the action's context type declares

This deliberately goes beyond polkit, which is told only an action id and, sometimes, loose string details. Because Cedar sees the real object, a policy can say "the owner of a session may lock it" instead of relying on each daemon to special-case owners before asking.

### Authentication

Cedar only answers allow or deny, so how the user has authenticated is part of the request: `context.auth` is an `Authentication` entity with two attributes.
- `identity` is `"none"`, `"self"` (their own password) or `"admin"` (an administrator's password);
- `fresh` is whether that password was just entered, rather than remembered from an earlier authentication.

polkit's results become ordinary conditions on it:

| polkit            | Cedar condition |
|-------------------|-----------------|
| `yes`             | none |
| `auth_self_keep`  | `["self", "admin"].contains(context.auth.identity)` |
| `auth_self`       | `["self", "admin"].contains(context.auth.identity) && context.auth.fresh` |
| `auth_admin_keep` | `context.auth.identity == "admin"` |
| `auth_admin`      | `context.auth.identity == "admin" && context.auth.fresh` |
| `no`              | no policy at all, since Cedar denies by default |

To decide what to ask for, CedarKit evaluates in three steps:

1. **As the user has actually authenticated** (today, never, as nobody is prompted yet). If that's allowed, the result is `allow`.
2. **With the authentication unknown**, using Cedar's type-aware partial evaluation (TPE). If the request is denied however the user might authenticate, the result is `deny`, without prompting. This is why `Authentication` is an entity: TPE can leave an entity's attributes unknown, but not part of the context.
3. **Otherwise, the weakest authentication that works**, found by re-evaluating only what's left of the policies with progressively stronger authentication: own password remembered, own password entered, admin password remembered, admin password entered. The result is the matching challenge (`auth_self_keep`, ..., `auth_admin`).

Results use polkit's names. Remembering authentications for a while isn't implemented yet.

polkit's three default columns become conditions on the session:

| polkit           | Cedar condition                      |
|------------------|--------------------------------------|
| `allow_active`   | `context.local && context.active`    |
| `allow_inactive` | `context.local && !context.active`   |
| `allow_any`      | `!context.local`                     |

```cedar
// Requires auth_admin_keep for inactive or non-local sessions.
permit (
  principal,
  action in [Action::"org.freedesktop.login1.reboot", Action::"org.freedesktop.login1.power-off"],
  resource
)
when { !(context.local && context.active) }
when { context.auth.identity == "admin" };
```

### Making defaults stricter

Cedar combines all policies: a `permit` can only allow more, and a `forbid` overrides any `permit`. So an action is made stricter with a `forbid ... unless` naming what's required. For example, in a local `.cedar` file:

```cedar
// Always ask for an admin password to set the time, never remember it
// (the default is auth_admin_keep).
forbid (principal, action == Action::"org.freedesktop.timedate1.set-time", resource)
unless { context.auth.identity == "admin" && context.auth.fresh };

// Make even active local users enter their own password to reboot
// (the default is yes).
forbid (principal, action == Action::"org.freedesktop.login1.reboot", resource)
unless { ["self", "admin"].contains(context.auth.identity) };
```

`cedarctl check` takes `--auth self|admin` and `--fresh` to evaluate a request as if the user had authenticated.

Policies are loaded from every `*.cedar` file under the policy directory, recursively, and the schema from every `*.cedarschema` file there. The schema is required:
- **At load:** policies must validate against it, or loading fails.
- **On every check:** requests are checked against it too, so a resource of the wrong type, a missing required attribute, or a missing declared detail is an error.
- **Undeclared actions** are denied.

`cedarctl validate` reports the same validation errors, plus warnings, such as a policy that can never match because its action doesn't apply to that resource type.


## systemd policies

`policies/systemd/` covers all 158 polkit actions in systemd's `main` branch plus the fixes in the [polkit-fixes branch](#systemd-patches). Each action is mapped to the resource it acts on, based on reading where systemd checks it.

| File | Written by | Contents |
|------|------------|----------|
| `entities.cedarschema` | hand | The resource types (`Session`, `Unit`, `Machine`, `Link`, `Home`, ...), their attributes, and the polkit details that carry them |
| `ownership.cedar` | hand | Cases where systemd lets an object's owner through without asking polkit |
| `<service>.cedarschema` | generated | Each action, with its polkit description as `@doc`, its `org.freedesktop.policykit.imply` list as `@implies`, the resource types it applies to, and the id of the singleton it acts on (`@singleton`), if any |
| `<service>.cedar` | generated | polkit's defaults for each action |

Regenerate after a systemd update with:

```sh
tools/polkit2cedar.py ~/src/systemd/src policies/systemd "systemd <version>" tools/systemd-resources.json
tools/details.py policies tools/systemd-resources.json
```

The converter refuses to run if an action has no entry in `tools/systemd-resources.json`, so new actions have to be looked at and given a resource. `details.py` checks that every resource type an action applies to is either identified by a polkit detail or named by the action, and that every attribute says which detail carries it.

### From polkit details to resources

To evaluate a polkit check, CedarKit needs the resource and the attributes the model uses. The `@detail` annotations in the schemas say which polkit detail supplies each one. Details holding a user, such as `uid` or `owner_uid`, carry a numeric uid, which is resolved to the user's name. Resource types without a detail are singletons, named by each action's `@singleton`.

An attribute is only modelled when systemd itself uses it to decide authorization. Today that means skipping polkit for the object's owner, which `ownership.cedar` expresses as policy instead. Context details are only modelled when a policy reads them: `verb` for `machine1.manage-machines`, and `timestamp_fresh` for credentials.

| Resource | Identified by | Attributes | Actions |
|----------|---------------|------------|---------|
| `Cgroup` | `cgroup` | – | 1 |
| `Clock` | fixed per action | – | 3 |
| `Credential` | `credential` | scope ← `scope`, owner? ← `uid` | 2 |
| `Device` | `device` | – | 4 |
| `Directory` | `directory` | – | 6 |
| `DnssdService` | `dnssd_service` | owner ← `owner_uid` | 2 |
| `ExtensionHierarchy` | fixed per action | – | 4 |
| `Hardware` | fixed per action | – | 3 |
| `Home` | `username` | owner? ← `uid` | 8 |
| `Hostname` | `hostname_type` | – | 2 |
| `Image` | `class`, `image` | root? ← `image_root` | 8 |
| `ImageFile` | `image_path` | – | 5 |
| `ImagePool` | `class` | root? ← `image_root` | 4 |
| `InhibitTarget` | fixed per action | – | 10 |
| `InstanceMetadata` | `wellKnown` | key? ← `key` | 1 |
| `Keyboard` | fixed per action | – | 1 |
| `Link` | `interface` | – | 24 |
| `Locale` | fixed per action | – | 1 |
| `Machine` | `machine` | owner ← `owner_uid` | 10 |
| `MachineInfo` | `machine_info_key` | – | 1 |
| `Manager` | fixed per action | – | 6 |
| `NetworkConfig` | fixed per action | – | 2 |
| `Resolver` | fixed per action | – | 8 |
| `Seat` | `seat` | – | 2 |
| `Session` | `session` | owner ← `owner_uid` | 2 |
| `SigningKey` | `signing_key` | – | 1 |
| `StorageVolume` | `name` | – | 1 |
| `System` | fixed per action | – | 26 |
| `TimeSync` | fixed per action | – | 1 |
| `Timezone` | fixed per action | – | 1 |
| `Transfer` | `transfer` | – | 1 |
| `Unit` | `unit` | – | 1 |
| `UpdateTarget` | `class`, `name` | – | 9 |
| `User` | `uid` | name ← `uid`, uid ← `uid` | 4 |
| `UserNamespace` | `name` | – | 4 |

### systemd patches

Unpatched systemd passes few of these details. The `polkit-fixes` branch of systemd fixes the inconsistencies in its polkit checks (see `systemd-262-bugs.md`), then passes every detail in the table above, one commit per changed action.

Some behaviour is not modelled yet:

- **Daemon-level shortcuts:** each daemon still lets root, or its own service user, skip the check entirely. For `namespace-resource.delegate-mount`, which only root may call, this means polkit is never consulted.
- **Extra request parameters:** many actions take parameters that could belong in the request context, such as a job mode or a shutdown that overrides inhibitors. Only those read by a policy are modelled.

## Trying it out

```sh
cargo run -p cedarctl -- --policies policies validate
cargo run -p cedarctl -- --policies policies check org.freedesktop.login1.reboot \
    --resource 'System::"local"' --local --active

# The owner of a session may terminate it without authenticating
cargo run -p cedarctl -- --policies policies check org.freedesktop.login1.manage \
    --resource 'Session::"3"' --attr "owner=User::\"$(id -un)\""

# Run the daemon on the session bus and query it. Arguments: uid, action,
# resource, resource attributes (entity references as (ss) type/id
# structs), resource parents, details.
cargo run -p cedarkitd -- --policies policies --session &
busctl --user call org.cedarkit.Authority1 /org/cedarkit/Authority1 \
    org.cedarkit.Authority1 CheckAuthorization 'ussa{sv}asa{ss}' \
    "$(id -u)" org.freedesktop.login1.manage 'Session::"3"' \
    1 owner '(ss)' User "$(id -un)" 0 0
```


## Roadmap

- [ ] Fill in session state (`local`/`active`) from logind
- [ ] Authenticate callers of the daemon
- [ ] Authentication agents and running the challenge
- [ ] Implement `org.freedesktop.PolicyKit1.Authority` so existing polkit clients work unchanged
- [ ] Reload policies when they change on disk
- [x] Translate systemd's polkit actions, with real resources
- [x] Patch systemd to pass the details these resources need to polkit
- [ ] Build resources from polkit details in the `org.freedesktop.PolicyKit1.Authority` implementation, following the `@detail` annotations
- [ ] Per-action context types (job mode, inhibitor overrides, ...)
- [ ] Temporary authorizations (`_keep`, `@implies`)
- [ ] A built-in translator for arbitrary polkit `.policy` files
