# CedarKit

This project is a polkit alternative, which uses the [Cedar](https://www.cedarpolicy.com/) policy language.

[`docs/design.md`](docs/design.md) defines the authorization model: what policies, entity data and callers can rely on. This file is an overview.


## Building

Use `nix-shell` to download the needed programs.

```sh
nix-shell
cargo build
cargo test
```


## Layout

| Path                         | What it is                                                         |
|------------------------------|--------------------------------------------------------------------|
| `crates/cedarkit-core`       | The authorization engine: loads files, evaluates requests          |
| `crates/cedarkit-logind`     | logind's fact provider: what logind knows about a process          |
| `crates/cedarkitd`           | The daemon: `org.cedarkit.Authority1` on D-Bus, `org.cedarkit.Agent` on Varlink, and `cedarkit-pam-helper` |
| `crates/cedarkit-agent`      | `cedarkit-agent`, a GTK authentication agent after GNOME Shell's   |
| `crates/cedarkit-agent-protocol` | The `org.cedarkit.Agent` Varlink interface                     |
| `crates/cedarctl`            | CLI for checking requests and validating policies                  |
| `policies/`                  | Vendor files, laid out like `/usr/share/cedarkit`                  |
| `policies/cedarkit/`         | CedarKit's own: the default admin role                             |
| `policies/logind/`           | logind's fact provider schema                                      |
| `policies/systemd/`          | systemd's polkit actions translated to Cedar (see below)           |
| `state/subject.cedarschema`  | The generated subject schema for `policies/`                       |
| `tools/`                     | `polkit2cedar.py`, `details.py`, and the systemd action → resource map |
| `data/`                      | D-Bus configuration (CedarKit's, and polkit's for `--polkit`), the `cedarkit` PAM service, and the agent's autostart entry |


## Policy model

Each check is one Cedar request:

- **principal**: the caller's `User::"<uid>"`, a member of its `Group::"<name>"`s and of `Role`s
- **action**: `Action::"<action id>"`, using polkit-style ids such as `org.freedesktop.login1.reboot`
- **resource**: the object the action acts on, e.g. `systemd::Unit::"sshd.service"` or `logind::Session::"3"`, with its attributes (such as its `owner`)
- **context**: `{ subject, auth }`, plus `details` for actions that declare any

This deliberately goes beyond polkit, which is told only an action id and, sometimes, loose string details. Because Cedar sees the real object, a policy can say "the owner of a session may lock it" instead of relying on each daemon to special-case owners before asking.

### The subject

`context.subject` holds what fact providers know about the calling process, one optional attribute per provider. logind's is built in: `context.subject.logind` is a `logind::Process`, with the process's `session`, the user's graphical `display` session, and whether any of the user's sessions is active (`user_active`). Policies can be as precise as logind is, for example "from a seat", or "in the caller's own session".

`Subject` itself is declared in a generated file, `/var/lib/cedarkit/subject.cedarschema`, which `cedarctl schema update` writes from the installed providers' `@subject` types.

### Authentication

Cedar only answers allow or deny, so how the caller has authenticated is part of the request: `context.auth` is an `Authentication` entity.
- `user` is who entered a password, if anyone did; it may be someone else, such as an admin;
- `fresh` is whether that happened during this check, rather than being remembered from an earlier one;
- `action` and `same_resource` say what a remembered authentication was given for.

polkit's results become ordinary conditions on it:

| polkit            | Cedar condition |
|-------------------|-----------------|
| `yes`             | none |
| `auth_self_keep`  | `context.auth has user && context.auth.user == principal && context.auth.action == action` |
| `auth_self`       | `context.auth has user && context.auth.user == principal && context.auth.fresh` |
| `auth_admin_keep` | `context.auth has user && context.auth.user in Role::"<prefix>admin" && context.auth.action == action` |
| `auth_admin`      | `context.auth has user && context.auth.user in Role::"<prefix>admin" && context.auth.fresh` |
| `no`              | no policy at all, since Cedar denies by default |

So by default, a remembered authentication counts for the same action on any resource, as polkit's temporary authorizations do. A policy can accept less, by also requiring `context.auth.same_resource`, or more, for example any of a group of related actions.

As in polkit, an authentication is only remembered after a `_keep` challenge, for the process that asked (and sibling processes in the same terminal), until it expires after 5 minutes (polkit's `ExpirationSeconds`) or the process exits.

### Roles

What "an admin" means is up to each machine, not the application. Policies ask for a role, such as `Role::"org.freedesktop.timedate1.admin"`, and entity data files (`*.entities.json`, in Cedar's JSON entity format) say who's in it. They hold role memberships and nothing else: users (by uid), groups and roles, in roles. Memberships combine across files:

```json
[
  { "uid": { "type": "Group", "id": "wheel" },
    "parents": [{ "type": "Role", "id": "admin" }] }
]
```

Here, `policies/cedarkit/admin.entities.json` makes `wheel` the general admin role, and each application's generated `<service>.entities.json` puts `Role::"admin"` in that application's admin role. To let the `netadmin` group approve network changes too, add `/etc/cedarkit/local/netadmin.entities.json`:

```json
[
  { "uid": { "type": "Group", "id": "netadmin" },
    "parents": [{ "type": "Role", "id": "org.freedesktop.network1.admin" }] }
]
```

### Results

A check is `allow`, `deny`, or `challenge` with a list of users who could authenticate to allow it, the caller first. Each says whether a remembered authentication by them would be accepted (`keep`). CedarKit finds them by trying the caller, every member of a role, and the users the resource refers to, such as its owner.

The request is denied if nobody could pass, if the action isn't declared, if the request doesn't match the schema, if a user it refers to doesn't exist, or if any policy fails to evaluate.

### Authentication agents

When a check is a challenge and the caller allows interaction, `cedarkitd` asks the authentication agent of the caller's session to have the user authenticate, and answers once they have. `cedarkit-agent` follows GNOME Shell's polkit dialog: it asks for one user's password (yours if you're listed, otherwise root's), shows PAM's messages as they come, and lets you try again until you succeed or cancel. For an account without a password, it just asks you to confirm.

Agents talk to `cedarkitd` over [Varlink](https://varlink.org/), as `org.cedarkit.Agent` on `/run/cedarkit/org.cedarkit.Agent`. They only relay PAM's conversation: PAM runs in `cedarkit-pam-helper`, which `cedarkitd` starts as root, so `cedarkitd` sees the result itself. A successful authentication is remembered for the process that asked. If the caller gives up first (`CancelCheckAuthorization`, leaving the bus, or the process exiting), the dialog closes and the check is denied.

### Standing in for polkit

`cedarkitd --polkit` also serves polkit's own D-Bus interface, `org.freedesktop.PolicyKit1`, so unmodified polkit clients (`pkcheck`, systemd, GNOME) and polkit's authentication agents (GNOME Shell's, `pkttyagent`) work with it in place of polkitd. Resources are built from the details mechanisms pass, following the schema's `@detail` annotations, so systemd needs the [patches](#systemd-patches) that pass them; anything that can't be resolved is denied. Install `data/org.freedesktop.PolicyKit1.conf` in place of polkit's bus configuration, and stop polkitd.

polkit's labels (`auth_self`, `auth_admin_keep`, ...) only exist for polkit compatibility: `auth_self` if the caller is the only option, otherwise `auth_admin`, and `_keep` if remembered authentications would be accepted.

### polkit's session columns

polkit has three default columns, and picks exactly one per caller: `allow_active` for a local session in the foreground, `allow_inactive` for any other local session, and `allow_any` for everyone else. Cedar instead combines every policy that applies, and the least demanding permit wins. So each column becomes a policy for every session it could apply to, written over logind's facts:

| polkit           | Cedar condition |
|------------------|-----------------|
| `allow_any`      | none |
| `allow_inactive` | *local*: the process's session, or failing that the user's display session, has a seat |
| `allow_active`   | *local* `&& context.subject.logind.user_active` |

This gives polkit's answer as long as each column is at least as permissive as the broader one. That's true of all of systemd's actions, and `polkit2cedar.py` refuses to translate an action where it isn't. For example, `login1.reboot` is `auth_admin_keep` / `auth_admin_keep` / `yes`, and is in the groups of actions with those results:

```cedar
// Allowed for active local sessions.
@id("org.freedesktop.login1/yes/active")
permit (principal, action in [Action::"org.freedesktop.login1.reboot", ...], resource)
when {
  context.subject has logind &&
  ((context.subject.logind has session && context.subject.logind.session has seat) ||
   (!(context.subject.logind has session) &&
    context.subject.logind has display && context.subject.logind.display has seat)) &&
  context.subject.logind.user_active
};

// Requires auth_admin_keep for any session.
@id("org.freedesktop.login1/auth_admin_keep/any")
permit (principal, action in [Action::"org.freedesktop.login1.reboot", ...], resource)
when {
  context.auth has user && context.auth.user in Role::"org.freedesktop.login1.admin" &&
  context.auth.action == action
};
```

polkit's `imply` becomes more permits: an action implied by A is allowed where A is `yes`, and with an authentication remembered for A where A is `_keep`.

### Making defaults stricter

A `permit` can only allow more, and a `forbid` overrides any `permit`. So an action is made stricter with a `forbid ... unless` naming what's required, in a local `.cedar` file:

```cedar
// Always ask for an admin password to set the time, never remember it
// (the default is auth_admin_keep).
@id("local/set-time")
forbid (principal, action == Action::"org.freedesktop.timedate1.set-time", resource)
unless {
  context.auth has user &&
  context.auth.user in Role::"org.freedesktop.timedate1.admin" &&
  context.auth.fresh
};
```

### Files

| Directory | Contents |
|-----------|----------|
| `/usr/share/cedarkit/<app>/` | Vendor schemas, policies and entity data for one application |
| `/etc/cedarkit/<app>/` | The local admin's replacements for vendor files with the same name |
| `/etc/cedarkit/local/` | The local admin's own files |
| `/var/lib/cedarkit/subject.cedarschema` | Written by `cedarctl schema update` |

Vendor files are confined to their application: its namespace, its actions (those starting with the prefixes it declares with `@prefixes` on its namespace), and its roles. The local admin's files can contain anything. Everything must validate against the schema, or CedarKit doesn't start. `cedarctl validate` reports the same errors, plus warnings about likely mistakes, such as a role with no members.


## systemd policies

`policies/systemd/` covers all 158 polkit actions in systemd's `main` branch plus the fixes in the [polkit-fixes branch](#systemd-patches). Each action is mapped to the resource it acts on, based on reading where systemd checks it.

| File | Written by | Contents |
|------|------------|----------|
| `entities.cedarschema` | hand | The resource types in `namespace systemd` (`Unit`, `Machine`, `Link`, `Home`, ...), their attributes, and the polkit details that carry them |
| `ownership.cedar` | hand | Cases where systemd lets an object's owner through without asking polkit |
| `_namespace.cedarschema` | generated | The action prefixes systemd owns |
| `<service>.cedarschema` | generated | Each action, with its polkit description as `@doc`, its `org.freedesktop.policykit.imply` list as `@implies`, the resource types it applies to, and the id of the singleton it acts on (`@singleton`), if any |
| `<service>.cedar` | generated | polkit's defaults for each action, and the permits that `imply` adds |
| `<service>.entities.json` | generated | Puts `Role::"admin"` in the service's admin role, `Role::"<service>.admin"` |

Sessions and seats are logind's types, `logind::Session` and `logind::Seat`, which CedarKit fills in from logind itself.

Regenerate after a systemd update with:

```sh
tools/polkit2cedar.py ~/src/systemd/src policies/systemd systemd "systemd <version>" tools/systemd-resources.json
tools/details.py policies tools/systemd-resources.json
```

The converter refuses to run if an action has no entry in `tools/systemd-resources.json`, so new actions have to be looked at and given a resource. `details.py` checks that every resource type an action applies to is either identified by a polkit detail or named by the action, and that every attribute says which detail carries it.

### From polkit details to resources

To evaluate a polkit check, CedarKit needs the resource and the attributes the model uses. The `@detail` annotations in the schemas say which polkit detail supplies each one. Details holding a user, such as `uid` or `owner_uid`, carry a numeric uid, which is the user's id. Resource types without a detail are singletons, named by each action's `@singleton`.

An attribute is only modelled when systemd itself uses it to decide authorization. Today that means skipping polkit for the object's owner, which `ownership.cedar` expresses as policy instead. Context details are only modelled when a policy reads them: `verb` for `machine1.manage-machines`, and `timestamp_fresh` for credentials.

| Resource | Identified by | Attributes | Actions |
|----------|---------------|------------|---------|
| `User` | `uid` | – | 4 |
| `logind::Seat` | `seat` | – | 2 |
| `logind::Session` | `session` | user ← built in, seat? ← built in, remote ← built in, class ← built in, type ← built in, active ← built in | 2 |
| `systemd::Cgroup` | `cgroup` | – | 1 |
| `systemd::Clock` | fixed per action | – | 3 |
| `systemd::Credential` | `credential` | scope ← `scope`, owner? ← `uid` | 2 |
| `systemd::Device` | `device` | – | 4 |
| `systemd::Directory` | `directory` | – | 6 |
| `systemd::DnssdService` | `dnssd_service` | owner ← `owner_uid` | 2 |
| `systemd::ExtensionHierarchy` | fixed per action | – | 4 |
| `systemd::Hardware` | fixed per action | – | 3 |
| `systemd::Home` | `username` | owner? ← `uid` | 8 |
| `systemd::Hostname` | `hostname_type` | – | 2 |
| `systemd::Image` | `class`, `image` | root? ← `image_root` | 8 |
| `systemd::ImageFile` | `image_path` | – | 5 |
| `systemd::ImagePool` | `class` | root? ← `image_root` | 4 |
| `systemd::InhibitTarget` | fixed per action | – | 10 |
| `systemd::InstanceMetadata` | `wellKnown` | key? ← `key` | 1 |
| `systemd::Keyboard` | fixed per action | – | 1 |
| `systemd::Link` | `interface` | – | 24 |
| `systemd::Locale` | fixed per action | – | 1 |
| `systemd::Machine` | `machine` | owner ← `owner_uid` | 10 |
| `systemd::MachineInfo` | `machine_info_key` | – | 1 |
| `systemd::Manager` | fixed per action | – | 6 |
| `systemd::NetworkConfig` | fixed per action | – | 2 |
| `systemd::Resolver` | fixed per action | – | 8 |
| `systemd::SigningKey` | `signing_key` | – | 1 |
| `systemd::StorageVolume` | `name` | – | 1 |
| `systemd::System` | fixed per action | – | 26 |
| `systemd::TimeSync` | fixed per action | – | 1 |
| `systemd::Timezone` | fixed per action | – | 1 |
| `systemd::Transfer` | `transfer` | – | 1 |
| `systemd::Unit` | `unit` | – | 1 |
| `systemd::UpdateTarget` | `class`, `name` | – | 9 |
| `systemd::UserNamespace` | `name` | – | 4 |

### systemd patches

Unpatched systemd passes few of these details. The `polkit-fixes` branch of systemd fixes the inconsistencies in its polkit checks (see `systemd-262-bugs.md`), then passes every detail in the table above, one commit per changed action.

Some behaviour is not modelled yet:

- **Daemon-level shortcuts:** each daemon still lets root, or its own service user, skip the check entirely. For `namespace-resource.delegate-mount`, which only root may call, this means polkit is never consulted.
- **Extra request parameters:** many actions take parameters that could belong in the request context, such as a job mode or a shutdown that overrides inhibitors. Only those read by a policy are modelled.

## Trying it out

```sh
cedarctl() { cargo run -q -p cedarctl -- --vendor policies --admin local \
    --subject-schema state/subject.cedarschema "$@"; }

cedarctl validate

# Asks logind about this shell's session.
cedarctl check org.freedesktop.login1.reboot --reasons

# Or pretend: none, remote, inactive or active.
cedarctl check org.freedesktop.login1.reboot --session inactive

# The owner of a machine may terminate it without authenticating.
cedarctl check org.freedesktop.machine1.manage-machines \
    --resource 'systemd::Machine::"box"' --attr "owner=User::\"$(id -u)\"" --detail verb=terminate

# As if an admin had authenticated earlier, for this action on another clock.
cedarctl check org.freedesktop.timedate1.set-time --auth-user root \
    --auth-resource 'systemd::Clock::"rtc"'

# Run the daemon on the session bus and query it. Arguments: the subject
# ("" for the caller), the action, the resource (id, attributes, parents),
# details, flags and a cancellation id ("" for none). It replies with the decision and, for a challenge, who
# could authenticate: (uid, name, keep).
cargo run -p cedarkitd -- --vendor policies --admin local \
    --subject-schema state/subject.cedarschema --session &
busctl --user call org.cedarkit.Authority1 /org/cedarkit/Authority1 \
    org.cedarkit.Authority1 CheckAuthorization '(sa{sv})s(sa{sv}as)a{sv}us' \
    "" 0 org.freedesktop.login1.reboot 'systemd::System::"local"' 0 0 0 0 ""
```

To try the agent, without installing a PAM service, use a PAM configuration directory with a test service, e.g. `pam/cedarkit-test`:

```
auth    required  pam_exec.so expose_authtok quiet /path/to/check-password
account required  pam_permit.so
```

```sh
cargo build
target/debug/cedarkitd --vendor policies --admin local --subject-schema state/subject.cedarschema \
    --session --agent-socket "$XDG_RUNTIME_DIR/cedarkit/agent" \
    --pam-service cedarkit-test --pam-confdir pam &
target/debug/cedarkit-agent --socket "$XDG_RUNTIME_DIR/cedarkit/agent" &

# Flags 1: AllowUserInteraction. The dialog appears, and the call returns once
# you've authenticated or cancelled.
busctl --user call --timeout=120 org.cedarkit.Authority1 /org/cedarkit/Authority1 \
    org.cedarkit.Authority1 CheckAuthorization '(sa{sv})s(sa{sv}as)a{sv}us' \
    "" 0 org.freedesktop.timedate1.set-time 'systemd::Clock::"system"' 0 0 0 1 ""
```

To try the polkit front end with polkit's own tools, point them at the session bus:

```sh
target/debug/cedarkitd --vendor policies --admin local --subject-schema state/subject.cedarschema \
    --session --polkit &
export DBUS_SYSTEM_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS
pkaction --action-id org.freedesktop.login1.reboot --verbose
pkcheck --process $$ --action-id org.freedesktop.timedate1.set-time
pkcheck --process $$ --action-id org.freedesktop.machine1.shell \
    --detail machine box --detail owner_uid "$(id -u)"
```

After changing which fact providers are installed, regenerate the subject schema with `cedarctl schema update`.


## Roadmap

- [x] Translate systemd's polkit actions, with real resources
- [x] Patch systemd to pass the details these resources need to polkit
- [x] Facts about the caller from logind
- [x] Identify callers of the daemon from their D-Bus credentials
- [x] Remembered authentications, matched by policy
- [x] Authentication agents and running the challenge
- [x] Forget remembered authentications when they expire or the process exits, as polkit
- [x] Implement `org.freedesktop.PolicyKit1.Authority` so existing polkit clients work unchanged, building resources from polkit details following the `@detail` annotations
- [ ] Let mechanisms other than root report resources ([design, open question 1](docs/design.md#13-open-questions))
- [ ] Reload policies when they change on disk
- [ ] Per-action context types (job mode, inhibitor overrides, ...)
- [ ] A built-in translator for arbitrary polkit `.policy` files
