# CedarKit authorization model, v1

Status: **draft for freezing.** Once accepted, everything in the [contract](#1-what-is-frozen) changes only by the [evolution rules](#10-evolving-the-contract).

This document defines what policies, entity data and callers can rely on. Anything not listed here, including how the engine computes its answers, is implementation detail and may change.

## Contents

1. [What is frozen](#1-what-is-frozen)
2. [Actors and trust](#2-actors-and-trust)
3. [Identities](#3-identities)
4. [The request](#4-the-request)
5. [Core schema](#5-core-schema)
6. [Application schemas](#6-application-schemas)
7. [Policy idioms](#7-policy-idioms)
8. [Files and loading](#8-files-and-loading)
9. [Evaluation](#9-evaluation)
10. [Evolving the contract](#10-evolving-the-contract)
11. [The polkit-compatible front end](#11-the-polkit-compatible-front-end)
12. [Decisions and rationale](#12-decisions-and-rationale)
13. [Open questions](#13-open-questions)
14. [Implementation status](#14-implementation-status)

## 1. What is frozen

The **contract** consists of:

- the core schema ([section 5](#5-core-schema)): entity types, their attributes, and the meaning of each attribute;
- the rule for generating `Subject` from the installed fact providers ([section 6.5](#65-fact-providers)), though not any particular generated file;
- the shape of a request ([section 4](#4-the-request));
- the rules applications must follow for their schemas, policies and entity data ([sections 6](#6-application-schemas)–[8](#8-files-and-loading));
- the evaluation guarantees ([section 9](#9-evaluation)), but not the algorithm;
- the native result format ([section 9.4](#94-results));
- the file layout and trust boundary ([section 8](#8-files-and-loading)).

**Not** part of the contract:

- how the engine evaluates, including partial evaluation (TPE) and how it finds candidate users;
- the text of generated policies, `tools/polkit2cedar.py` and `tools/systemd-resources.json`;
- the Rust crate API and `cedarctl` flags;
- the polkit result labels (`auth_self`, …), which exist only in the [polkit-compatible front end](#11-the-polkit-compatible-front-end).

## 2. Actors and trust

| Actor | Trusted for | Supplies |
|---|---|---|
| CedarKit itself | everything it derives | the subject process, user and group entities, authentication state |
| Fact providers (logind, sshd, …) | facts about the subject, in their own namespace only | what they know about the calling process, e.g. its logind session or its SSH connection |
| Kernel, logind, NSS | authoritative facts | process credentials, sessions, accounts, group membership |
| Mechanisms (logind, machined, …) | their own objects only | the resource, its attributes and parents, and the request details, for actions in their namespace |
| Applications (vendor files) | their own namespace only | schemas, policies and role memberships for their own actions and roles |
| Local admin (`/etc` files) | everything | any policy, schema or role membership |
| Authentication agents | showing a challenge to the user of their session | the user's choice to authenticate or not, and their answers to PAM's prompts, never the result |
| PAM, run by CedarKit | verifying credentials | whether user U authenticated |
| Unprivileged callers | nothing | only the question being asked |

Consequences, all enforced by CedarKit:

- **The subject is the calling process.** CedarKit identifies it from the D-Bus connection's credentials (pidfd where available, otherwise pid plus start time) and derives the uid and groups itself. A caller never supplies a uid. Everything else known about the subject comes from fact providers ([section 6.5](#65-fact-providers)). Checking on behalf of another process is limited to root and to mechanisms, as in polkit.
- **Authentication state** comes only from PAM, which CedarKit runs itself (fresh), and from CedarKit's store of remembered authentications. It never comes from files, callers, mechanisms or agents ([section 9.6](#96-authentication-agents)).
- **Resource facts** are accepted only from mechanisms allowed to assert them for that namespace, and **subject facts** only from the provider that owns the namespace (see [open question 1](#13-open-questions)).
- **Vendor files** can only affect their own namespace ([section 8.2](#82-what-vendor-files-may-contain)).

## 3. Identities

| Entity | Id | Attributes | Source |
|---|---|---|---|
| `User` | the uid, as a string: `User::"1000"` | `uid: Long`, `name?: String` | NSS; `name` is absent for accounts without one |
| `Group` | the group name: `Group::"wheel"` | `gid?: Long` | NSS |
| `Role` | a name: `Role::"admin"`, `Role::"org.freedesktop.login1.admin"` | none | entity data files |

- Users are identified by uid because it never changes and every account has one. A policy that means a specific user by name writes `principal has name && principal.name == "alice"`; one that means them by uid writes `principal == User::"1000"` or `principal.uid == 1000`.
- Groups are identified by name because memberships are almost always written per group, and readable entity files matter more there. Groups without a name don't occur in practice.
- A user's groups are all the groups NSS reports for them, including their primary group.
- Memberships: `User in [Group, Role]`, `Group in [Role]`, `Role in [Role]`. A user's group memberships come only from NSS; role memberships only from entity data files.

## 4. The request

Every check is one Cedar request:

- **principal**: the subject's `User`.
- **action**: `Action::"<action id>"`, using the polkit-style reverse-DNS id, e.g. `Action::"org.freedesktop.login1.reboot"`. Actions are always in the root namespace.
- **resource**: the object the action acts on, of a type declared by the application, e.g. `systemd::Unit::"sshd.service"` or `logind::Session::"3"`. For actions that act on the machine as a whole, a singleton named by the action (`@singleton`).
- **context**: exactly `{ subject: Subject, auth: Authentication }`, plus `details` for actions that declare any ([section 6.3](#63-context-types-and-details)).

### 4.1 The subject

`context.subject` is an entity holding what fact providers know about the calling process. It has one optional attribute per installed provider, named after the provider's namespace: for example, `context.subject.logind` for logind's view of the process, and `context.subject.sshd` for sshd's view of its connection. An attribute is absent when the provider knows nothing about the process.

CedarKit itself defines no session facts. In particular, polkit's "local" and "active" are not part of the contract. The policy translator expresses them as conditions over logind's facts ([section 7.2](#72-session-columns)).

### 4.2 Authentication

`context.auth` describes how the subject has authenticated for this request.

- `user` is set **only** when a credential was verified for that user: a password, or in future FIDO2, a fingerprint and so on. Nothing weaker, such as a click-to-confirm, ever sets it. It may differ from the principal, e.g. an admin approving for someone else.
- `fresh` is true if the authentication happened during this check, and false if it was remembered from an earlier one.
- `action` is the action the authentication was given for. For a fresh authentication, this is the requested action.
- `same_resource` is true if the authentication was given for this request's resource. It's always true for a fresh authentication.

When the subject hasn't authenticated, `user` is absent, `fresh` is false, `action` is the requested action and `same_resource` is true.

## 5. Core schema

`cedarkit.cedarschema`, in the root namespace:

```cedar
// Version 1 of the CedarKit core schema. Changes are append-only:
// see docs/design.md, section 10.

entity Role in [Role];

entity Group in [Role] {
  gid?: Long,
};

// Id: the uid, e.g. User::"1000".
entity User in [Group, Role] {
  uid: Long,
  name?: String,
};

// entity Subject: what fact providers know about the calling process.
// Declared in the generated subject schema, with one optional attribute per
// installed fact provider (docs/design.md, section 6.5).

// How the subject has authenticated for this request.
entity Authentication {
  // Set only when a credential was verified for this user.
  user?: User,
  // Authenticated during this check, rather than remembered.
  fresh: Bool,
  // The action the authentication was given for.
  action: Action,
  // The authentication was given for this request's resource.
  same_resource: Bool,
};

type Context = { subject: Subject, auth: Authentication };
```

`Subject` and `Authentication` are entities rather than records so that new attributes and memberships can be added without touching any application's context types, and so that the engine may leave authentication unknown when evaluating partially.

With logind's provider installed, the generated subject schema contains `entity Subject { logind?: logind::Process };`.

## 6. Application schemas

### 6.1 Namespaces

Each application declares its types in its own Cedar namespace, named after its directory: for example, `namespace systemd { entity Unit; }`. Policies refer to them as `systemd::Unit`. Core types (`User`, `Group`, `Role`, `Subject`, `Authentication`, `Context`) are in the root namespace and are referred to unqualified.

### 6.2 Actions

- Actions are declared in the root namespace, with ids that start with one of the application's **action prefixes** (e.g. `org.freedesktop.login1.`). The application declares its prefixes with `@prefixes("…")` on its namespace, space-separated, each ending in a dot:

  ```cedar
  @prefixes("org.freedesktop.login1. org.freedesktop.timedate1.")
  namespace systemd {}
  ```

  The same prefixes name its roles, e.g. `Role::"org.freedesktop.login1.admin"`. No two applications' prefixes may overlap.
- An action may be in **action groups** declared by the same application, for use in authentication reuse ([section 7.4](#74-remembered-authentications)).
- Optional annotations:

| Annotation | Meaning |
|---|---|
| `@doc("…")` | the human-readable description (polkit's `<description>`) |
| `@singleton("Type::\"id\"")` | the resource, for actions that always act on the same one |
| `@implies("a b …")` | polkit's `org.freedesktop.policykit.imply`: being allowed this action also allows the listed ones ([section 7.5](#75-implied-actions)) |

### 6.3 Context types and details

- An action's context is either the core `Context`, or a record with exactly `subject: Subject`, `auth: Authentication` and `details: { … }`.
- `details` holds request facts the mechanism passes in addition to the resource, for example the `verb` of a machine operation.
- Every detail is **optional** and **typed** with a Cedar type (`String`, `Long`, `Bool`, or an entity type). Policies must check `context.details has <name>` before using one. A mechanism that passes fewer details therefore never causes an error.
- Details not declared for the action are dropped.

### 6.4 Resource types and polkit details

Resource entity types and their attributes carry `@detail("…")` annotations naming the polkit details that identify them, for the [polkit-compatible front end](#11-the-polkit-compatible-front-end). For example, `@detail("machine")` on `systemd::Machine`, and `@detail("owner_uid")` on its `owner` attribute. Users, and the types of built-in fact providers such as `logind::Session`, are built by CedarKit itself; mechanisms only name them. A detail holding a user is a uid, and becomes `User::"<uid>"` directly.

### 6.5 Fact providers

A fact provider tells CedarKit about the calling process. A provider:

- owns a namespace, like an application;
- marks one entity type in it with `@subject` as its **subject facts**, describing what it knows about a process;
- may declare further types those facts refer to, such as sessions or seats.

#### The subject schema

`Subject` is declared in a generated schema file, `/var/lib/cedarkit/subject.cedarschema`, with one optional attribute per installed provider, named after the namespace and typed as its subject facts:

```cedar
// Generated by `cedarctl schema update`. Do not edit.
entity Subject {
  logind?: logind::Process,
  sshd?: sshd::Connection,
};
```

This follows the pattern used for Kubernetes custom resources by Cedar's Kubernetes integrations: types that depend on what's installed are generated by a tool and written to a file, rather than invented by the authorizer.
- **The file is static.** CedarKit only ever loads files, so the type policies are checked against is always written down, and any Cedar tool can validate against it. Installing or removing a provider never changes the core schema.
- **`cedarctl schema update` writes it.** It scans the installed provider schemas for `@subject` types and writes the file. Package hooks run it after a provider is installed or removed; an admin can run it too.
- **Updates are all-or-nothing.** Before writing, it validates every installed policy against the new schema. If any fails, typically because it uses facts from a provider that's no longer installed, it reports those policies and leaves the old file in place.
- **Out-of-date files are caught at load.**
  - If the file names a provider namespace that no longer exists, CedarKit refuses to start, like any other schema error.
  - If an installed provider is missing from it, CedarKit starts with a warning and doesn't consult that provider until the file is updated.

How facts are obtained:
- **Built-in providers:** CedarKit queries the source itself. logind's provider is built in.
- **External providers:** the provider reports facts for specific processes of a subject, e.g. sshd for the processes of a connection. CedarKit accepts them only from that provider ([open question 1](#13-open-questions)), and forgets them when those processes exit.

#### logind's provider

```cedar
namespace logind {
  @detail("seat")
  entity Seat;

  // A logind session, by session id. Also the resource of login1's session
  // actions; CedarKit fills in its attributes from logind.
  @detail("session")
  entity Session {
    user: User,
    seat?: Seat,
    remote: Bool,
    // "user", "greeter", "lock-screen", "background", "manager", ...
    class: String,
    // "tty", "x11", "wayland", "unspecified", ...
    type: String,
    active: Bool,
  };

  // What logind knows about the calling process.
  @subject
  entity Process {
    // The process's own session, if it's in one.
    session?: Session,
    // The user's graphical session, if any.
    display?: Session,
    // Some session of the user is active.
    user_active: Bool,
  };
}
```

Facts are reported as logind states them. Policies can be precise in ways polkit can't express, for example "the caller's own session", "from a seat", or "in a graphical session":

```cedar
permit (principal, action == Action::"org.freedesktop.login1.lock-sessions", resource)
when {
  context.subject has logind && context.subject.logind has session &&
  resource == context.subject.logind.session && resource has seat
};
```

#### An external provider, for example sshd

```cedar
namespace sshd {
  @subject
  entity Connection {
    client: ipaddr,
    // The authorized principals of the key or certificate used.
    principals: Set<String>,
    key_type: String,
  };
}
```

```cedar
permit (principal, action == Action::"org.freedesktop.login1.reboot", resource)
when {
  context.subject has sshd &&
  context.subject.sshd.principals.contains("ops-oncall") &&
  context.subject.sshd.client.isInRange(ip("10.0.0.0/8"))
};
```

## 7. Policy idioms

Policies are ordinary Cedar: default deny, `permit`s add, and `forbid`s override every `permit`.

### 7.1 Authentication patterns

Generated policies, and policies written by applications, express polkit's results with exactly these conditions:

| polkit | condition |
|---|---|
| `yes` | none |
| `auth_self_keep` | `context.auth has user && context.auth.user == principal && context.auth.action == action && context.auth.same_resource` |
| `auth_self` | `context.auth has user && context.auth.user == principal && context.auth.fresh` |
| `auth_admin_keep` | `context.auth has user && context.auth.user in Role::"<prefix>admin" && context.auth.action == action && context.auth.same_resource` |
| `auth_admin` | `context.auth has user && context.auth.user in Role::"<prefix>admin" && context.auth.fresh` |
| `no` | no policy |

`<prefix>admin` is the application's admin role, e.g. `Role::"org.freedesktop.login1.admin"`. New authentication features, such as requiring a specific method, are added as **additional conditions** next to these. The patterns themselves never change. `cedarctl validate` warns about authentication conditions that don't match one of these patterns.

### 7.2 Session columns

polkit's three default columns become cumulative conditions over logind's facts, defined the way polkit derives them. The session is the process's own session, or the user's graphical session if the process has none:

| polkit | condition |
|---|---|
| `allow_any` | none |
| `allow_inactive` | *local* |
| `allow_active` | *local* `&& context.subject.logind.user_active` |

where *local* is:

```cedar
context.subject has logind &&
((context.subject.logind has session && context.subject.logind.session has seat) ||
 (!(context.subject.logind has session) &&
  context.subject.logind has display && context.subject.logind.display has seat))
```

These conditions are generated, and aren't part of the contract. They depend only on logind's facts, which are. A subject logind knows nothing about has no `logind` attribute, so only `allow_any` applies to it, as in polkit.

This matches polkit only when each column is at least as permissive as the broader one. The translator rejects `.policy` files where that doesn't hold, and leaves out a column whose result is the same as the broader one's.

### 7.3 Changing defaults

- **Loosening:** add a `permit`, e.g. let a group use an action without authenticating.
- **Tightening:** add a `forbid … unless { <requirement> }`, e.g. require a fresh admin authentication:

  ```cedar
  forbid (principal, action == Action::"org.freedesktop.timedate1.set-time", resource)
  unless {
    context.auth has user &&
    context.auth.user in Role::"org.freedesktop.timedate1.admin" &&
    context.auth.fresh
  };
  ```

- **Who counts as an admin:** entity data, not policy ([section 8.3](#83-entity-data)).

### 7.4 Remembered authentications

By default (the generated `_keep` patterns), a remembered authentication counts only for the same action on the same resource. Policies decide when it counts for more:

```cedar
// Any of these time settings may use an admin authentication remembered
// from any of the others, on any clock.
permit (principal, action in Action::"org.freedesktop.timedate1.settings", resource)
when {
  context.auth has user &&
  context.auth.user in Role::"org.freedesktop.timedate1.admin" &&
  context.auth.action in Action::"org.freedesktop.timedate1.settings"
};
```

where the application's schema declares `action "org.freedesktop.timedate1.set-time" in ["org.freedesktop.timedate1.settings"]`, and so on.

### 7.5 Implied actions

polkit's `imply`: an action A that implies X means that being allowed A also allows X. Cedar policies can't ask whether another action would be allowed, so the translator makes it explicit:

polkit grants X when the subject is already authorized for A without interacting: by A's defaults, or by a temporary authorization for A. The translator copies exactly that:

- **Defaults:** for each action X implied by A, each `yes` permit of A is emitted again for X, with the same session condition. In systemd this matters: `login1.reboot` is `yes` for active local sessions and implies `login1.set-wall-message`, which is otherwise `auth_admin_keep`.
- **Remembered authentications:** each `_keep` permit of A is emitted for X with the same session condition, and the authentication condition `context.auth has user && <who> && context.auth.action == Action::"<A>"`. A remembered authentication for A on any resource then covers X, as in polkit, whose resources differ between A and X anyway.
- **Fresh authentications:** A's `auth_self` and `auth_admin` permits aren't copied. polkit never prompts for X on A's behalf.
- **Not carried over:** policies added to A later, by the local admin or anyone else, don't automatically apply to X. polkit would apply them, because it evaluates A in full. To extend them to X, write them for both actions, or for an action group containing both.
- **Undefined actions:** an implied action that isn't declared anywhere (systemd's `machine1` actions name some that don't exist) is ignored.

The engine has no special handling for `imply`.

### 7.6 Policy ids

Every generated policy has an `@id`: `"<file>/<result>/<column>"` for the defaults, which group the actions of a `.policy` file with the same result, e.g. `@id("org.freedesktop.login1/yes/active")`, and `"<X>/implied-by/<A>/<column>"` for implied actions. Policies without an `@id` are named after their file and position. Hand-written policies should have one too. Ids appear in diagnostics and logs.

## 8. Files and loading

### 8.1 Layout

| Directory | Owner | Contents |
|---|---|---|
| `/usr/share/cedarkit/<app>/` | vendor (packages) | `*.cedarschema`, `*.cedar`, `*.entities.json` for one application, `<app>` being its namespace |
| `/etc/cedarkit/<app>/` | local admin | same; a file here replaces the vendor file with the same relative path |
| `/etc/cedarkit/local/` | local admin | additional schemas, policies and entity data |
| `/var/lib/cedarkit/subject.cedarschema` | `cedarctl schema update` | the generated `Subject` declaration ([section 6.5](#65-fact-providers)); never edited by hand |

The core schema is part of CedarKit itself. `/usr/share/cedarkit/cedarkit/` holds CedarKit's own vendor files, such as the default admin role, and isn't restricted like other applications'. Files are read in lexical path order. A file that can't be read or parsed stops loading with an error naming the file.

### 8.2 What vendor files may contain

The rules below are checked at load time. A vendor file that breaks them is rejected, and CedarKit refuses to start, naming the file.

- **Schemas:** only the namespace `<app>`, and in the root namespace only actions starting with the application's declared action prefixes, in action groups of its own.
- **Policies:** the action constraint must be a closed set of the application's own actions (`action == …` or `action in [ … ]`, including its own action groups). A policy that doesn't constrain the action is rejected.
- **Entity data:** only memberships whose parent is one of the application's own roles (`Role::"<prefix>…"`).
- **`@implies`:** may only list the application's own actions.

Files under `/etc` are unrestricted.

### 8.3 Entity data

Entity data files (`*.entities.json`, Cedar's JSON entity format) declare **role memberships and nothing else**:

- Entities may only be of type `User`, `Group` or `Role`, with no attributes, and with only `Role` parents.
- The same entity may appear in several files; its memberships are combined. There is no way to remove a membership declared elsewhere. To take away what a role grants, write a `forbid`.
- Memberships are merged into the entities CedarKit builds for a request. They never replace facts from NSS, mechanisms or authentication.

Defaults:

- `/usr/share/cedarkit/cedarkit/admin.entities.json`: `Group::"wheel"` in `Role::"admin"`.
- Each application: `Role::"admin"` in `Role::"<prefix>admin"`.

### 8.4 Validation at load

- Policies must validate against the combined schema: the core schema, all application and provider schemas, and the generated subject schema.
- Entity data must follow [section 8.3](#83-entity-data).
- Vendor files must follow [section 8.2](#82-what-vendor-files-may-contain).
- **Any failure stops loading.** CedarKit doesn't start with a partial policy set.

`cedarctl validate` reports the same errors, plus warnings:
- a policy that can never apply;
- a role that a policy refers to but that has no members;
- an authentication condition that doesn't match the patterns in [section 7.1](#71-authentication-patterns).

## 9. Evaluation

### 9.1 Guarantees

The engine's answer satisfies all of these, however it computes them.

1. **Allow** means Cedar allows the request with the subject's actual authentication, which is fresh or remembered.
2. **Challenge** means at least one listed option would make Cedar allow the request, and each listed option does.
3. **Deny** means no option CedarKit knows of would make Cedar allow the request.
4. **Fail closed.** The request is denied if:
   - the action isn't declared;
   - a request fact doesn't match the schema;
   - a user referred to by the resource can't be resolved;
   - **any policy fails to evaluate**;
   - nobody known could pass a challenge.
5. **Monotonic.** Adding a `permit` never makes the answer more demanding. Adding a `forbid` never makes it less demanding.

### 9.2 Remembered authentications

- After an agent reports a successful authentication, CedarKit remembers it, recording:
  - the subject process, identified by pidfd or pid plus start time;
  - the authenticated user;
  - the action and resource it was given for;
  - an expiry time.
- It's forgotten when it expires (by default 5 minutes, configurable), when the process exits, or when the subject's session ends.
- When checking a request, the engine tries each authentication remembered for the subject process, with `fresh = false` and `action`/`same_resource` set from the record. The request is allowed if Cedar allows it with any of them.
- Whether a remembered authentication counts is decided only by policy ([section 7.4](#74-remembered-authentications)).

### 9.3 Challenges

When authenticating could help, the engine finds users who could authenticate. These always include the subject, the members of roles that apply, and users the resource refers to. For each user it determines whether a remembered authentication would pass, or only a fresh one.

### 9.4 Results

The native result is one of:

- `allow`;
- `deny`;
- `challenge`, with a list of options, the subject first if present. Each option has:
  - the user, as uid and name;
  - whether a remembered authentication by them would be accepted (`keep`).

Labels such as `auth_admin_keep` are not part of the native result.

### 9.5 Native D-Bus interface

`org.cedarkit.Authority1`:

```
CheckAuthorization(
    (sa{sv}) subject,        // polkit-style subject; defaults to the caller
    s action,
    (s a{sv} as) resource,   // id ("Type::\"id\""), attributes, parents
    a{sv} details,           // typed values
    u flags,                 // AllowUserInteraction, ...
    s cancellation_id)       // for CancelCheckAuthorization; "" for none
  -> (s decision, a(usb) options)   // options: (uid, name, keep)

CancelCheckAuthorization(s cancellation_id)
```

Cancellation ids are scoped to the caller, as in polkit.

The exact wire format is settled when the interface is implemented. It must carry the information above, and it must not take the subject's uid from the caller.

### 9.6 Authentication agents

An authentication agent asks the user to authenticate when a process in their session meets a challenge, like polkit's agents. CedarKit's GNOME-style agent is `cedarkit-agent`.

- **Registering:** an agent connects to `/run/cedarkit/org.cedarkit.Agent` and calls `org.cedarkit.Agent.Register` (Varlink) with the `more` flag. It serves its own login session or, if it has none, its user's graphical session, as determined from its credentials. It can't register for another user's session, and each session has at most one agent.
- **Challenges:** when `CheckAuthorization` has `AllowUserInteraction` and the result is a challenge, CedarKit sends the challenge's options to the agent for the subject's session (or its user's graphical session), with the action and its `@doc` description. The call waits until the request ends. If there's no agent, the challenge is returned as is.
- **Conversation:** the agent chooses one of the options, and calls `Authenticate` and then `Respond`, relaying PAM's prompts and messages to the user and their answers back. PAM runs in `cedarkit-pam-helper`, which CedarKit starts as root for each attempt, with the PAM service `cedarkit`. CedarKit learns the result from PAM itself; an agent can't claim one.
- **Results:** after a failure, the agent may try again. After a success, CedarKit checks the request again with that fresh authentication ([section 4.2](#42-authentication)), remembers the authentication ([section 9.2](#92-remembered-authentications)), and returns the result. If the user dismisses the request, or the agent goes away, the request is denied.
- **Cancellation:** the request ends early, and is denied, if the caller of `CheckAuthorization` cancels it with `CancelCheckAuthorization`, leaves the bus, or the subject process exits. The agent is told, and closes its dialog.
- **Requests** are identified by unguessable cookies, and only the agent's user (or root) may act on them.
- **Accounts without a password:** an agent shouldn't let PAM succeed without the user's say-so. Like GNOME Shell, `cedarkit-agent` asks AccountsService, and for an account whose password mode is "none", shows the request straight away and starts PAM only once the user confirms.

The interface, with each call's semantics, is `crates/cedarkit-agent-protocol/src/org.cedarkit.Agent.varlink`.

## 10. Evolving the contract

- The core schema is **append-only**:
  - new entity types and new optional attributes may be added;
  - new memberships (`in [...]`) may be added to existing types;
  - nothing is renamed, removed or made stricter.
- New required attributes are added only to entities CedarKit always builds itself, and only if the engine can always supply them.
- A change that can't be made append-only goes into a new namespace (`cedarkit2::`) alongside v1, never into v1.
- Wire changes to the native interface create a new interface version (`Authority2`).
- The polkit patterns in [section 7.1](#71-authentication-patterns) never change. New features are expressed as additional conditions.

Foreseen additions, all append-only:
- **Interactive confirmation without a credential:** `Authentication.confirmed?: Bool`.
- **Credential methods** (password, FIDO2, fingerprint): `Authentication.method?`, or a `Method` entity hierarchy that local admins configure ("strong methods") like roles.
- **More facts about the subject:** new providers (sshd, a container manager, …), or new optional attributes on a provider's types, e.g. the process's systemd unit.
- **Authenticating as another user:** already expressible, as `context.auth.user` may be any user.

## 11. The polkit-compatible front end

`org.freedesktop.PolicyKit1.Authority`, for unmodified polkit clients and agents. It's built on the native evaluation and is not part of the Cedar contract.

- **Resources:** built from polkit details using the `@detail` and `@singleton` annotations. Details are converted to the types the schema declares.
- **Labels:** `auth_self` or `auth_self_keep` if the only option is the subject, otherwise `auth_admin` or `auth_admin_keep`. The `_keep` form is used if a remembered authentication would be accepted. The returned `polkit.result` detail carries the same label.
- **Agents:** the agent receives the options as its identity list. A response is accepted only for a listed identity, and is then re-checked with a fresh authentication by that user.
- **Unknown actions and challenges nobody can answer:** denied, like the native interface ([decision 3](#12-decisions-and-rationale)). There's no root fallback.
- **Remembered authentications:** reported with `polkit.temporary_authorization_id`, and can be listed and revoked through polkit's methods.

## 12. Decisions and rationale

| # | Decision | Why |
|---|---|---|
| 1 | Authentication is request data that policies test, not an annotation. | Keeps Cedar's semantics: `forbid` means deny, and annotations never change decisions. Analysis tools can then reason about authentication requirements. |
| 2 | Who counts as an admin is decided by role memberships in entity data. | Applications ship policies that ask for a role, and each machine decides who's in it, without editing application files. This is Cedar's standard way of expressing roles. |
| 3 | Unknown actions and unanswerable challenges are denied in both interfaces. | Fail closed. Chosen over polkit's behaviour (an error, and root as a last-resort identity). |
| 4 | Session columns are cumulative, and non-monotonic `.policy` files are rejected. | Simpler policies; holds for all of systemd's actions. |
| 5 | Users are identified by uid, with an optional `name` attribute. Groups are identified by name. | Uids are stable and every account has one. Group names keep entity files readable. |
| 6 | Remembered authentications record their action and resource, and policies decide what they count for. | Configurable per action. By default stricter than polkit, which reuses an authentication for any resource. |
| 7 | `imply` becomes policy: implied actions get copies of the implying actions' `yes` and `_keep` permits. | Keeps `imply` in Cedar, where analysis tools and admins can see it, instead of in the engine. The cost: later policies for an implying action don't automatically extend to the actions it implies. |
| 8 | Labels exist only in the polkit front end. | The labelling heuristic has changed repeatedly. Keeping it out of the contract means it can change again without breaking anything. |
| 9 | Vendor files are confined to their namespace, and entity data can only add role memberships. | Packages can't grant themselves, or each other, anything outside their own actions. Entity data can't forge facts about requests. |
| 10 | Evaluation errors deny. | A `forbid` that fails to evaluate must not silently stop forbidding. |
| 11 | Facts about the subject come from namespaced fact providers, not fixed core attributes. polkit's local/active are generated conditions over logind's facts. | Any source of facts (logind, sshd, …) can be added without changing the core. Policies can use what logind actually reports, not just polkit's two booleans. |
| 12 | `Subject` is declared in a schema file generated by `cedarctl schema update` when providers are installed or removed, not synthesized when CedarKit loads. | The schema stays static and inspectable, as Cedar expects, while third parties can still add providers. This mirrors how Cedar's Kubernetes integrations generate schemas for custom resources. |

## 13. Open questions

1. **How mechanisms and fact providers are bound to namespaces.** For example, a vendor manifest listing the D-Bus names or uids allowed to report `systemd::` resources or `sshd::` subject facts. Until then, the native interface accepts resource facts only from root, and only built-in providers report subject facts.
2. **Root.** polkit authorizes uid 0 without evaluating anything, unless asked to check anyway. Should CedarKit do the same in the polkit front end, the native interface, or neither? systemd skips polkit for root itself.
3. **Default `_keep` scope.** [Section 7.1](#71-authentication-patterns) uses "same action, same resource". polkit uses "same action, any resource". This could be either default, and is configurable by policy whichever is chosen.
4. **Interaction flag.** Whether a check without `AllowUserInteraction` should still report the options (polkit reports only that a challenge is needed), given that the options reveal who's an admin.

## 14. Implementation status

Implemented:

- the core schema, logind's provider (`policies/logind/`, `crates/cedarkit-logind`), and the generated subject schema with `cedarctl schema update`;
- loading: the vendor and `/etc` layout with masking, the vendor rules, the entity data rules, and errors naming each file or policy;
- evaluation: the guarantees in [section 9.1](#91-guarantees), remembered authentications matched by policy, structured results, and users resolved from the resource and facts;
- `cedarctl validate` with the warnings in [section 8.4](#84-validation-at-load);
- the native D-Bus interface, deriving the subject from the caller's credentials and logind;
- authentication agents ([section 9.6](#96-authentication-agents)), with `cedarkit-agent`, a GTK agent after GNOME Shell's;
- the translator and systemd's policies, in `policies/systemd/`.

Not yet implemented:

- forgetting remembered authentications when the process exits or its session ends;
- the polkit-compatible front end ([section 11](#11-the-polkit-compatible-front-end)); its labels are in `cedarkit_core::polkit`;
- binding mechanisms and providers to namespaces ([open question 1](#13-open-questions)).
