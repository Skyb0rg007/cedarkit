// Ownership rules: the cases where systemd 262 lets a caller through without
// asking polkit because they own the object (its `good_user` check). polkit's
// defaults can't express these, since polkit is never told who owns what.

// logind lets a session's owner terminate, kill, lock and unlock it.
permit (
  principal,
  action in [
    Action::"org.freedesktop.login1.manage",
    Action::"org.freedesktop.login1.lock-sessions"
  ],
  resource is Session
)
when { resource.owner == principal };

// ...and lets a user terminate or kill all of their own sessions.
permit (
  principal,
  action == Action::"org.freedesktop.login1.manage",
  resource is User
)
when { resource == principal };

// homed lets a home's owner activate it, check its password, and change it.
permit (
  principal,
  action in [
    Action::"org.freedesktop.home1.activate-home",
    Action::"org.freedesktop.home1.authenticate-home",
    Action::"org.freedesktop.home1.passwd-home"
  ],
  resource is Home
)
when { resource has owner && resource.owner == principal };

// machined lets whoever registered a machine log in, open a shell or a pty
// in it. (`.host` is owned by root.)
permit (
  principal,
  action in [
    Action::"org.freedesktop.machine1.login",
    Action::"org.freedesktop.machine1.shell",
    Action::"org.freedesktop.machine1.open-pty",
    Action::"org.freedesktop.machine1.host-login",
    Action::"org.freedesktop.machine1.host-shell",
    Action::"org.freedesktop.machine1.host-open-pty"
  ],
  resource is Machine
)
when { resource.owner == principal };

// ...and stop, kill or unregister it, but not bind-mount into it, copy
// files in or out, or open its root directory.
permit (
  principal,
  action == Action::"org.freedesktop.machine1.manage-machines",
  resource is Machine
)
when {
  resource.owner == principal &&
  ["unregister", "terminate", "kill"].contains(context.details.verb)
};

// resolved lets whoever registered a DNS-SD service unregister it.
permit (
  principal,
  action == Action::"org.freedesktop.resolve1.unregister-service",
  resource is DnssdService
)
when { resource.owner == principal };

// A user's own ask-password instance answers that user.
permit (
  principal,
  action == Action::"io.systemd.ask-password.ask",
  resource is User
)
when { resource == principal };

// systemd-creds lets users encrypt and decrypt their own user-scoped
// credentials, as long as the timestamp isn't backdated.
permit (
  principal,
  action in [
    Action::"io.systemd.credentials.encrypt",
    Action::"io.systemd.credentials.decrypt"
  ],
  resource is Credential
)
when {
  resource.scope == "user" &&
  resource has owner && resource.owner == principal &&
  context.details.timestamp_fresh == "1"
};
