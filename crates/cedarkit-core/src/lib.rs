//! Core authorization engine for CedarKit.
//!
//! CedarKit answers the question polkit does, "may this process perform this
//! action?", with policies written in Cedar. `docs/design.md` defines the
//! model:
//!
//! - principal: the subject's `User::"<uid>"`, in its `Group::"<name>"`s and
//!   `Role::"<name>"`s
//! - action: `Action::"<action id>"`, e.g. `Action::"org.freedesktop.login1.reboot"`
//! - resource: the object acted on, e.g. `systemd::Unit::"sshd.service"`
//! - context: `{ subject, auth, details? }`: what fact providers know about the
//!   calling process, how it has authenticated, and request details

mod authority;
mod entities;
mod error;
mod facts;
mod identity;
mod policies;
pub mod polkit;
mod resource;
mod schema;
mod sources;
mod store;

pub use authority::{
    Authentication, Authority, ChallengeOption, CheckRequest, Decision, Loaded, Outcome,
    subject_schema,
};
pub use cedar_policy::EntityUid;
pub use error::{Error, Result};
pub use facts::{Facts, Subject};
pub use identity::{Directory, Group, Nss, User};
pub use resource::{AttrValue, Resource, entity_uid};
pub use sources::{Kind, Layout, Origin, Source, read_sources, read_subject_schema};
pub use store::{AuthStore, DEFAULT_LIFETIME, Holder, ProcessId, Remembered};

#[cfg(test)]
mod tests;
