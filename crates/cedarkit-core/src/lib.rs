//! Core authorization engine for CedarKit.
//!
//! CedarKit answers the same question polkit does — "may this subject perform
//! this action?" — but the rules are written in the Cedar policy language
//! instead of JavaScript.
//!
//! The Cedar entity model is:
//!
//! - principal: `User::"<name>"`, a member of each of its `Group::"<name>"`s
//! - action:    `Action::"<polkit action id>"`, e.g. `Action::"org.freedesktop.login1.reboot"`
//! - resource:  the object acted on, e.g. `Unit::"sshd.service"`
//! - context:   `{ local, active, details }` describing the subject's session
//!   and any mechanism-supplied details

mod authority;
mod error;
mod resource;
mod subject;

pub use authority::{
    Authentication, Authority, Challenge, CheckRequest, Decision, Identity, Validation, read_tree,
    validate,
};
pub use error::{Error, Result};
pub use resource::{AttrValue, Resource, entity_uid};
pub use subject::Subject;

/// Default directory policies are loaded from.
pub const DEFAULT_POLICY_DIR: &str = "/etc/cedarkit/policies";
