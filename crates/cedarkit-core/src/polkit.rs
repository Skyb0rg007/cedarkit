//! polkit's result labels, for the polkit-compatible front end
//! (docs/design.md, section 11). They aren't part of the native result.

use crate::Decision;

/// The polkit result for a decision about `subject`'s request: `yes`, `no`,
/// or `auth_self` if the only option is the subject, otherwise `auth_admin`,
/// with `_keep` if a remembered authentication would be accepted.
pub fn result(decision: &Decision, subject: u32) -> &'static str {
    match decision {
        Decision::Allow => "yes",
        Decision::Deny => "no",
        Decision::Challenge(options) => {
            let own = matches!(options.as_slice(), [only] if only.uid == subject);
            let keep = options.iter().all(|o| o.keep);
            match (own, keep) {
                (true, true) => "auth_self_keep",
                (true, false) => "auth_self",
                (false, true) => "auth_admin_keep",
                (false, false) => "auth_admin",
            }
        }
    }
}
