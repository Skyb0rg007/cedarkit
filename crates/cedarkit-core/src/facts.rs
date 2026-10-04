use crate::{Resource, User};

/// What a fact provider knows about the calling process (docs/design.md,
/// section 6.5). Policies see it as `context.subject.<provider>`.
#[derive(Debug, Clone, PartialEq)]
pub struct Facts {
    /// The provider's namespace, e.g. `logind`.
    pub provider: String,
    /// The process, as the provider's `@subject` entity type, e.g.
    /// `logind::Process::"1234"`.
    pub process: Resource,
    /// The entities the facts refer to, such as sessions and seats. They must
    /// be in the provider's namespace.
    pub related: Vec<Resource>,
}

/// The process a check is made for: its user, and what fact providers know
/// about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Subject {
    pub user: User,
    pub facts: Vec<Facts>,
}

impl Subject {
    /// A subject no fact provider knows anything about.
    pub fn new(user: User) -> Self {
        Self {
            user,
            facts: Vec::new(),
        }
    }

    pub fn with_facts(mut self, facts: Facts) -> Self {
        self.facts.push(facts);
        self
    }
}
