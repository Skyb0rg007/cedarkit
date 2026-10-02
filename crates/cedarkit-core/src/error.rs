use std::path::PathBuf;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse policies: {0}")]
    Policy(#[from] Box<cedar_policy::ParseErrors>),

    #[error("policies don't validate against the schema:\n{0}")]
    Invalid(String),

    #[error("invalid schema: {0}")]
    Schema(String),

    #[error("failed to build authorization request: {0}")]
    Request(String),

    #[error("unknown uid {0}")]
    UnknownUid(u32),

    #[error("unknown user {0:?}")]
    UnknownUser(String),

    #[error("failed to look up user: {0}")]
    Lookup(#[from] nix::Error),
}
