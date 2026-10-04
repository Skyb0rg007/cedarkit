use std::path::PathBuf;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The files couldn't be loaded. Each problem names the file or policy
    /// it's about.
    #[error("{}", .0.join("\n"))]
    Load(Vec<String>),

    #[error("invalid request: {0}")]
    Request(String),

    #[error("failed to look up user: {0}")]
    Lookup(#[from] nix::Error),
}
