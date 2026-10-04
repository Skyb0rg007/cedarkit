use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Where CedarKit's files are (docs/design.md, section 8.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// Vendor files, one directory per application: `/usr/share/cedarkit`.
    pub vendor: PathBuf,
    /// The local admin's files: `/etc/cedarkit`. `<app>/` replaces vendor
    /// files with the same relative path, and `local/` adds more.
    pub admin: PathBuf,
    /// The generated subject schema: `/var/lib/cedarkit/subject.cedarschema`.
    pub subject_schema: PathBuf,
}

impl Layout {
    pub fn system() -> Self {
        Self {
            vendor: "/usr/share/cedarkit".into(),
            admin: "/etc/cedarkit".into(),
            subject_schema: "/var/lib/cedarkit/subject.cedarschema".into(),
        }
    }
}

impl Default for Layout {
    fn default() -> Self {
        Self::system()
    }
}

/// What a file holds, from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `*.cedarschema`
    Schema,
    /// `*.cedar`
    Policies,
    /// `*.entities.json`
    Entities,
}

impl Kind {
    fn of(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?;
        if name.ends_with(".cedarschema") {
            Some(Self::Schema)
        } else if name.ends_with(".cedar") {
            Some(Self::Policies)
        } else if name.ends_with(".entities.json") {
            Some(Self::Entities)
        } else {
            None
        }
    }
}

/// Who a file comes from, which decides what it may contain (section 8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Shipped by an application, confined to its namespace.
    Vendor(String),
    /// The local admin's, unrestricted.
    Admin,
}

/// A schema, policy or entity data file.
#[derive(Debug, Clone)]
pub struct Source {
    pub path: PathBuf,
    pub kind: Kind,
    pub origin: Origin,
    pub text: String,
}

impl Source {
    /// A file with the given contents, of the kind its name says.
    pub fn new(path: impl Into<PathBuf>, origin: Origin, text: impl Into<String>) -> Result<Self> {
        let path = path.into();
        let kind = Kind::of(&path).ok_or_else(|| {
            Error::Load(vec![format!("{}: unknown kind of file", path.display())])
        })?;
        Ok(Self {
            path,
            kind,
            origin,
            text: text.into(),
        })
    }
}

/// The application named by the first component of `rel`.
fn app_of(rel: &Path) -> Option<String> {
    let mut components = rel.components();
    let app = components.next()?.as_os_str().to_str()?.to_owned();
    // A file directly in the root isn't in any application's directory.
    components.next().map(|_| app)
}

/// Reads the vendor and admin files, in lexical order of their paths relative
/// to their root. An admin file replaces the vendor file with the same
/// relative path. A missing root counts as empty.
pub fn read_sources(layout: &Layout) -> Result<Vec<Source>> {
    let mut files = BTreeMap::new();
    for (root, vendor) in [(&layout.vendor, true), (&layout.admin, false)] {
        for path in walk(root)? {
            let rel = path
                .strip_prefix(root)
                .expect("walked paths are under the root");
            let Some(kind) = Kind::of(&path) else {
                continue;
            };
            let origin = match (vendor, app_of(rel)) {
                (false, _) => Origin::Admin,
                (true, Some(app)) => Origin::Vendor(app),
                (true, None) => {
                    return Err(Error::Load(vec![format!(
                        "{}: not in an application's directory",
                        path.display()
                    )]));
                }
            };
            files.insert(rel.to_owned(), (path, kind, origin));
        }
    }

    files
        .into_values()
        .map(|(path, kind, origin)| {
            tracing::debug!(path = %path.display(), "loading file");
            let text = fs::read_to_string(&path).map_err(|source| Error::Io {
                path: path.clone(),
                source,
            })?;
            Ok(Source {
                path,
                kind,
                origin,
                text,
            })
        })
        .collect()
}

/// Every file under `dir`, recursively.
fn walk(dir: &Path) -> Result<Vec<PathBuf>> {
    let io_err = |source| Error::Io {
        path: dir.to_owned(),
        source,
    };
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err(e)),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry.map_err(io_err)?.path();
        if path.is_dir() {
            paths.extend(walk(&path)?);
        } else {
            paths.push(path);
        }
    }
    Ok(paths)
}

/// Reads the subject schema.
pub fn read_subject_schema(layout: &Layout) -> Result<String> {
    fs::read_to_string(&layout.subject_schema).map_err(|source| match source.kind() {
        std::io::ErrorKind::NotFound => Error::Load(vec![format!(
            "{}: missing; run `cedarctl schema update`",
            layout.subject_schema.display()
        )]),
        _ => Error::Io {
            path: layout.subject_schema.clone(),
            source,
        },
    })
}
