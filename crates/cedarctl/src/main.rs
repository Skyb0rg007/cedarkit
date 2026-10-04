//! `cedarctl`: check and validate CedarKit policies from the command line.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use cedarkit_core::{
    AttrValue, Authentication, Authority, CheckRequest, Decision, Directory, Layout, Nss, Resource,
    Subject, User,
};
use cedarkit_logind::{Logind, ProcessInfo, Session};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Directory of vendor files, one directory per application.
    #[arg(long, global = true, default_value = "/usr/share/cedarkit")]
    vendor: PathBuf,

    /// Directory of the local admin's files.
    #[arg(long, global = true, default_value = "/etc/cedarkit")]
    admin: PathBuf,

    /// The generated subject schema.
    #[arg(
        long,
        global = true,
        default_value = "/var/lib/cedarkit/subject.cedarschema"
    )]
    subject_schema: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Evaluate an authorization request locally against the policies.
    Check(Check),

    /// Check that the files load, and warn about likely mistakes.
    Validate,

    /// Manage the generated subject schema.
    #[command(subcommand)]
    Schema(SchemaCommand),
}

#[derive(Subcommand)]
enum SchemaCommand {
    /// Write the subject schema for the installed fact providers, if every
    /// policy validates against it.
    Update {
        /// Print it rather than writing it.
        #[arg(long)]
        print: bool,
    },
}

#[derive(clap::Args)]
struct Check {
    /// Action id, e.g. `org.freedesktop.login1.reboot`.
    action: String,

    /// Resource acted on, in Cedar syntax, e.g. `systemd::Unit::"sshd.service"`.
    /// Defaults to the action's `@singleton`.
    #[arg(long)]
    resource: Option<String>,

    /// Resource attribute as `key=value`. Values `true`/`false`, integers
    /// and `Type::"id"` entity references are typed; anything else is a
    /// string.
    #[arg(long = "attr", value_parser = parse_pair)]
    attrs: Vec<(String, String)>,

    /// Entity the resource is a member of.
    #[arg(long = "parent")]
    parents: Vec<String>,

    /// User to check for, by name or uid (defaults to the current user).
    #[arg(long)]
    user: Option<String>,

    /// What logind knows about the subject: `auto` asks logind about this
    /// process, the others pretend. Defaults to `auto` for the current user,
    /// and `none` otherwise.
    #[arg(long, value_enum)]
    session: Option<SessionKind>,

    /// Treat this user, by name or uid, as having authenticated: remembered
    /// from earlier, or just now with `--fresh`.
    #[arg(long)]
    auth_user: Option<String>,

    /// The authentication was given just now.
    #[arg(long, requires = "auth_user", conflicts_with_all = ["auth_action", "auth_resource"])]
    fresh: bool,

    /// The action a remembered authentication was given for (defaults to
    /// this one).
    #[arg(long, requires = "auth_user")]
    auth_action: Option<String>,

    /// The resource a remembered authentication was given for (defaults to
    /// this one).
    #[arg(long, requires = "auth_user")]
    auth_resource: Option<String>,

    /// Request detail as `key=value`, converted to the type the action
    /// declares for it.
    #[arg(long = "detail", value_parser = parse_pair)]
    details: Vec<(String, String)>,

    /// Print polkit's result instead, e.g. `auth_admin_keep`.
    #[arg(long)]
    polkit: bool,

    /// Also print why: the policies that allowed or forbade it, or what went
    /// wrong.
    #[arg(long)]
    reasons: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SessionKind {
    Auto,
    /// logind knows nothing about the subject.
    None,
    /// In a remote session.
    Remote,
    /// In a local session, while none of the user's sessions are active.
    Inactive,
    /// In the active local session.
    Active,
}

fn parse_pair(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .ok_or_else(|| format!("expected key=value, got {s:?}"))
}

fn find_user(spec: &str) -> anyhow::Result<User> {
    let user = match spec.parse() {
        Ok(uid) => Nss.user(uid)?,
        Err(_) => Nss.user_by_name(spec)?,
    };
    user.with_context(|| format!("no such user {spec:?}"))
}

/// A pretend session, for the `--session` presets.
fn pretend(kind: SessionKind, uid: u32) -> Option<ProcessInfo> {
    let session = |seat: Option<&str>, active| Session {
        id: "c1".into(),
        uid,
        seat: seat.map(str::to_owned),
        remote: seat.is_none(),
        class: "user".into(),
        type_: "tty".into(),
        active,
    };
    Some(match kind {
        SessionKind::Auto | SessionKind::None => return None,
        SessionKind::Remote => ProcessInfo {
            session: Some(session(None, true)),
            ..ProcessInfo::default()
        },
        SessionKind::Inactive => ProcessInfo {
            session: Some(session(Some("seat0"), false)),
            display: None,
            user_active: false,
        },
        SessionKind::Active => ProcessInfo {
            session: Some(session(Some("seat0"), true)),
            display: None,
            user_active: true,
        },
    })
}

fn logind() -> anyhow::Result<(tokio::runtime::Runtime, Logind)> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let logind = rt
        .block_on(Logind::system())
        .context("connecting to logind")?;
    Ok((rt, logind))
}

fn check(authority: &Authority, args: Check) -> anyhow::Result<ExitCode> {
    let current = nix::unistd::Uid::current().as_raw();
    let user = match &args.user {
        Some(spec) => find_user(spec)?,
        None => Nss.user(current)?.unwrap_or_else(|| User::new(current)),
    };
    let session = args.session.unwrap_or(if args.user.is_none() {
        SessionKind::Auto
    } else {
        SessionKind::None
    });

    let mut resource = match &args.resource {
        Some(r) => Resource::parse(r)?,
        None => Resource::new(
            authority
                .singleton(&args.action)
                .with_context(|| format!("{} needs a --resource", args.action))?
                .clone(),
        ),
    };
    for (key, value) in &args.attrs {
        resource = resource.with_attr(key.clone(), value.parse::<AttrValue>()?);
    }
    for parent in &args.parents {
        resource = resource.with_parent(Resource::parse(parent)?.uid);
    }

    let pid = std::process::id();
    let mut subject = Subject::new(user);
    let needs_logind = session == SessionKind::Auto
        || (args.attrs.is_empty() && resource.uid.type_name().to_string() == "logind::Session");
    if needs_logind {
        let (rt, logind) = logind()?;
        if session == SessionKind::Auto {
            if subject.user.uid != current {
                bail!("--session auto only works for the current user");
            }
            let info = rt.block_on(logind.process(pid, current))?;
            subject = subject.with_facts(info.facts(pid));
        }
        rt.block_on(logind.fill_resource(&mut resource))?;
    }
    if let Some(info) = pretend(session, subject.user.uid) {
        subject = subject.with_facts(info.facts(pid));
    }

    let details: HashMap<String, String> = args.details.into_iter().collect();
    let mut request = CheckRequest {
        details: authority.parse_details(&args.action, &details)?,
        ..CheckRequest::new(subject, args.action, resource)
    };
    if let Some(spec) = &args.auth_user {
        let auth_user = find_user(spec)?;
        let auth = Authentication::fresh(auth_user.uid, &request);
        request.authentications.push(if args.fresh {
            auth
        } else {
            Authentication {
                action: args.auth_action.clone().unwrap_or(auth.action.clone()),
                resource: match &args.auth_resource {
                    Some(r) => Resource::parse(r)?.uid,
                    None => auth.resource.clone(),
                },
                ..auth.remembered()
            }
        });
    }

    let outcome = authority.check(&request);
    if args.polkit {
        println!(
            "{}",
            cedarkit_core::polkit::result(&outcome.decision, request.subject.user.uid)
        );
    } else {
        println!("{}", outcome.decision.as_str());
        if let Decision::Challenge(options) = &outcome.decision {
            for o in options {
                println!(
                    "  {} {} {}",
                    o.uid,
                    o.name.as_deref().unwrap_or("-"),
                    if o.keep { "keep" } else { "fresh" }
                );
            }
        }
    }
    if args.reasons {
        for reason in &outcome.reasons {
            eprintln!("{reason}");
        }
    }
    Ok(if outcome.decision == Decision::Deny {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    let layout = Layout {
        vendor: cli.vendor,
        admin: cli.admin,
        subject_schema: cli.subject_schema,
    };

    match cli.command {
        Command::Check(args) => {
            let loaded = Authority::load(&layout).context("loading policies")?;
            check(&loaded.authority, args)
        }

        Command::Validate => {
            let loaded = match Authority::load(&layout) {
                Ok(loaded) => loaded,
                Err(cedarkit_core::Error::Load(errors)) => {
                    for e in errors {
                        eprintln!("error: {e}");
                    }
                    return Ok(ExitCode::FAILURE);
                }
                Err(e) => return Err(e.into()),
            };
            for warning in loaded.warnings.iter().chain(&loaded.authority.lint()) {
                eprintln!("warning: {warning}");
            }
            println!("policies are valid");
            Ok(ExitCode::SUCCESS)
        }

        Command::Schema(SchemaCommand::Update { print }) => {
            let sources = cedarkit_core::read_sources(&layout)?;
            let schema = cedarkit_core::subject_schema(&sources)?;
            let label = layout.subject_schema.display().to_string();
            if let Err(e) = Authority::from_sources(&sources, &label, &schema) {
                eprintln!("{e}");
                eprintln!("not updating {label}: the policies don't load with the new schema");
                return Ok(ExitCode::FAILURE);
            }
            if print {
                print!("{schema}");
                return Ok(ExitCode::SUCCESS);
            }
            if let Some(dir) = layout.subject_schema.parent() {
                fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            }
            let tmp = layout.subject_schema.with_extension("cedarschema.new");
            fs::write(&tmp, &schema).with_context(|| format!("writing {}", tmp.display()))?;
            fs::rename(&tmp, &layout.subject_schema).with_context(|| format!("writing {label}"))?;
            println!("updated {label}");
            Ok(ExitCode::SUCCESS)
        }
    }
}
