//! `cedarctl`: check and validate CedarKit policies from the command line.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context as _;
use cedarkit_core::{
    AttrValue, Authentication, Authority, CheckRequest, Decision, Identity, Resource, Subject,
};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Directory to load `*.cedar` policy files from.
    #[arg(long, global = true, default_value = cedarkit_core::DEFAULT_POLICY_DIR)]
    policies: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Evaluate an authorization request locally against the policies.
    Check {
        /// Action id, e.g. `org.freedesktop.login1.reboot`.
        action: String,

        /// Resource acted on, in Cedar syntax, e.g. `Unit::"sshd.service"`.
        #[arg(long)]
        resource: String,

        /// Resource attribute as `key=value`. Values `true`/`false`, integers
        /// and `Type::"id"` entity references are typed; anything else is a
        /// string.
        #[arg(long = "attr", value_parser = parse_detail)]
        attrs: Vec<(String, String)>,

        /// Entity the resource is a member of, e.g. `Seat::"seat0"`.
        #[arg(long = "parent")]
        parents: Vec<String>,

        /// User to check for (defaults to the current user).
        #[arg(long)]
        user: Option<String>,

        /// Treat the subject's session as local.
        #[arg(long)]
        local: bool,

        /// Treat the subject's session as active.
        #[arg(long)]
        active: bool,

        /// Treat the subject as having authenticated as themselves or as an
        /// administrator.
        #[arg(long)]
        auth: Option<AuthAs>,

        /// Treat that authentication as just entered, rather than
        /// remembered from earlier.
        #[arg(long, requires = "auth")]
        fresh: bool,

        /// Extra `key=value` details passed in the request context.
        #[arg(long = "detail", value_parser = parse_detail)]
        details: Vec<(String, String)>,
    },

    /// Validate the policies against a Cedar schema.
    Validate {
        /// Schema file (defaults to every `*.cedarschema` under the policy directory).
        #[arg(long)]
        schema: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum AuthAs {
    #[value(name = "self")]
    Self_,
    Admin,
}

fn parse_detail(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .ok_or_else(|| format!("expected key=value, got {s:?}"))
}

fn main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();

    match cli.command {
        Command::Check {
            action,
            resource,
            attrs,
            parents,
            user,
            local,
            active,
            auth,
            fresh,
            details,
        } => {
            let mut subject = match user {
                Some(name) => Subject::from_name(&name)?,
                None => Subject::current()?,
            };
            subject.local = local;
            subject.active = active;

            let mut resource = Resource::parse(&resource)?;
            for (key, value) in attrs {
                resource = resource.with_attr(key, value.parse::<AttrValue>()?);
            }
            for parent in parents {
                resource = resource.with_parent(Resource::parse(&parent)?.uid);
            }

            let request = CheckRequest {
                subject,
                action_id: action,
                resource,
                details: details.into_iter().collect::<HashMap<_, _>>(),
                auth: Authentication {
                    identity: auth.map(|a| match a {
                        AuthAs::Self_ => Identity::Self_,
                        AuthAs::Admin => Identity::Admin,
                    }),
                    fresh,
                },
            };
            let authority = Authority::from_dir(&cli.policies)
                .with_context(|| format!("loading policies from {}", cli.policies.display()))?;
            let decision = authority.check(&request)?;
            println!("{}", decision.polkit_result());
            Ok(if decision == Decision::Deny {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }

        Command::Validate { schema } => {
            let src = match schema {
                Some(path) => fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?,
                None => cedarkit_core::read_tree(&cli.policies, "cedarschema")?,
            };
            let policies = cedarkit_core::read_tree(&cli.policies, "cedar")?;
            let validation = cedarkit_core::validate(&policies, &src)?;
            for warning in &validation.warnings {
                eprintln!("warning: {warning}");
            }
            for err in &validation.errors {
                eprintln!("error: {err}");
            }
            if validation.errors.is_empty() {
                println!("policies are valid");
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::FAILURE)
            }
        }
    }
}
