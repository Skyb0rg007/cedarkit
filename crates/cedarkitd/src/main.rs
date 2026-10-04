//! `cedarkitd`: the CedarKit authority daemon.
//!
//! Exposes `org.cedarkit.Authority1` on the system bus (or the session bus,
//! for development) and answers authorization checks using Cedar policies
//! (docs/design.md, section 9.5). Authentication agents connect over
//! Varlink, as `org.cedarkit.Agent` (section 9.6). With `--polkit`, it also
//! stands in for polkitd, as `org.freedesktop.PolicyKit1` (section 11).

mod agents;
mod authority1;
mod cancel;
mod polkit;
mod siblings;
mod state;
mod varlink;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use cedarkit_core::{AuthStore, Authority, DEFAULT_LIFETIME, Layout};
use cedarkit_logind::Logind;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::state::State;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Directory of vendor files, one directory per application.
    #[arg(long, default_value = "/usr/share/cedarkit")]
    vendor: PathBuf,

    /// Directory of the local admin's files.
    #[arg(long, default_value = "/etc/cedarkit")]
    admin: PathBuf,

    /// The generated subject schema.
    #[arg(long, default_value = "/var/lib/cedarkit/subject.cedarschema")]
    subject_schema: PathBuf,

    /// Serve on the session bus instead of the system bus.
    #[arg(long)]
    session: bool,

    /// Also serve polkit's interface, `org.freedesktop.PolicyKit1`, in place
    /// of polkitd.
    #[arg(long)]
    polkit: bool,

    /// How long to remember authentications, in seconds. By default,
    /// polkit's `ExpirationSeconds` from `polkitd.conf`, or 300.
    #[arg(long)]
    remember_seconds: Option<u64>,

    /// Where to listen for authentication agents.
    #[arg(long, default_value = cedarkit_agent_protocol::SOCKET)]
    agent_socket: PathBuf,

    /// The PAM service users authenticate with.
    #[arg(long, default_value = "cedarkit")]
    pam_service: String,

    /// Where to find the PAM service's configuration, rather than
    /// `/etc/pam.d`. For testing.
    #[arg(long)]
    pam_confdir: Option<PathBuf>,

    /// `cedarkit-pam-helper`, by default next to this program.
    #[arg(long)]
    pam_helper: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let layout = Layout {
        vendor: args.vendor,
        admin: args.admin,
        subject_schema: args.subject_schema,
    };

    let loaded = Authority::load(&layout).context("loading policies")?;
    for warning in &loaded.warnings {
        tracing::warn!("{warning}");
    }
    let logind = match Logind::system().await {
        Ok(logind) => Some(Arc::new(logind)),
        Err(e) => {
            tracing::warn!("can't connect to logind, so it reports no facts: {e}");
            None
        }
    };
    let pam_helper = match args.pam_helper {
        Some(path) => path,
        None => std::env::current_exe()
            .context("finding cedarkit-pam-helper")?
            .with_file_name("cedarkit-pam-helper"),
    };
    let agents = Arc::new(agents::Agents::new(agents::PamConfig {
        helper: pam_helper,
        service: args.pam_service,
        confdir: args.pam_confdir,
    }));
    let lifetime = Duration::from_secs(args.remember_seconds.unwrap_or_else(polkit_expiration));
    let state = Arc::new(State {
        authority: loaded.authority,
        logind: logind.clone(),
        store: Mutex::new(AuthStore::new(lifetime)),
        agents: agents.clone(),
        cancellations: Arc::default(),
        own_uid: nix::unistd::geteuid().as_raw(),
        changed: tokio::sync::Notify::new(),
    });

    let builder = if args.session {
        zbus::connection::Builder::session()?
    } else {
        zbus::connection::Builder::system()?
    };
    let mut builder = builder.name(authority1::BUS_NAME)?.serve_at(
        authority1::PATH,
        authority1::AuthorityService {
            state: state.clone(),
        },
    )?;
    if args.polkit {
        builder = builder.name(polkit::BUS_NAME)?.serve_at(
            polkit::PATH,
            polkit::PolkitAuthority {
                state: state.clone(),
            },
        )?;
    }
    let conn = builder.build().await.context("connecting to D-Bus")?;

    if args.polkit {
        // polkit's Changed signal, when remembered authentications change.
        let (conn, state) = (conn.clone(), state.clone());
        tokio::spawn(async move {
            loop {
                state.changed.notified().await;
                let iface = conn
                    .object_server()
                    .interface::<_, polkit::PolkitAuthority>(polkit::PATH)
                    .await;
                if let Ok(iface) = iface {
                    let _ = polkit::PolkitAuthority::changed(iface.signal_emitter()).await;
                }
            }
        });
        tracing::info!(name = polkit::BUS_NAME, "serving polkit's interface");
    }

    tracing::info!(
        name = authority1::BUS_NAME,
        path = authority1::PATH,
        "cedarkitd ready"
    );
    tokio::select! {
        result = varlink::serve(&args.agent_socket, agents, logind) => result?,
        result = tokio::signal::ctrl_c() => result?,
    }
    tracing::info!("shutting down");
    Ok(())
}

/// polkit's `ExpirationSeconds`, from the first `polkitd.conf` that sets
/// it, as polkitd reads it; or the default of 300.
fn polkit_expiration() -> u64 {
    let read = |path: &str| -> Option<u64> {
        let text = std::fs::read_to_string(path).ok()?;
        let mut in_section = false;
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                in_section = line == "[Polkitd]";
            } else if in_section && let Some(value) = line.strip_prefix("ExpirationSeconds=") {
                return value.trim().parse().ok();
            }
        }
        None
    };
    [
        "/etc/polkit-1/polkitd.conf",
        "/run/polkit-1/polkitd.conf",
        "/usr/share/polkit-1/polkitd.conf",
    ]
    .into_iter()
    .find_map(read)
    .unwrap_or(DEFAULT_LIFETIME.as_secs())
}
