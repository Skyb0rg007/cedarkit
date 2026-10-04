//! `cedarkit-agent`: asks the user to authenticate when a process in their
//! session needs to, for CedarKit (docs/design.md, section 9.6).
//!
//! Its dialog follows GNOME Shell's polkit agent
//! (`js/ui/components/polkitAgent.js`): one request at a time, one user to
//! authenticate as, and PAM's conversation shown as it happens. It talks to
//! `cedarkitd` over Varlink, as `org.cedarkit.Agent`.

mod agent;
mod dialog;

use std::cell::Cell;
use std::path::PathBuf;

use adw::prelude::*;
use clap::Parser;
use gtk::glib;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Where cedarkitd listens for agents.
    #[arg(long, default_value = cedarkit_agent_protocol::SOCKET)]
    socket: PathBuf,
}

fn main() -> glib::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    // One agent per session: a second instance just activates the first.
    let app = adw::Application::builder()
        .application_id("org.cedarkit.Agent")
        .build();
    let started = Cell::new(false);
    app.connect_activate(move |app| {
        if started.replace(true) {
            return;
        }
        // Keep running without any windows open.
        let hold = app.hold();
        let socket = args.socket.clone();
        glib::spawn_future_local(async move {
            let _hold = hold;
            agent::run(&socket).await;
        });
    });
    app.run_with_args::<&str>(&[])
}
