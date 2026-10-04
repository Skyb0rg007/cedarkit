//! `cedarkit-cli-agent`: a CedarKit authentication agent driven from the
//! command line, for testing.
//!
//! It registers as the agent for its session, and handles each request by
//! authenticating with answers given in advance (`--answer`, used in order
//! for each prompt) or read from stdin (`--stdin`, one line per prompt). It
//! reports everything as JSON lines on stdout:
//!
//! ```text
//! {"event":"registered"}
//! {"event":"request","cookie":"…","action":"…","message":"…","identities":[…]}
//! {"event":"authenticating","cookie":"…","uid":1000}
//! {"event":"info","text":"…"}  {"event":"error","text":"…"}
//! {"event":"prompt","text":"Password: ","echo":false}
//! {"event":"result","cookie":"…","success":true}
//! {"event":"dismissed","cookie":"…"}
//! {"event":"cancelled","cookie":"…"}
//! ```
//!
//! After a failed attempt it tries again while it has answers left, and
//! otherwise dismisses the request.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use cedarkit_agent_protocol::{AgentProxy, Identity, Request, Step};
use clap::Parser;
use futures_util::{StreamExt, pin_mut};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader, Lines, Stdin};
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Where cedarkitd listens for agents.
    #[arg(long, default_value = cedarkit_agent_protocol::SOCKET)]
    socket: PathBuf,

    /// An answer to a prompt, used in order. May be repeated.
    #[arg(long = "answer")]
    answers: Vec<String>,

    /// Read the answer to each prompt from a line of stdin.
    #[arg(long, conflicts_with = "answers")]
    stdin: bool,

    /// Authenticate as this user, by name or uid, rather than as GNOME's
    /// agent chooses (yourself if listed, otherwise root, otherwise the
    /// first listed).
    #[arg(long = "as")]
    user: Option<String>,

    /// Dismiss every request, as a user closing the dialog.
    #[arg(long)]
    dismiss: bool,

    /// Exit after handling this many requests.
    #[arg(long)]
    requests: Option<usize>,
}

fn emit(value: serde_json::Value) {
    println!("{value}");
}

/// Where answers come from.
enum Answers {
    Given(VecDeque<String>),
    Stdin(Lines<BufReader<Stdin>>),
}

impl Answers {
    async fn next(&mut self) -> Option<String> {
        match self {
            Self::Given(answers) => answers.pop_front(),
            Self::Stdin(lines) => lines.next_line().await.ok().flatten(),
        }
    }

    /// Whether another attempt could be answered.
    fn more(&self) -> bool {
        match self {
            Self::Given(answers) => !answers.is_empty(),
            Self::Stdin(_) => true,
        }
    }
}

/// The identity to authenticate as.
fn choose<'a>(identities: &'a [Identity], user: Option<&str>) -> Option<&'a Identity> {
    if let Some(user) = user {
        return identities
            .iter()
            .find(|i| i.name == user || i.uid.to_string() == user);
    }
    let me = nix::unistd::getuid().as_raw();
    identities
        .iter()
        .find(|i| i.uid == me)
        .or_else(|| identities.iter().find(|i| i.uid == 0))
        .or(identities.first())
}

/// How handling a request ended.
enum End {
    Done,
    Cancelled,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut answers = if args.stdin {
        Answers::Stdin(BufReader::new(tokio::io::stdin()).lines())
    } else {
        Answers::Given(args.answers.iter().cloned().collect())
    };

    let mut conn = zlink::tokio::unix::connect(&args.socket)
        .await
        .with_context(|| format!("connecting to {}", args.socket.display()))?;
    let events = conn.register().await?;
    pin_mut!(events);
    match events.next().await {
        Some(Ok(Ok(_))) => emit(json!({"event": "registered"})),
        Some(Ok(Err(e))) => bail!("registering: {e}"),
        Some(Err(e)) => bail!("registering: {e}"),
        None => bail!("cedarkitd closed the connection"),
    }

    // Requests are handled one at a time, while cancellations are watched.
    let (requests_tx, mut requests) = mpsc::unbounded_channel::<Request>();
    let (cancels_tx, mut cancels) = mpsc::unbounded_channel::<String>();
    let reader = async move {
        while let Some(event) = events.next().await {
            let event = event??;
            if let Some(request) = event.request {
                requests_tx.send(request)?;
            }
            if let Some(cookie) = event.cancelled {
                cancels_tx.send(cookie)?;
            }
        }
        anyhow::Ok(())
    };
    let handler = async {
        let mut handled = 0;
        while let Some(request) = requests.recv().await {
            emit(json!({
                "event": "request",
                "cookie": request.cookie,
                "action": request.action,
                "message": request.message,
                "identities": request.identities.iter()
                    .map(|i| json!({"uid": i.uid, "name": i.name}))
                    .collect::<Vec<_>>(),
            }));
            match handle(&args, &request, &mut answers, &mut cancels).await? {
                End::Done => {}
                End::Cancelled => emit(json!({"event": "cancelled", "cookie": request.cookie})),
            }
            handled += 1;
            if args.requests.is_some_and(|n| handled >= n) {
                return anyhow::Ok(());
            }
        }
        Ok(())
    };
    tokio::select! {
        result = reader => result.context("cedarkitd closed the connection"),
        result = handler => result,
    }
}

/// Handles a request: dismisses it, or authenticates until it succeeds or
/// the answers run out.
async fn handle(
    args: &Args,
    request: &Request,
    answers: &mut Answers,
    cancels: &mut mpsc::UnboundedReceiver<String>,
) -> anyhow::Result<End> {
    let cookie = &request.cookie;
    let identity = choose(&request.identities, args.user.as_deref());
    let (Some(identity), false) = (identity, args.dismiss) else {
        dismiss(&args.socket, cookie).await?;
        return Ok(End::Done);
    };

    let conversation = async {
        let mut conn = zlink::tokio::unix::connect(&args.socket).await?;
        loop {
            emit(json!({"event": "authenticating", "cookie": cookie, "uid": identity.uid}));
            let mut answer: Option<String> = None;
            let success = loop {
                let last = {
                    let steps = match &answer {
                        None => conn.authenticate(cookie, identity.uid).await?.boxed_local(),
                        Some(a) => conn.respond(cookie, a).await?.boxed_local(),
                    };
                    pin_mut!(steps);
                    let mut last = None;
                    while let Some(step) = steps.next().await {
                        let step: Step = step??;
                        report(&step);
                        if step.is_last() {
                            last = Some(step);
                            break;
                        }
                    }
                    last.context("cedarkitd ended the conversation")?
                };
                match last.success {
                    Some(success) => break success,
                    None => match answers.next().await {
                        Some(a) => answer = Some(a),
                        None => return anyhow::Ok(false),
                    },
                }
            };
            emit(json!({"event": "result", "cookie": cookie, "success": success}));
            if success || !answers.more() {
                return Ok(success);
            }
        }
    };

    let cancelled = async {
        while let Some(c) = cancels.recv().await {
            if c == *cookie {
                return;
            }
        }
        std::future::pending::<()>().await;
    };
    tokio::select! {
        success = conversation => {
            if !success? {
                dismiss(&args.socket, cookie).await?;
            }
            Ok(End::Done)
        }
        () = cancelled => Ok(End::Cancelled),
    }
}

fn report(step: &Step) {
    if let Some(text) = &step.info {
        emit(json!({"event": "info", "text": text}));
    }
    if let Some(text) = &step.error {
        emit(json!({"event": "error", "text": text}));
    }
    if let Some(prompt) = &step.prompt {
        emit(json!({"event": "prompt", "text": prompt.text, "echo": prompt.echo}));
    }
}

async fn dismiss(socket: &Path, cookie: &str) -> anyhow::Result<()> {
    let mut conn = zlink::tokio::unix::connect(socket).await?;
    conn.dismiss(cookie).await??;
    emit(json!({"event": "dismissed", "cookie": cookie}));
    Ok(())
}
