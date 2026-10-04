//! The `org.cedarkit.Agent` Varlink interface, for authentication agents.
//!
//! Each connection is served in its own task, since a request waits for
//! users to type, and a registered agent's connection streams requests for
//! as long as it's open.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use cedarkit_agent_protocol::{AgentError, DESCRIPTION, Event, INTERFACE, Method, Step};
use cedarkit_logind::Logind;
use serde::Serialize;
use zlink::{Listener as _, Reply};

use crate::agents::{Agents, Turn};

type Connection = zlink::tokio::unix::Connection;

/// Listens for agents at `path`.
pub async fn serve(
    path: &Path,
    agents: Arc<Agents>,
    logind: Option<Arc<Logind>>,
) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(e).with_context(|| format!("removing {}", path.display()));
        }
        _ => {}
    }
    let mut listener = zlink::tokio::unix::bind(path)
        .with_context(|| format!("listening on {}", path.display()))?;
    // Anyone may connect; what they may do depends on who they are.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    tracing::info!(path = %path.display(), "listening for authentication agents");

    while let Some(conn) = listener.accept().await? {
        let agents = agents.clone();
        let logind = logind.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(conn, &agents, logind.as_deref()).await {
                tracing::debug!("agent connection ended: {e}");
            }
        });
    }
    Ok(())
}

async fn send<T: Serialize + std::fmt::Debug>(
    conn: &mut Connection,
    reply: T,
    continues: bool,
) -> zlink::Result<()> {
    let reply = Reply::new(Some(reply)).set_continues(Some(continues));
    conn.send_reply(&reply, vec![]).await
}

async fn send_error(conn: &mut Connection, error: AgentError) -> zlink::Result<()> {
    conn.send_error(&error, vec![]).await
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Info {
    vendor: &'static str,
    product: &'static str,
    version: &'static str,
    url: &'static str,
    interfaces: [&'static str; 2],
}

#[derive(Debug, Serialize)]
#[serde(tag = "error", content = "parameters")]
enum ServiceError {
    #[serde(rename = "org.varlink.service.InterfaceNotFound")]
    InterfaceNotFound { interface: String },
}

async fn handle(
    mut conn: Connection,
    agents: &Agents,
    logind: Option<&Logind>,
) -> anyhow::Result<()> {
    let creds = conn.peer_credentials().await?;
    let uid = creds.unix_user_id().as_raw();
    let pid = creds.process_id().as_raw_nonzero().get() as u32;

    loop {
        let (call, _fds) = conn.receive_call::<Method>().await?;
        let more = call.more();
        let method = call.method().clone();
        match method {
            Method::Register if !more => send_error(&mut conn, AgentError::ExpectedMore).await?,
            Method::Register => {
                let session = match agent_session(logind, pid, uid).await {
                    Ok(session) => session,
                    Err(e) => {
                        send_error(&mut conn, e).await?;
                        continue;
                    }
                };
                match agents.register(&session, uid) {
                    Ok(registration) => return run_agent(conn, agents, registration).await,
                    Err(e) => send_error(&mut conn, e).await?,
                }
            }

            Method::Authenticate { .. } | Method::Respond { .. } if !more => {
                send_error(&mut conn, AgentError::ExpectedMore).await?
            }
            Method::Authenticate { cookie, uid: user } => {
                match agents.authenticate(uid, &cookie, user).await {
                    Ok(turn) => converse(&mut conn, agents, &cookie, turn).await?,
                    Err(e) => send_error(&mut conn, e).await?,
                }
            }
            Method::Respond { cookie, response } => {
                let answered = match agents.attempt(uid, &cookie) {
                    Ok(turn) => {
                        let answer = turn.conversation.lock().await.answer(&response).await;
                        answer.map(|()| turn)
                    }
                    Err(e) => Err(e),
                };
                match answered {
                    Ok(turn) => converse(&mut conn, agents, &cookie, turn).await?,
                    Err(e) => send_error(&mut conn, e).await?,
                }
            }

            Method::Dismiss { cookie } => match agents.dismiss(uid, &cookie) {
                // A reply without parameters, for `-> ()`.
                Ok(()) => conn.send_reply(&Reply::<()>::new(None), vec![]).await?,
                Err(e) => send_error(&mut conn, e).await?,
            },

            Method::GetInfo => {
                let info = Info {
                    vendor: "CedarKit",
                    product: "cedarkitd",
                    version: env!("CARGO_PKG_VERSION"),
                    url: "https://github.com/Skyb0rg007/cedarkit",
                    interfaces: [INTERFACE, "org.varlink.service"],
                };
                send(&mut conn, info, false).await?;
            }
            Method::GetInterfaceDescription { interface } if interface == INTERFACE => {
                #[derive(Debug, Serialize)]
                struct Description {
                    description: &'static str,
                }
                send(
                    &mut conn,
                    Description {
                        description: DESCRIPTION,
                    },
                    false,
                )
                .await?;
            }
            Method::GetInterfaceDescription { interface } => {
                conn.send_error(&ServiceError::InterfaceNotFound { interface }, vec![])
                    .await?;
            }
        }
    }
}

/// The session an agent serves: its own, or failing that its user's
/// graphical session, as for subjects.
async fn agent_session(logind: Option<&Logind>, pid: u32, uid: u32) -> Result<String, AgentError> {
    let logind = logind.ok_or(AgentError::NoSession)?;
    let info = logind
        .process(pid, uid)
        .await
        .map_err(|e| AgentError::Failed {
            message: format!("can't ask logind: {e}"),
        })?;
    let session = info.session.or(info.display).ok_or(AgentError::NoSession)?;
    // An agent may only serve its own user's session.
    if session.uid != uid && uid != 0 {
        return Err(AgentError::NoSession);
    }
    Ok(session.id)
}

/// Streams requests to a registered agent until it disconnects.
async fn run_agent(
    mut conn: Connection,
    agents: &Agents,
    mut registration: crate::agents::Registration,
) -> anyhow::Result<()> {
    let result = async {
        send(&mut conn, Event::default(), true).await?;
        let (mut read, mut write) = conn.split();
        loop {
            tokio::select! {
                event = registration.events.recv() => {
                    let Some(event) = event else { break };
                    let reply = Reply::new(Some(event)).set_continues(Some(true));
                    write.send_reply(&reply, vec![]).await?;
                }
                // Agents don't call anything on this connection, so this
                // only ends when the agent disconnects.
                _ = read.receive_call::<Method>() => break,
            }
        }
        anyhow::Ok(())
    }
    .await;
    agents.unregister(registration.id);
    result
}

/// Relays PAM's messages to the agent, up to the next prompt or the result.
async fn converse(
    conn: &mut Connection,
    agents: &Agents,
    cookie: &str,
    mut turn: Turn,
) -> anyhow::Result<()> {
    loop {
        let step = {
            let mut conversation = turn.conversation.lock().await;
            tokio::select! {
                step = conversation.next_step() => step,
                // The request ended, or another attempt replaced this one.
                _ = turn.alive.changed() => {
                    send_error(conn, AgentError::NoSuchRequest).await?;
                    return Ok(());
                }
            }
        };
        let last = step.is_last();
        if let Some(success) = step.success {
            if success {
                tracing::info!(uid = turn.uid, "authenticated for an agent's request");
            } else {
                tracing::info!(
                    uid = turn.uid,
                    "failed to authenticate for an agent's request"
                );
            }
            agents.finish(cookie, turn.uid, success);
        }
        send::<Step>(conn, step, !last).await?;
        if last {
            return Ok(());
        }
    }
}
