//! Registering with cedarkitd, and handling its requests one at a time, as
//! GNOME Shell does.

use std::cell::RefCell;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use anyhow::Context as _;
use cedarkit_agent_protocol::{AgentProxy, Request};
use futures_util::{StreamExt, pin_mut};
use gtk::glib;

/// How long to wait before registering again, after losing cedarkitd.
const RETRY: Duration = Duration::from_secs(5);

/// The request being handled, and those cancelled before their turn.
#[derive(Default)]
struct State {
    current: Option<(String, async_channel::Sender<()>)>,
    cancelled: HashSet<String>,
    /// No longer registered, so no request may be handled.
    stopped: bool,
}

impl State {
    fn cancel(&mut self, cookie: &str) {
        match &self.current {
            Some((current, tx)) if current == cookie => {
                let _ = tx.try_send(());
            }
            _ => {
                self.cancelled.insert(cookie.to_owned());
            }
        }
    }
}

/// Serves cedarkitd for as long as the agent runs, registering again
/// whenever the connection is lost.
pub async fn run(socket: &Path) {
    loop {
        match serve(socket).await {
            Ok(()) => tracing::info!("cedarkitd closed the connection"),
            Err(e) => tracing::warn!("can't serve cedarkitd: {e:#}"),
        }
        glib::timeout_future(RETRY).await;
    }
}

async fn serve(socket: &Path) -> anyhow::Result<()> {
    let mut conn = zlink::smol::unix::connect(socket)
        .await
        .with_context(|| format!("connecting to {}", socket.display()))?;
    let events = conn.register().await?;
    pin_mut!(events);

    // The first reply confirms the registration.
    match events.next().await {
        Some(Ok(Ok(_))) => tracing::info!("registered as the session's authentication agent"),
        Some(Ok(Err(e))) => return Err(e).context("registering"),
        Some(Err(e)) => return Err(e).context("registering"),
        None => anyhow::bail!("cedarkitd closed the connection while registering"),
    }

    let state = Rc::new(RefCell::new(State::default()));
    let (queue, requests) = async_channel::unbounded();
    let worker = glib::spawn_future_local(work(socket.to_owned(), requests, state.clone()));

    let result = async {
        while let Some(event) = events.next().await {
            let event = event??;
            if let Some(request) = event.request {
                tracing::debug!(cookie = request.cookie, action = request.action, "request");
                queue.send(request).await?;
            }
            if let Some(cookie) = event.cancelled {
                tracing::debug!(cookie, "cancelled");
                state.borrow_mut().cancel(&cookie);
            }
        }
        anyhow::Ok(())
    }
    .await;

    // Unregistered: whatever was waiting is moot. The request in progress
    // closes its dialog when told, and the rest are dropped.
    let current = {
        let mut state = state.borrow_mut();
        state.stopped = true;
        state.current.take()
    };
    if let Some((_, tx)) = current {
        let _ = tx.try_send(());
    }
    queue.close();
    let _ = worker.await;
    result
}

/// Handles requests one at a time.
async fn work(
    socket: PathBuf,
    requests: async_channel::Receiver<Request>,
    state: Rc<RefCell<State>>,
) {
    while let Ok(request) = requests.recv().await {
        if state.borrow().stopped {
            break;
        }
        if state.borrow_mut().cancelled.remove(&request.cookie) {
            continue;
        }
        let (tx, cancelled) = async_channel::bounded(1);
        state.borrow_mut().current = Some((request.cookie.clone(), tx));
        crate::dialog::authenticate(&socket, &request, cancelled).await;
        state.borrow_mut().current = None;
    }
}
