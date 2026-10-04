//! Authentication agents (docs/design.md, section 9.6): one per login
//! session, asked to authenticate when a process in that session meets a
//! challenge.
//!
//! Native agents talk Varlink. The user authenticates through PAM, which
//! runs in `cedarkit-pam-helper`; agents only relay the conversation, so
//! CedarKit learns the result first-hand rather than trusting an agent's
//! report. polkit agents (section 11) run polkit's own helper, which reports
//! the result as root, as to polkit.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use cedarkit_agent_protocol::{AgentError, Event, Identity, Request, Step};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot, watch};

/// How to run PAM.
#[derive(Debug, Clone)]
pub struct PamConfig {
    pub helper: PathBuf,
    pub service: String,
    /// Where to find the service's configuration, if not `/etc/pam.d`.
    pub confdir: Option<PathBuf>,
}

/// How CedarKit reaches an agent.
pub enum Channel {
    /// A native agent, over Varlink (`org.cedarkit.Agent`).
    Varlink(mpsc::UnboundedSender<Event>),
    /// A polkit agent, such as GNOME Shell's, which implements
    /// `org.freedesktop.PolicyKit1.AuthenticationAgent` and runs PAM itself,
    /// through polkit's helper.
    Polkit(PolkitAgent),
}

/// Where a polkit agent is on the bus.
#[derive(Clone)]
pub struct PolkitAgent {
    pub conn: zbus::Connection,
    /// Its unique name.
    pub name: String,
    pub path: String,
}

const POLKIT_AGENT: &str = "org.freedesktop.PolicyKit1.AuthenticationAgent";

/// What an agent is asked.
#[derive(Debug, Clone)]
pub struct AgentRequest {
    pub action: String,
    /// What the agent shows, e.g. polkit's `<message>`.
    pub message: String,
    pub icon: String,
    /// polkit's details, for polkit agents.
    pub details: HashMap<String, String>,
    pub identities: Vec<Identity>,
}

/// The registered agents, and the requests they're handling.
pub struct Agents {
    pam: PamConfig,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    agents: Vec<Agent>,
    /// By cookie.
    requests: HashMap<String, Pending>,
}

struct Agent {
    id: u64,
    uid: u32,
    session: String,
    /// Only used when the session has no other agent, as polkit's
    /// `fallback` option.
    fallback: bool,
    channel: Channel,
}

struct Pending {
    agent: u64,
    agent_uid: u32,
    /// Whether a polkit agent is handling it.
    polkit: bool,
    identities: Vec<Identity>,
    /// Told the uid that authenticated.
    done: oneshot::Sender<u32>,
    /// For a native agent, the attempt in progress.
    conversation: Option<Attempt>,
    /// For a polkit agent, who polkit's helper says authenticated.
    authenticated: Option<u32>,
}

/// An attempt to authenticate, which ends when its sender is dropped.
struct Attempt {
    uid: u32,
    conversation: Arc<tokio::sync::Mutex<Conversation>>,
    alive: watch::Sender<()>,
}

/// A registered agent: its events, and its id for unregistering.
pub struct Registration {
    pub id: u64,
    pub events: mpsc::UnboundedReceiver<Event>,
}

/// A request sent to an agent. Dropping it cancels the request.
pub struct Challenge {
    agents: Arc<Agents>,
    cookie: String,
    done: Option<oneshot::Receiver<u32>>,
}

impl Challenge {
    /// Waits for someone to authenticate, returning their uid, or `None` if
    /// the user dismissed the request or the agent went away.
    pub async fn wait(mut self) -> Option<u32> {
        self.done.take()?.await.ok()
    }
}

impl Drop for Challenge {
    fn drop(&mut self) {
        self.agents.cancel(&self.cookie);
    }
}

/// An attempt's access to its conversation with PAM, which reports
/// cancellation when the attempt is replaced or the request ends.
pub struct Turn {
    pub conversation: Arc<tokio::sync::Mutex<Conversation>>,
    pub alive: watch::Receiver<()>,
    pub uid: u32,
}

/// A random cookie, so that one agent can't guess another's requests.
fn cookie() -> String {
    let mut bytes = [0u8; 16];
    // getrandom(2) only fails for invalid arguments, or before the entropy
    // pool is ready.
    let n = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    assert_eq!(n, bytes.len() as isize, "getrandom failed");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Agents {
    pub fn new(pam: PamConfig) -> Self {
        Self {
            pam,
            inner: Mutex::default(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("the agents' lock isn't poisoned")
    }

    fn add(
        &self,
        session: &str,
        uid: u32,
        fallback: bool,
        channel: Channel,
    ) -> Result<u64, AgentError> {
        let mut inner = self.lock();
        if inner
            .agents
            .iter()
            .any(|a| a.session == session && a.fallback == fallback)
        {
            return Err(AgentError::AgentExists);
        }
        inner.next_id += 1;
        let id = inner.next_id;
        inner.agents.push(Agent {
            id,
            uid,
            session: session.to_owned(),
            fallback,
            channel,
        });
        tracing::info!(session, uid, fallback, "authentication agent registered");
        Ok(id)
    }

    /// Registers a native agent run by `uid` for `session`.
    pub fn register(&self, session: &str, uid: u32) -> Result<Registration, AgentError> {
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.add(session, uid, false, Channel::Varlink(tx))?;
        Ok(Registration { id, events: rx })
    }

    /// Registers a polkit agent run by `uid` for `session`.
    pub fn register_polkit(
        &self,
        session: &str,
        uid: u32,
        fallback: bool,
        agent: PolkitAgent,
    ) -> Result<u64, AgentError> {
        self.add(session, uid, fallback, Channel::Polkit(agent))
    }

    /// Removes an agent, failing the requests it was handling.
    pub fn unregister(&self, id: u64) {
        let mut inner = self.lock();
        inner.agents.retain(|a| {
            if a.id == id {
                tracing::info!(session = a.session, "authentication agent unregistered");
            }
            a.id != id
        });
        inner.requests.retain(|_, p| p.agent != id);
    }

    /// Removes the polkit agents at bus name `name` (and object `path`, if
    /// given), returning whether there were any.
    pub fn unregister_polkit(&self, name: &str, path: Option<&str>) -> bool {
        let ids: Vec<u64> = self
            .lock()
            .agents
            .iter()
            .filter(|a| match &a.channel {
                Channel::Polkit(p) => p.name == name && path.is_none_or(|path| p.path == path),
                Channel::Varlink(_) => false,
            })
            .map(|a| a.id)
            .collect();
        for id in &ids {
            self.unregister(*id);
        }
        !ids.is_empty()
    }

    /// Asks the agent for `session` to have one of the request's identities
    /// authenticate, or returns `None` if there's no agent.
    pub fn begin(self: &Arc<Self>, session: &str, request: AgentRequest) -> Option<Challenge> {
        let mut inner = self.lock();
        let agent = inner
            .agents
            .iter()
            .filter(|a| a.session == session)
            .min_by_key(|a| a.fallback)?;
        let (id, agent_uid) = (agent.id, agent.uid);
        let cookie = cookie();
        let polkit = match &agent.channel {
            Channel::Varlink(events) => {
                let event = Event {
                    request: Some(Request {
                        cookie: cookie.clone(),
                        action: request.action.clone(),
                        message: request.message.clone(),
                        identities: request.identities.clone(),
                    }),
                    cancelled: None,
                };
                if events.send(event).is_err() {
                    return None;
                }
                false
            }
            Channel::Polkit(agent) => {
                let (agents, agent, cookie, request) =
                    (self.clone(), agent.clone(), cookie.clone(), request.clone());
                tokio::spawn(async move {
                    let replied = begin_polkit(&agent, &cookie, &request).await;
                    if let Err(e) = &replied {
                        tracing::debug!(cookie, "polkit agent's request ended: {e}");
                    }
                    agents.polkit_finished(&cookie, replied.is_ok());
                });
                true
            }
        };
        let (done, rx) = oneshot::channel();
        inner.requests.insert(
            cookie.clone(),
            Pending {
                agent: id,
                agent_uid,
                polkit,
                identities: request.identities,
                done,
                conversation: None,
                authenticated: None,
            },
        );
        Some(Challenge {
            agents: self.clone(),
            cookie,
            done: Some(rx),
        })
    }

    /// Ends a request, telling its agent if it's still waiting.
    fn cancel(&self, cookie: &str) {
        let mut inner = self.lock();
        let Some(pending) = inner.requests.remove(cookie) else {
            return;
        };
        let Some(agent) = inner.agents.iter().find(|a| a.id == pending.agent) else {
            return;
        };
        match &agent.channel {
            Channel::Varlink(events) => {
                let _ = events.send(Event {
                    request: None,
                    cancelled: Some(cookie.to_owned()),
                });
            }
            Channel::Polkit(agent) => {
                let (agent, cookie) = (agent.clone(), cookie.to_owned());
                tokio::spawn(async move {
                    let result = agent
                        .conn
                        .call_method(
                            Some(agent.name.as_str()),
                            agent.path.as_str(),
                            Some(POLKIT_AGENT),
                            "CancelAuthentication",
                            &(cookie.as_str(),),
                        )
                        .await;
                    if let Err(e) = result {
                        tracing::debug!(cookie, "can't cancel the polkit agent's request: {e}");
                    }
                });
            }
        }
    }

    /// Records polkit's helper saying that `identity` authenticated for a
    /// polkit agent's request. `claimed` is the uid the helper says it ran
    /// for, which must be the agent's, if given.
    pub fn polkit_response(
        &self,
        cookie: &str,
        claimed: Option<u32>,
        identity: u32,
    ) -> Result<(), String> {
        let mut inner = self.lock();
        let pending = match inner.requests.get_mut(cookie) {
            Some(p) if p.polkit => p,
            _ => return Err(format!("no authentication with cookie {cookie:?}")),
        };
        if claimed.is_some_and(|uid| uid != pending.agent_uid) {
            return Err("the authentication was for another user's agent".into());
        }
        if !pending.identities.iter().any(|i| i.uid == identity) {
            return Err("the authenticated identity is wrong".into());
        }
        pending.authenticated = Some(identity);
        Ok(())
    }

    /// A polkit agent finished a request. It succeeded if the agent says so,
    /// and polkit's helper reported who authenticated.
    fn polkit_finished(&self, cookie: &str, replied: bool) {
        let Some(pending) = self.lock().requests.remove(cookie) else {
            return;
        };
        match pending.authenticated {
            Some(uid) if replied => {
                let _ = pending.done.send(uid);
            }
            _ => {}
        }
    }

    /// A native agent's request, for the agent run by `caller`.
    fn request<'a>(
        inner: &'a mut Inner,
        caller: u32,
        cookie: &str,
    ) -> Result<&'a mut Pending, AgentError> {
        match inner.requests.get_mut(cookie) {
            Some(p) if !p.polkit && (p.agent_uid == caller || caller == 0) => Ok(p),
            _ => Err(AgentError::NoSuchRequest),
        }
    }

    /// Starts an attempt by `uid` to authenticate for a request, replacing
    /// any attempt in progress.
    pub async fn authenticate(
        &self,
        caller: u32,
        cookie: &str,
        uid: u32,
    ) -> Result<Turn, AgentError> {
        let name = {
            let mut inner = self.lock();
            let pending = Self::request(&mut inner, caller, cookie)?;
            pending.conversation = None;
            let identity = pending.identities.iter().find(|i| i.uid == uid);
            identity.ok_or(AgentError::NotAnIdentity)?.name.clone()
        };

        let conversation =
            Conversation::spawn(&self.pam, &name)
                .await
                .map_err(|e| AgentError::Failed {
                    message: format!("can't start authentication: {e}"),
                })?;
        let conversation = Arc::new(tokio::sync::Mutex::new(conversation));
        let (alive_tx, alive) = watch::channel(());

        let mut inner = self.lock();
        let pending = Self::request(&mut inner, caller, cookie)?;
        pending.conversation = Some(Attempt {
            uid,
            conversation: conversation.clone(),
            alive: alive_tx,
        });
        Ok(Turn {
            conversation,
            alive,
            uid,
        })
    }

    /// The attempt in progress for a request, to answer its prompt.
    pub fn attempt(&self, caller: u32, cookie: &str) -> Result<Turn, AgentError> {
        let mut inner = self.lock();
        let pending = Self::request(&mut inner, caller, cookie)?;
        let attempt = pending.conversation.as_ref().ok_or(AgentError::NoPrompt)?;
        Ok(Turn {
            conversation: attempt.conversation.clone(),
            alive: attempt.alive.subscribe(),
            uid: attempt.uid,
        })
    }

    /// Records the end of an attempt. A success completes the request.
    pub fn finish(&self, cookie: &str, uid: u32, success: bool) {
        let mut inner = self.lock();
        if success {
            if let Some(pending) = inner.requests.remove(cookie) {
                let _ = pending.done.send(uid);
            }
        } else if let Some(pending) = inner.requests.get_mut(cookie) {
            pending.conversation = None;
        }
    }

    /// The user dismissed a request.
    pub fn dismiss(&self, caller: u32, cookie: &str) -> Result<(), AgentError> {
        let mut inner = self.lock();
        Self::request(&mut inner, caller, cookie)?;
        inner.requests.remove(cookie);
        Ok(())
    }
}

/// Calls a polkit agent's `BeginAuthentication`, which returns once the user
/// has authenticated or given up.
async fn begin_polkit(
    agent: &PolkitAgent,
    cookie: &str,
    request: &AgentRequest,
) -> zbus::Result<()> {
    use zbus::zvariant::Value;
    let identities: Vec<(&str, HashMap<&str, Value<'_>>)> = request
        .identities
        .iter()
        .map(|i| ("unix-user", HashMap::from([("uid", Value::U32(i.uid))])))
        .collect();
    agent
        .conn
        .call_method(
            Some(agent.name.as_str()),
            agent.path.as_str(),
            Some(POLKIT_AGENT),
            "BeginAuthentication",
            &(
                request.action.as_str(),
                request.message.as_str(),
                request.icon.as_str(),
                &request.details,
                cookie,
                identities,
            ),
        )
        .await?;
    Ok(())
}

/// A conversation with PAM, through `cedarkit-pam-helper`.
pub struct Conversation {
    // Killed when the conversation is dropped.
    _child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
    /// Whether PAM is waiting for an answer.
    prompted: bool,
}

impl Conversation {
    async fn spawn(pam: &PamConfig, user: &str) -> std::io::Result<Self> {
        let mut command = Command::new(&pam.helper);
        command.arg(&pam.service).arg(user);
        if let Some(dir) = &pam.confdir {
            command.arg(dir);
        }
        // Only what PAM's messages need.
        command.env_clear().env("PATH", "/usr/bin:/bin");
        for var in ["LANG", "LANGUAGE", "LC_MESSAGES"] {
            if let Ok(value) = std::env::var(var) {
                command.env(var, value);
            }
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child.stdin.take().expect("stdin is piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout is piped")).lines();
        Ok(Self {
            _child: child,
            stdin,
            stdout,
            prompted: false,
        })
    }

    /// PAM's next message. A helper that stops making sense has failed.
    pub async fn next_step(&mut self) -> Step {
        let line = match self.stdout.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) | Err(_) => return Step::done(false),
        };
        match serde_json::from_str::<Step>(&line) {
            Ok(step) => {
                self.prompted = step.prompt.is_some();
                step
            }
            Err(e) => {
                tracing::warn!("unexpected output from cedarkit-pam-helper: {e}");
                Step::done(false)
            }
        }
    }

    /// Answers PAM's prompt.
    pub async fn answer(&mut self, answer: &str) -> Result<(), AgentError> {
        if !self.prompted {
            return Err(AgentError::NoPrompt);
        }
        self.prompted = false;
        let mut line = serde_json::to_string(answer).expect("strings serialize");
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| AgentError::Failed {
                message: format!("can't answer PAM: {e}"),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: u32 = 1000;
    const BOB: u32 = 1001;

    /// A stand-in for `cedarkit-pam-helper`: asks for a password, which is
    /// "secret".
    fn agents(dir: &std::path::Path) -> Arc<Agents> {
        let script = dir.join("helper");
        std::fs::write(
            &script,
            "echo '{\"info\":\"Hello\"}'\n\
             echo '{\"prompt\":{\"text\":\"Password: \",\"echo\":false}}'\n\
             read -r answer\n\
             if [ \"$answer\" = '\"secret\"' ]; then echo '{\"success\":true}'; \
             else echo '{\"success\":false}'; fi\n",
        )
        .unwrap();
        // Run as `sh SCRIPT USER`, rather than executing the script: another
        // test forking while it's being written could make that fail with
        // ETXTBSY.
        Arc::new(Agents::new(PamConfig {
            helper: "/bin/sh".into(),
            service: script.display().to_string(),
            confdir: None,
        }))
    }

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cedarkitd-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ask(action: &str) -> AgentRequest {
        AgentRequest {
            action: action.into(),
            message: "Do it".into(),
            icon: String::new(),
            details: HashMap::new(),
            identities: identities(),
        }
    }

    fn identities() -> Vec<Identity> {
        vec![Identity {
            uid: BOB,
            name: "bob".into(),
        }]
    }

    fn request(event: Option<Event>) -> Request {
        event.and_then(|e| e.request).expect("a request")
    }

    #[test]
    fn one_agent_per_session() {
        let dir = tempdir("one");
        let agents = agents(&dir);
        let first = agents.register("3", ALICE).unwrap();
        assert_eq!(
            agents.register("3", ALICE).err(),
            Some(AgentError::AgentExists)
        );
        assert!(agents.register("4", BOB).is_ok());
        agents.unregister(first.id);
        assert!(agents.register("3", ALICE).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn requests_and_cancellation() {
        let dir = tempdir("requests");
        let agents = agents(&dir);
        assert!(agents.begin("3", ask("a")).is_none(), "no agent yet");

        let mut agent = agents.register("3", ALICE).unwrap();
        let challenge = agents.begin("3", ask("org.example.a")).unwrap();
        let sent = request(agent.events.recv().await);
        assert_eq!(sent.action, "org.example.a");
        assert_eq!(sent.identities, identities());

        // Only the agent's user may act on its requests.
        assert_eq!(
            agents.dismiss(BOB, &sent.cookie),
            Err(AgentError::NoSuchRequest)
        );
        // Giving up on the check tells the agent.
        drop(challenge);
        let cancelled = agent.events.recv().await.unwrap().cancelled;
        assert_eq!(cancelled.as_deref(), Some(sent.cookie.as_str()));
        assert_eq!(
            agents.dismiss(ALICE, &sent.cookie),
            Err(AgentError::NoSuchRequest)
        );

        // The user dismissing it ends the check.
        let challenge = agents.begin("3", ask("org.example.a")).unwrap();
        let sent = request(agent.events.recv().await);
        agents.dismiss(ALICE, &sent.cookie).unwrap();
        assert_eq!(challenge.wait().await, None);

        // So does the agent going away.
        let challenge = agents.begin("3", ask("org.example.a")).unwrap();
        agents.unregister(agent.id);
        assert_eq!(challenge.wait().await, None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    async fn steps(turn: &Turn) -> Vec<Step> {
        let mut steps = Vec::new();
        loop {
            let step = turn.conversation.lock().await.next_step().await;
            let last = step.is_last();
            steps.push(step);
            if last {
                return steps;
            }
        }
    }

    #[tokio::test]
    async fn authenticating() {
        let dir = tempdir("auth");
        let agents = agents(&dir);
        let mut agent = agents.register("3", ALICE).unwrap();
        let challenge = agents.begin("3", ask("org.example.a")).unwrap();
        let cookie = request(agent.events.recv().await).cookie;

        assert_eq!(
            agents.authenticate(ALICE, &cookie, ALICE).await.err(),
            Some(AgentError::NotAnIdentity)
        );
        assert_eq!(
            agents.attempt(ALICE, &cookie).err(),
            Some(AgentError::NoPrompt)
        );

        // A wrong password, then the right one.
        for (password, success) in [("wrong", false), ("secret", true)] {
            let turn = agents.authenticate(ALICE, &cookie, BOB).await.unwrap();
            assert_eq!(
                steps(&turn).await,
                [Step::info("Hello"), Step::prompt("Password: ", false)]
            );
            let turn = agents.attempt(ALICE, &cookie).unwrap();
            turn.conversation
                .lock()
                .await
                .answer(password)
                .await
                .unwrap();
            assert_eq!(steps(&turn).await, [Step::done(success)]);
            agents.finish(&cookie, turn.uid, success);
        }
        assert_eq!(challenge.wait().await, Some(BOB));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
