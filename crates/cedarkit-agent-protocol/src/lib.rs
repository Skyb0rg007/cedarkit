//! CedarKit's authentication agent protocol: the `org.cedarkit.Agent`
//! Varlink interface, between `cedarkitd` and the agents that ask users to
//! authenticate. See `org.cedarkit.Agent.varlink` for what each call does.

use futures_util::Stream;
use serde::{Deserialize, Serialize};

/// The interface's name.
pub const INTERFACE: &str = "org.cedarkit.Agent";

/// The interface description, in Varlink's IDL.
pub const DESCRIPTION: &str = include_str!("org.cedarkit.Agent.varlink");

/// Where `cedarkitd` listens for agents.
pub const SOCKET: &str = "/run/cedarkit/org.cedarkit.Agent";

/// A user who could authenticate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub uid: u32,
    pub name: String,
}

/// A request to authenticate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub cookie: String,
    pub action: String,
    pub message: String,
    /// The subject first, if listed.
    pub identities: Vec<Identity>,
}

/// A reply to `Register`: the confirmation (neither field set), a request,
/// or a cancellation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled: Option<String>,
}

/// What PAM asks the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    pub text: String,
    pub echo: bool,
}

/// A reply to `Authenticate` or `Respond`: exactly one field is set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<Prompt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
}

impl Step {
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            info: Some(text.into()),
            ..Self::default()
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self {
            error: Some(text.into()),
            ..Self::default()
        }
    }

    pub fn prompt(text: impl Into<String>, echo: bool) -> Self {
        Self {
            prompt: Some(Prompt {
                text: text.into(),
                echo,
            }),
            ..Self::default()
        }
    }

    pub fn done(success: bool) -> Self {
        Self {
            success: Some(success),
            ..Self::default()
        }
    }

    /// Whether this is the last reply to the call: a prompt or the result.
    pub fn is_last(&self) -> bool {
        self.prompt.is_some() || self.success.is_some()
    }
}

/// The interface's errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", content = "parameters")]
pub enum AgentError {
    #[serde(rename = "org.cedarkit.Agent.AgentExists")]
    AgentExists,
    #[serde(rename = "org.cedarkit.Agent.NoSession")]
    NoSession,
    #[serde(rename = "org.cedarkit.Agent.NoSuchRequest")]
    NoSuchRequest,
    #[serde(rename = "org.cedarkit.Agent.NotAnIdentity")]
    NotAnIdentity,
    #[serde(rename = "org.cedarkit.Agent.NoPrompt")]
    NoPrompt,
    #[serde(rename = "org.cedarkit.Agent.Failed")]
    Failed { message: String },
    /// A streaming method was called without the more flag.
    #[serde(rename = "org.varlink.service.ExpectedMore")]
    ExpectedMore,
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AgentExists => f.write_str("another agent is registered for the session"),
            Self::NoSession => f.write_str("not in a login session"),
            Self::NoSuchRequest => f.write_str("no such request"),
            Self::NotAnIdentity => f.write_str("not one of the request's identities"),
            Self::NoPrompt => f.write_str("there's no prompt to answer"),
            Self::Failed { message } => f.write_str(message),
            Self::ExpectedMore => f.write_str("the call needs the more flag"),
        }
    }
}

impl std::error::Error for AgentError {}

/// The calls the daemon handles: this interface's, and the parts of
/// `org.varlink.service` that describe it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "parameters")]
pub enum Method {
    #[serde(rename = "org.cedarkit.Agent.Register")]
    Register,
    #[serde(rename = "org.cedarkit.Agent.Authenticate")]
    Authenticate { cookie: String, uid: u32 },
    #[serde(rename = "org.cedarkit.Agent.Respond")]
    Respond { cookie: String, response: String },
    #[serde(rename = "org.cedarkit.Agent.Dismiss")]
    Dismiss { cookie: String },
    #[serde(rename = "org.varlink.service.GetInfo")]
    GetInfo,
    #[serde(rename = "org.varlink.service.GetInterfaceDescription")]
    GetInterfaceDescription { interface: String },
}

/// Calls to the daemon, for agents.
#[zlink_core::proxy(interface = "org.cedarkit.Agent", crate = "zlink_core")]
pub trait AgentProxy {
    #[zlink(more)]
    async fn register(
        &mut self,
    ) -> zlink_core::Result<impl Stream<Item = zlink_core::Result<Result<Event, AgentError>>>>;

    #[zlink(more)]
    async fn authenticate(
        &mut self,
        cookie: &str,
        uid: u32,
    ) -> zlink_core::Result<impl Stream<Item = zlink_core::Result<Result<Step, AgentError>>>>;

    #[zlink(more)]
    async fn respond(
        &mut self,
        cookie: &str,
        response: &str,
    ) -> zlink_core::Result<impl Stream<Item = zlink_core::Result<Result<Step, AgentError>>>>;

    async fn dismiss(&mut self, cookie: &str) -> zlink_core::Result<Result<(), AgentError>>;
}
