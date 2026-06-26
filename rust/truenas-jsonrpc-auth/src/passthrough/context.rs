//! The metadata a passthrough hand-off carries to the broker alongside the client fd, and the
//! verdict the broker returns.

use serde::{Deserialize, Serialize};
use truenas_jsonrpc_server::{Transport, TransportPosture};

use crate::channel::Channel;
use crate::outcome::{Outcome, Principal, RejectKind};

/// AF_UNIX peer credentials (`SO_PEERCRED`), forwarded to the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCred {
    /// Connecting process id.
    pub pid: i32,
    /// Connecting user id.
    pub uid: u32,
    /// Connecting group id.
    pub gid: u32,
}

/// The context a passthrough hand-off sends the broker together with the client connection's fd —
/// enough for the broker to conduct (or refuse) authentication on the fd it receives. Built from
/// the connection's [`Channel`], plus the negotiated protocol name (which the channel doesn't
/// carry). Binary fields ride as JSON byte arrays — this is an internal local-socket protocol, not
/// a hand-written wire format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerContext {
    /// The negotiated protocol name, if the caller set it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// The transport the client arrived on: `"unix"` or `"tcp"`.
    pub transport: String,
    /// AF_UNIX peer credentials, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peercred: Option<PeerCred>,
    /// Whether the channel is confidential (AF_UNIX local trust, or TLS).
    pub encrypted: bool,
    /// The TLS-verified client certificate (DER), if the peer presented one (mTLS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<Vec<u8>>,
    /// The `tls-server-end-point` channel binding (RFC 5929), if the channel is bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_binding: Option<Vec<u8>>,
    /// The connection's declared [`TransportPosture`] — the trust the server vouched for. The broker
    /// should re-validate it against the passed fd (e.g. probe `SOL_TLS` for kTLS, confirm AF_UNIX
    /// for the unix postures) before honoring it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<TransportPosture>,
}

impl BrokerContext {
    /// Derive the context from the connection's [`Channel`] (protocol unset — add it with
    /// [`with_protocol`](Self::with_protocol)).
    pub fn from_channel(channel: &Channel) -> Self {
        let transport = match channel.transport {
            Transport::Unix => "unix",
            Transport::Tcp => "tcp",
        };
        Self {
            protocol: None,
            transport: transport.to_string(),
            peercred: channel.ucred.map(|c| PeerCred { pid: c.pid, uid: c.uid, gid: c.gid }),
            encrypted: channel.encrypted,
            client_cert: channel.client_cert.clone(),
            channel_binding: channel.channel_binding.clone(),
            posture: channel.posture,
        }
    }

    /// Attach the negotiated protocol name.
    #[must_use]
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }
}

/// The broker's verdict for a passthrough hand-off, discriminated by `status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum BrokerVerdict {
    /// The broker authenticated the client as `identity`.
    #[serde(rename = "AUTHENTICATED")]
    Authenticated {
        /// The server-internal identity to store on the session.
        identity: serde_json::Value,
        /// The authentication mechanism the broker actually used (`"SCRAM"`, `"GSSAPI"`, …). The
        /// server authorizes `(uid, mechanism)` from this and records it in the session credential,
        /// so a brokered session is granted roles like an in-process one of the same method.
        mechanism: String,
        /// Who to authorize as — the [`Principal`] the stack resolves roles from (a uid, or an
        /// account name resolved via the username→uid resolver). Defaults to [`Principal::None`].
        #[serde(default)]
        principal: Principal,
        /// Optional client-facing identity info echoed in the `SUCCESS` reply.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_info: Option<serde_json::Value>,
    },
    /// The broker refused: the channel didn't meet its requirements.
    #[serde(rename = "DENIED")]
    Denied,
    /// The broker refused: a generic authentication failure.
    #[serde(rename = "AUTH_ERR")]
    AuthErr,
}

impl BrokerVerdict {
    /// Map the verdict onto the [`Outcome`] the auth stack commits, plus — when authenticated — the
    /// mechanism the broker reported using (so the server authorizes `(uid, mechanism)` and records
    /// it in the credential). The mechanism is `None` on a non-authenticated verdict.
    pub(crate) fn into_handoff(self) -> (Outcome, Option<String>) {
        match self {
            BrokerVerdict::Authenticated { identity, mechanism, principal, user_info } => (
                Outcome::Authenticated { identity, principal, user_info, extra: None },
                Some(mechanism),
            ),
            BrokerVerdict::Denied => (Outcome::Reject(RejectKind::Denied), None),
            BrokerVerdict::AuthErr => (Outcome::Reject(RejectKind::AuthErr), None),
        }
    }
}
