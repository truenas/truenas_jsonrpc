//! [`Channel`] — what the transport offers an auth mechanism, derived from the connection's
//! [`Peer`], and the [`Capability`] gating mechanisms check before running.

use std::net::SocketAddr;

use truenas_jsonrpc_server::{Peer, Transport, Ucred};

/// A capability the channel may provide. A [`Mechanism`](crate::Mechanism) declares the set it
/// requires; the stack rejects (`DENIED`) before running it if the channel lacks any of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// A local (AF_UNIX) peer.
    Local,
    /// The channel is encrypted (AF_UNIX local trust, or TLS — set once the TLS phase lands).
    Encrypted,
    /// AF_UNIX with `SO_PEERCRED` credentials present.
    Peercred,
    /// The peer presented a (TLS-verified) client certificate.
    ClientCert,
}

/// Immutable per-connection channel context: the transport plus whatever credentials/binding the
/// wire makes available. Built once from the [`Peer`] by [`AuthSession::from_peer`](crate::AuthSession::from_peer)
/// and read by mechanisms; never mutated after construction.
#[derive(Clone, Debug)]
pub struct Channel {
    /// The transport the connection arrived on.
    pub transport: Transport,
    /// AF_UNIX peer credentials (`SO_PEERCRED`), or `None` on TCP.
    pub ucred: Option<Ucred>,
    /// TCP peer address, or `None` on AF_UNIX.
    pub addr: Option<SocketAddr>,
    /// Whether the channel is confidential (AF_UNIX is treated as local-trust-encrypted; TLS sets
    /// this in the transport phase).
    pub encrypted: bool,
    /// The TLS-verified client certificate (DER), if the peer presented one. Populated in the
    /// mTLS phase; `None` until then and on non-TLS transports.
    pub client_cert: Option<Vec<u8>>,
    /// The server's `tls-server-end-point` channel-binding value (RFC 5929) for this connection —
    /// required by SCRAM-SHA-512-PLUS. Populated in the transport phase; `None` off TLS.
    pub channel_binding: Option<Vec<u8>>,
}

impl Channel {
    /// Derive the channel context from the connected [`Peer`].
    pub fn from_peer(peer: &Peer) -> Self {
        let tls = peer.tls.as_ref();
        Self {
            transport: peer.transport,
            ucred: peer.ucred,
            addr: peer.addr,
            // Encrypted if AF_UNIX (local trust) or a TLS / `wss` connection.
            encrypted: peer.transport == Transport::Unix || tls.is_some(),
            client_cert: tls.and_then(|t| t.peer_cert.clone()),
            channel_binding: tls.and_then(|t| t.channel_binding.clone()),
        }
    }

    /// Whether the channel provides `cap`.
    pub fn has(&self, cap: Capability) -> bool {
        match cap {
            Capability::Local => self.transport == Transport::Unix,
            Capability::Encrypted => self.encrypted,
            Capability::Peercred => self.transport == Transport::Unix && self.ucred.is_some(),
            Capability::ClientCert => self.client_cert.is_some(),
        }
    }

    /// Whether the channel provides every capability in `required`.
    pub fn has_all(&self, required: &[Capability]) -> bool {
        required.iter().all(|&c| self.has(c))
    }
}
