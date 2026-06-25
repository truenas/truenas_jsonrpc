//! Authentication layer for `truenas-jsonrpc`.
//!
//! A Rust port of the TrueNAS middleware auth mixin (`truenas_pyjsonrpc/mixins/auth/`), **without
//! PAM** and with a greenfield wire schema. The shape:
//!
//! - An [`AuthStack`] holds the enabled [`Mechanism`]s plus an optional AF_UNIX **peer-cred**
//!   default. [`install`] wires it onto a protocol's `$/sessionSetup` / `$/sessionSetupContinue`
//!   (the core seam), so authentication runs through the normal session-lifecycle machinery
//!   (`None → Init → Established`).
//! - The per-connection state is an [`AuthSession`] (`S` for the protocol/server): an immutable
//!   [`Channel`] (transport + credentials the wire offers) plus an in-progress / authenticated
//!   state that the setup handlers advance in place (via the session's `with_internal_mut`).
//! - A [`Mechanism`] is a challenge-response step returning an [`Outcome`]
//!   (`Authenticated` / `Challenge` / `NeedsOtp` / `Reject`); the stack maps that onto the
//!   `(SessionLifecycle, AuthResult)` the core expects and carries any pending state across the
//!   `$/sessionSetupContinue` round.
//!
//! Mechanisms are **user-declared**: AF_UNIX defaults to peer-cred, while TCP exposes only the
//! mechanisms the embedder registers (mTLS, SCRAM-SHA-512-PLUS, GSSAPI, passthrough). The latter
//! land over subsequent phases; the framework + peer-cred are here.
//!
//! ```ignore
//! let stack = AuthStack::builder()
//!     .peercred(|ch| ch.ucred.filter(|c| c.uid == 0).map(|c| json!({ "uid": c.uid })))
//!     .build();
//! let proto = install(JsonRpcProtocol::<AuthSession>::builder("conf", "1"), stack)
//!     .method(/* … app methods … */)
//!     .build();
//! let server = JsonRpcServer::<AuthSession>::builder("srv")
//!     .state_from_peer(AuthSession::from_peer)
//!     .protocol("main", proto)
//!     .build();
//! ```

mod channel;
#[cfg(feature = "keyring")]
mod keyring;
mod mechanism;
mod mtls;
mod outcome;
#[cfg(feature = "passthrough")]
mod passthrough;
#[cfg(feature = "scram")]
mod scram;
mod stack;
mod state;
mod wire;

pub use channel::{Capability, Channel};
#[cfg(feature = "keyring")]
pub use keyring::KeyringCredentials;
pub use mechanism::Mechanism;
pub use mtls::{Mtls, MTLS_TAG};
pub use outcome::{AuthProgress, Identity, Outcome, RejectKind};
#[cfg(feature = "passthrough")]
pub use passthrough::{
    BrokerContext, BrokerServer, BrokerVerdict, Passthrough, PeerCred, PASSTHROUGH_TAG,
};
#[cfg(feature = "scram")]
pub use scram::{derive_verifier, CredentialSource, Scram, ScramCredentials, SCRAM_TAG};
pub use stack::{install, AuthStack, AuthStackBuilder, FULL_ADMIN};
pub use state::{AuthSession, AuthSessionState};
pub use wire::{AuthResponse, AuthResult, ContinueArgs, SetupArgs};
