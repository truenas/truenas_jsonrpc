//! The mTLS (client-certificate) [`Mechanism`]: derive an identity from the TLS-verified client
//! certificate. TLS already authenticated the cert during the handshake (it chains to the server's
//! configured client CA), so this mechanism only maps the verified cert to an application identity.

use crate::channel::{Capability, Channel};
use crate::mechanism::Mechanism;
use crate::outcome::{AuthProgress, Identity, Outcome, RejectKind};
use crate::stack::AuthStackBuilder;

/// The wire tag clients use to select mTLS (`{ "mechanism": "CLIENT_CERTIFICATE" }`).
pub const MTLS_TAG: &str = "CLIENT_CERTIFICATE";

/// mTLS mechanism: maps the verified client certificate (DER) to an [`Identity`] via a policy
/// closure (return `None` to reject). Single-shot — the certificate is on the channel, not the
/// wire — and gated on [`Capability::ClientCert`], so a connection without a client cert is denied
/// before this runs.
pub struct Mtls<F> {
    policy: F,
}

impl<F> Mtls<F> {
    /// Build the mechanism from a cert→identity `policy` (parses the DER and returns the identity,
    /// e.g. from the subject CN / a SAN / the fingerprint).
    pub fn new(policy: F) -> Self {
        Self { policy }
    }
}

impl<F> Mechanism for Mtls<F>
where
    F: Fn(&[u8]) -> Option<Identity> + Send + Sync,
{
    fn required(&self) -> &'static [Capability] {
        &[Capability::ClientCert]
    }

    fn step(
        &self,
        _payload: &serde_json::Value,
        channel: &Channel,
        _progress: Option<AuthProgress>,
    ) -> Outcome {
        match channel.client_cert.as_deref().and_then(|der| (self.policy)(der)) {
            Some(identity) => Outcome::authenticated(identity),
            None => Outcome::Reject(RejectKind::AuthErr),
        }
    }
}

impl AuthStackBuilder {
    /// Enable mTLS under the [`MTLS_TAG`] tag: derive an identity from the verified client
    /// certificate (DER) via `policy`.
    #[must_use]
    pub fn mtls(self, policy: impl Fn(&[u8]) -> Option<Identity> + Send + Sync + 'static) -> Self {
        self.mechanism(MTLS_TAG, Mtls::new(policy))
    }
}
