//! The [`Mechanism`] trait — one challenge-response step. Concrete mechanisms (mTLS, SCRAM,
//! GSSAPI, passthrough) implement it in later phases; the stack routes to them by wire tag.

use crate::channel::Channel;
use crate::outcome::{AuthProgress, Outcome};

/// A pluggable authentication mechanism. The stack routes a setup/continue request to the
/// mechanism whose wire tag matches the request's `"mechanism"` field, after checking the channel
/// meets [`required`](Self::required); [`step`](Self::step) advances one round.
///
/// A single-shot mechanism (mTLS) returns `Authenticated`/`Reject` on the first call. A
/// multi-round one (SCRAM, GSSAPI) returns `Challenge { next, .. }` carrying its state, then is
/// called again with `progress = Some(..)` on `$/sessionSetupContinue`.
pub trait Mechanism: Send + Sync {
    /// The channel capabilities this mechanism requires. The stack returns `DENIED` without
    /// running [`step`](Self::step) if any are missing. Default: none.
    fn required(&self) -> &'static [crate::channel::Capability] {
        &[]
    }

    /// Advance the exchange. `payload` is the request's mechanism object (its `"mechanism"` tag
    /// already matched); `channel` is the immutable channel context; `progress` is the state this
    /// mechanism carried from the previous round (`None` on the first round).
    fn step(&self, payload: &serde_json::Value, channel: &Channel, progress: Option<AuthProgress>)
        -> Outcome;
}
