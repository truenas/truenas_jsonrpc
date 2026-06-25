//! Role-based authorization primitives.
//!
//! Authorization is a **native gate**, not a closure: a method declares the roles it requires (a
//! [`RoleMask`]), the session carries the roles its identity was granted (set once at
//! `sessionSetup`, hierarchy pre-expanded), and the dispatch path checks `required ⊆ granted` —
//! you must hold *all* the roles a method requires (subset / AND semantics, the standard ACL check).
//! There is no per-call policy callback and no request materialization for the gate. "Either of two
//! roles may call this" is expressed by **hierarchy** (a broader role implies the required one,
//! expanded into the granted mask at grant time) or by a shared permission both roles grant — not
//! by OR-matching. Resource / parameter-level authorization (ownership, "your own records", ABAC)
//! is the **handler's** job — it has the session and the typed params.
//!
//! Roles are bits in a `u64` (up to 64 roles — we define our own role set, so a sane taxonomy fits
//! with room to spare). [`RoleMask::FULL_ADMIN`] is the all-ones mask: it satisfies every
//! requirement for free (no special-casing — all-ones ANDed with any non-empty requirement is
//! non-zero) and marks the principal that may cancel / override anything. (The width is fully
//! encapsulated here and in the session's two accessors, so widening to `u128` later — at the cost
//! of an `AtomicU64` pair, since std has no `AtomicU128` — is a localized change.)

use std::collections::HashMap;

/// A set of roles as a 64-bit mask — one bit per role. Used both for a method's *required* roles
/// and a session's *granted* roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct RoleMask(u64);

impl RoleMask {
    /// The empty set — a method with no required roles is open to any authenticated caller.
    pub const NONE: RoleMask = RoleMask(0);

    /// Full administrator: every role (all bits set). Satisfies any gate, and is the marker for
    /// "may cancel / override anything".
    pub const FULL_ADMIN: RoleMask = RoleMask(u64::MAX);

    /// The raw bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// A mask from raw bits.
    pub const fn from_bits(bits: u64) -> RoleMask {
        RoleMask(bits)
    }

    /// Whether this is the empty set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether this granted set satisfies `required`: every required role is granted
    /// (`required ⊆ granted`, subset / AND semantics). An empty requirement is satisfied by anyone,
    /// and `FULL_ADMIN` (all-ones) satisfies every requirement — both fall out of the subset test.
    pub const fn satisfies(self, required: RoleMask) -> bool {
        (self.0 & required.0) == required.0
    }

    /// Whether this is the [`FULL_ADMIN`](RoleMask::FULL_ADMIN) set (all bits).
    pub const fn is_full_admin(self) -> bool {
        self.0 == u64::MAX
    }

    /// The union of two sets (used to expand role hierarchy when granting at `sessionSetup`).
    #[must_use]
    pub const fn union(self, other: RoleMask) -> RoleMask {
        RoleMask(self.0 | other.0)
    }
}

/// Interns role **names** to bits so a method's declared roles and a session's granted roles share
/// one numbering. Build it once from the canonical role list and share it (clone the handle) between
/// the protocol builder (which interns each method's `required` mask at build) and the auth layer
/// (which interns a session's `granted` mask at `sessionSetup`).
#[derive(Clone, Debug, Default)]
pub struct Roles {
    bit: HashMap<String, u8>,
}

impl Roles {
    /// Build a registry from the canonical, ordered role names — name `i` takes bit `i`.
    ///
    /// # Panics
    /// If more than 64 distinct roles are supplied (the `u64` mask holds at most 64).
    pub fn new<I, T>(names: I) -> Roles
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let mut bit = HashMap::new();
        for name in names {
            let next = bit.len();
            assert!(next < 64, "a RoleMask holds at most 64 roles");
            bit.entry(name.into()).or_insert(next as u8);
        }
        Roles { bit }
    }

    /// The single-bit mask for `name`, or `None` if the name isn't registered.
    pub fn get(&self, name: &str) -> Option<RoleMask> {
        self.bit.get(name).map(|&i| RoleMask(1u64 << i))
    }

    /// The union mask for `names`, or `Err(unknown_name)` if any name isn't registered.
    pub fn mask<I, T>(&self, names: I) -> Result<RoleMask, String>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let mut m = 0u64;
        for name in names {
            match self.bit.get(name.as_ref()) {
                Some(&i) => m |= 1u64 << i,
                None => return Err(name.as_ref().to_string()),
            }
        }
        Ok(RoleMask(m))
    }
}
