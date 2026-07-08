//! [`DaemonError`] — the error type returned by building and running a [`Daemon`](crate::Daemon).

use std::io;

/// An error from configuring or running a [`Daemon`](crate::Daemon).
///
/// Lifecycle hooks, the config mapping (`.parse`/`.load_config`), and the `services` closure all
/// return `Result<_, DaemonError>`. A `?` on a [`truenas_ros::Error`] (from a `ConfigFile` getter) or
/// a [`std::io::Error`] converts into this type, so a `.parse` closure and a hook can use `?` freely;
/// [`DaemonError::msg`] is the escape hatch for a free-form rejection message.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DaemonError {
    /// Reading or parsing the INI configuration failed (propagated from `truenas_ros`).
    #[error("config: {0}")]
    Config(#[from] truenas_ros::Error),

    /// A free-form failure with a message — used by config mappings and hooks that reject with a
    /// reason rather than an underlying error. Construct with [`DaemonError::msg`].
    #[error("{0}")]
    Message(String),

    /// Binding a listener failed. The first field is the transport label (e.g. `unix:/run/x.sock`).
    #[error("bind {0}: {1}")]
    Bind(String, #[source] io::Error),

    /// An underlying I/O error (blocking signals, creating the signalfd, building the runtime).
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl DaemonError {
    /// A free-form error carrying `message` — for a config mapping or hook that fails with a reason
    /// rather than an underlying [`std::io::Error`] or [`truenas_ros::Error`].
    pub fn msg(message: impl Into<String>) -> Self {
        DaemonError::Message(message.into())
    }
}
