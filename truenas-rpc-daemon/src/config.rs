//! Config loading: a single internal `loader` closure underlies configuration. `config_path(s)` +
//! `parse` compose into it (read the INI files into a [`ConfigFile`], then map to `C`); `load_config`
//! sets it directly. `SIGHUP` re-runs the loader and, on success, publishes the new snapshot.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::watch;
use truenas_ros::configfile::ConfigFile;

use crate::error::DaemonError;

/// The type-erased configuration loader: read the sources and produce a fresh `C`.
pub(crate) type Loader<C> = Arc<dyn Fn() -> Result<C, DaemonError> + Send + Sync>;

/// Compose INI `paths` + a `parse` mapping into a [`Loader`]: on each call, read the paths into a
/// [`ConfigFile`] (missing files are skipped, like `configparser.read([...])`) then map to `C`.
pub(crate) fn ini_loader<C, F>(paths: Vec<PathBuf>, parse: F) -> Loader<C>
where
    C: 'static,
    F: Fn(&ConfigFile) -> Result<C, DaemonError> + Send + Sync + 'static,
{
    Arc::new(move || {
        let mut cfg = ConfigFile::new();
        cfg.read_paths(paths.iter().cloned())?;
        parse(&cfg)
    })
}

/// Re-run `loader` and, on success, publish the new snapshot through `tx`. On failure the previous
/// snapshot is left in place (the error is returned for the caller to log) — a bad `SIGHUP` never
/// takes the service down.
pub(crate) fn reload<C>(loader: &Loader<C>, tx: &watch::Sender<Arc<C>>) -> Result<(), DaemonError> {
    let next = loader()?;
    let _ = tx.send(Arc::new(next));
    Ok(())
}
