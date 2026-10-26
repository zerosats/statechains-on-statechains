//! Exit phase timing reported to the desktop runtime.
use super::*;

/// Fixed exit phase labels on stderr; no identifiers or payloads.
pub(super) fn timed<T>(phase: &str, run: impl FnOnce() -> Result<T>) -> Result<T> {
    let started = std::time::Instant::now();
    let out = run()?;
    eprintln!(
        "ZARK_EXIT_TIMING {{\"phase\":\"{phase}\",\"milliseconds\":{}}}",
        started.elapsed().as_millis()
    );
    Ok(out)
}
