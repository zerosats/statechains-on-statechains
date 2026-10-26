//! A launching process may lower its soft descriptor limit after opening a
//! higher descriptor. Exercised in an isolated subprocess, never by changing
//! resource limits in the multi-threaded test runner itself.
use super::*;
use std::{
    fs::{self, File},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const TEST: &str = "verifier_process::descriptor_tests::lowered_soft_limit_still_closes_high_descriptors_and_retains_lock";
const MARKER: &str = "SC_VERIFIER_DESCRIPTOR_TEST";

fn set_soft_limit(soft: libc::rlim_t) -> Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0,
        "read test descriptor limit"
    );
    limit.rlim_cur = soft;
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } == 0,
        "set test descriptor limit"
    );
    Ok(())
}

#[test]
fn lowered_soft_limit_still_closes_high_descriptors_and_retains_lock() -> Result<()> {
    match std::env::var(MARKER).as_deref() {
        Ok("verify") => {
            let private: i32 = std::env::var("SC_PRIVATE_FD")?.parse()?;
            let lock: i32 = std::env::var("SC_LOCK_FD")?.parse()?;
            ensure!(
                unsafe { libc::fcntl(private, libc::F_GETFD) } == -1,
                "high descriptor reached the verifier"
            );
            ensure!(
                unsafe { libc::fcntl(lock, libc::F_GETFD) } >= 0,
                "operation lock lost"
            );
            return Ok(());
        }
        Ok("prepare") => {}
        _ => {
            ensure!(
                Command::new(std::env::current_exe()?)
                    .args(["--exact", TEST])
                    .env(MARKER, "prepare")
                    .status()?
                    .success(),
                "descriptor fixture failed"
            );
            return Ok(());
        }
    }
    set_soft_limit(16384)?;
    let file = File::open("/dev/null")?;
    // F_DUPFD intentionally omits CLOEXEC, modelling a library-created handle.
    let high = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 9000) };
    ensure!(high >= 9000, "duplicate test descriptor");
    let high = unsafe { OwnedFd::from_raw_fd(high) };
    set_soft_limit(8192)?;
    let dir = std::env::temp_dir().join(format!(
        "verifier-descriptors-{}",
        hex::encode(crate::random32())
    ));
    fs::create_dir(&dir)?;
    let result = (|| {
        let _lock = crate::local::ProcessLock::acquire(&dir.join("operation.lock"))?;
        let mut command = Command::new(std::env::current_exe()?);
        command.args(["--exact", TEST]);
        restrict(&mut command)?;
        command
            .env(MARKER, "verify")
            .env("SC_PRIVATE_FD", high.as_raw_fd().to_string())
            .env(
                "SC_LOCK_FD",
                crate::local::operation_lock_fd()
                    .context("test operation lock")?
                    .to_string(),
            );
        let mut child = Process::spawn(&mut command)?;
        let _ = child.enforce_runtime_limits()?;
        ensure!(
            child.0.wait()?.success(),
            "verifier descriptor check failed"
        );
        Ok(())
    })();
    fs::remove_dir_all(dir)?;
    result
}
