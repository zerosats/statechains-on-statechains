//! Exercise descriptor bounds in isolated subprocesses, never by changing
//! resource limits in the multi-threaded test runner itself.
use super::*;
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
};

const PREFIX: &str = "private_transfer::real_fixture::suite::proving::process::tests::";
const MARKER: &str = "ZARK_TEST_SPARK_FIXTURE_DESCRIPTORS";

fn rerun(test: &str, mode: &str) -> Result<()> {
    ensure!(
        Command::new(std::env::current_exe()?)
            .args(["--exact", &format!("{PREFIX}{test}")])
            .env(MARKER, mode)
            .status()?
            .success(),
        "isolated descriptor fixture failed"
    );
    Ok(())
}

fn descriptor_limit() -> Result<libc::rlimit> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0,
        "read descriptor limit"
    );
    Ok(limit)
}

fn set_soft_limit(soft: libc::rlim_t) -> Result<libc::rlimit> {
    let mut limit = descriptor_limit()?;
    limit.rlim_cur = soft;
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } == 0,
        "set test descriptor limit"
    );
    Ok(limit)
}

#[test]
fn bound_preserves_lower_soft_limits_and_the_hard_limit() -> Result<()> {
    const TEST: &str = "bound_preserves_lower_soft_limits_and_the_hard_limit";
    if let Ok(soft) = std::env::var(MARKER) {
        let before = set_soft_limit(soft.parse()?)?;
        bound_descriptor_limit();
        let after = descriptor_limit()?;
        ensure!(
            after.rlim_cur == before.rlim_cur.min(DESCRIPTORS) && after.rlim_max == before.rlim_max,
            "fixture descriptor bound"
        );
        return Ok(());
    }
    for soft in ["512", "16384"] {
        rerun(TEST, soft)?;
    }
    Ok(())
}

#[test]
fn bounded_launch_still_closes_high_descriptors_and_retains_operation_lock() -> Result<()> {
    const TEST: &str = "bounded_launch_still_closes_high_descriptors_and_retains_operation_lock";
    match std::env::var(MARKER).as_deref() {
        Ok("verify") => {
            let private: i32 = std::env::var("ZARK_TEST_PRIVATE_FD")?.parse()?;
            let lock: i32 = std::env::var("ZARK_TEST_LOCK_FD")?.parse()?;
            ensure!(
                unsafe { libc::fcntl(private, libc::F_GETFD) } == -1,
                "high descriptor leaked"
            );
            ensure!(
                unsafe { libc::fcntl(lock, libc::F_GETFD) } >= 0,
                "operation lock lost"
            );
            ensure!(
                std::env::var_os("ZARK_TEST_CREDENTIAL").is_none(),
                "credential leaked"
            );
            return Ok(());
        }
        Ok("prepare") => {}
        _ => return rerun(TEST, "prepare"),
    }
    set_soft_limit(16384)?;
    let file = File::open("/dev/null")?;
    // F_DUPFD intentionally omits CLOEXEC, modelling a library-created handle.
    let high = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 9000) };
    ensure!(high >= 9000, "duplicate test descriptor");
    let high = unsafe { OwnedFd::from_raw_fd(high) };
    bound_descriptor_limit();
    ensure!(
        unsafe { libc::sysconf(libc::_SC_OPEN_MAX) } == DESCRIPTORS as libc::c_long,
        "fixture descriptor bound"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../work/spark-fixture-descriptor-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root)?;
    let result = (|| {
        let lock = root.join("operation.lock");
        let _guard = zark_protocol::local::ProcessLock::acquire(&lock)?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--exact", &format!("{PREFIX}{TEST}")])
            .env("ZARK_TEST_CREDENTIAL", "synthetic");
        prepare(&mut command, &root, 2, false)?;
        // Locate the guard without exposing its handle in the public API.
        let inode = fs::metadata(&lock)?.ino();
        let lock_fd = fs::read_dir("/dev/fd")?
            .filter_map(|entry| entry.ok())
            .find(|entry| fs::metadata(entry.path()).is_ok_and(|m| m.ino() == inode))
            .context("find test lock")?
            .file_name();
        command
            .env(MARKER, "verify")
            .env("ZARK_TEST_PRIVATE_FD", high.as_raw_fd().to_string())
            .env("ZARK_TEST_LOCK_FD", lock_fd)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let mut child = Running(command.spawn()?);
        ensure!(
            child.0.wait()?.success(),
            "restricted child descriptor check"
        );
        Ok(())
    })();
    fs::remove_dir_all(root)?;
    result
}
