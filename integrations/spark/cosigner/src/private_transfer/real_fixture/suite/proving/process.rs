//! Restricted fixture tools: bounded workers, inherited lock and process cleanup.
use anyhow::{Context, Result, ensure};
use std::{
    fs, io,
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use zark_protocol::timing::{Phase, Span};

const WALL_SECONDS: u32 = 3600;
/// The explicit fixture holds a few engines, connections and tools at a time,
/// far below this bound.
const DESCRIPTORS: libc::rlim_t = 8192;

/// Node-based launchers raise the inherited soft descriptor limit to about a
/// million on macOS. Every fixture tool launch below, and every signer verifier
/// launch in this test process, scans that namespace before exec (~200 ms each).
/// Only lower the soft limit; keep the hard and any lower operator limit.
/// Existing higher descriptors stay open, so launches still scan /dev/fd too;
/// a launch racing this call keeps its longer, already-computed scan.
/// Failure retains the previous full scan.
pub(in super::super) fn bound_descriptor_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit/setrlimit only access the local rlimit value.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 && limit.rlim_cur > DESCRIPTORS {
            limit.rlim_cur = DESCRIPTORS;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}

pub(super) struct Running(pub(super) Child);
impl Drop for Running {
    fn drop(&mut self) {
        // SAFETY: prepare creates a fresh process group for this owned child.
        // Kill descendants too, including after the direct child has exited.
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
        let _ = self.0.wait();
    }
}

pub(super) fn prepare(
    command: &mut Command,
    directory: &Path,
    workers: u16,
    fast_msm: bool,
) -> Result<()> {
    ensure!((1..=8).contains(&workers), "Spark prover worker bound");
    let home = std::env::var_os("HOME").context("real-proof dependency cache home")?;
    let descriptors = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    ensure!(
        descriptors > 0 && descriptors <= i32::MAX as _,
        "Spark prover descriptor limit"
    );
    // Lowering a soft limit does not close already-open descriptors above it.
    let mut descriptor_end = descriptors as i32;
    for entry in fs::read_dir("/dev/fd").context("inspect inherited Spark prover descriptors")? {
        if let Some(fd) = entry?
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        {
            descriptor_end = descriptor_end.max(fd.saturating_add(1));
        }
    }
    command
        .current_dir(directory)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", directory)
        .env("HARDWARE_CONCURRENCY", workers.to_string())
        .env("BB_HARDWARE_CONCURRENCY", workers.to_string())
        .env("RAYON_NUM_THREADS", workers.to_string())
        .env("OMP_NUM_THREADS", workers.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Presence selects the backend. Never pass through ambient experimental
    // flags or set this to "0", which would still select the accelerated path.
    if fast_msm {
        command.env("BB_MSM_NEW", "1");
    }
    // Use only async-signal-safe operations between fork and exec. Private
    // wallet/network descriptors must not reach a witness executor or prover.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o077);
            for fd in 3..descriptor_end {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EBADF) {
                        return Err(error);
                    }
                } else if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::signal(libc::SIGALRM, libc::SIG_DFL) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
            if libc::sigemptyset(signals.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut signals = signals.assume_init();
            if libc::sigaddset(&mut signals, libc::SIGALRM) != 0
                || libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::alarm(WALL_SECONDS);
            for (resource, max) in [
                (libc::RLIMIT_CORE, 0u64),
                (libc::RLIMIT_CPU, WALL_SECONDS as u64),
                (libc::RLIMIT_FSIZE, 1024 * 1024 * 1024),
            ] {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(resource, &mut limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
                limit.rlim_cur = limit.rlim_cur.min(max as _);
                limit.rlim_max = limit.rlim_max.min(max as _);
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // Register after descriptor cleanup so any active caller operation lock is
    // deliberately inherited. Its lifetime must also cover a surviving child.
    zark_protocol::local::inherit_operation_lock(command);
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
#[path = "process_tests.rs"]
mod tests;

pub(super) fn run(
    command: &mut Command,
    directory: &Path,
    label: &str,
    workers: u16,
    fast_msm: bool,
) -> Result<Duration> {
    let log = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(format!("{label}.log")))?;
    prepare(command, directory, workers, fast_msm)?;
    command.stdout(log.try_clone()?).stderr(log);
    let started = Instant::now();
    eprintln!("Real Spark ownership {label}: {}", directory.display());
    let mut child = {
        let _span = Span::new(Phase::ProverProcessSpawn);
        Running(
            command
                .spawn()
                .context("start explicit real-proof fixture tool")?,
        )
    };
    loop {
        if let Some(status) = child.0.try_wait()? {
            ensure!(
                status.success(),
                "real-proof {label} failed; inspect {}/{}.log",
                directory.display(),
                label
            );
            break;
        }
        ensure!(
            started.elapsed() < Duration::from_secs(WALL_SECONDS as u64),
            "real-proof fixture process deadline"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    eprintln!(
        "Real Spark ownership {label} completed in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    Ok(started.elapsed())
}
