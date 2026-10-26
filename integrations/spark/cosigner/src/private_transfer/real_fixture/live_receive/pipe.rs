//! Test process plumbing, separate from both native and blind signer policies.
use super::*;
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command as ProcessCommand, Stdio},
};
pub(super) struct Pipe {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    log: fs::File,
}
impl Pipe {
    pub fn native(docker: &Path, log: &Path) -> Result<Self> {
        let tool = helper_path("zark-ordinary-receive");
        let mut command = ProcessCommand::new(docker);
        command.args([
            "exec",
            "-i",
            "--user",
            "regtest",
            "-w",
            "/src/open-ssp/vendor/spark/spark",
            "zark-spark-regtest",
            "env",
            "ZARK_SPARK_ORDINARY_RECEIVE_FIXTURE=1",
            &tool,
            "-test.run=^TestOrdinaryReceiveNativeFixture$",
            "-test.v",
            "-test.timeout=1h",
        ]);
        Self::spawn(command, log)
    }
    pub fn sdk(docker: &Path, transfer: &str, log: &Path) -> Result<Self> {
        let tool = helper_path("zark-sdk-receive");
        let mut command = ProcessCommand::new(docker);
        command.args([
            "exec",
            "-i",
            "--user",
            "regtest",
            "zark-spark-regtest",
            &tool,
            "/src/open-ssp/.regtest/zark-spark-acceptance/native",
            transfer,
        ]);
        Self::spawn(command, log)
    }
    /// Stock single-key send after a verified share release; the wallet
    /// answers its two port requests and fixes the transfer ID.
    pub fn sdk_send(docker: &Path, log: &Path) -> Result<Self> {
        let tool = helper_path("zark-sdk-send");
        let mut command = ProcessCommand::new(docker);
        command.args([
            "exec",
            "-i",
            "--user",
            "regtest",
            "zark-spark-regtest",
            &tool,
            "/src/open-ssp/.regtest/zark-spark-acceptance/native",
        ]);
        Self::spawn(command, log)
    }
    fn spawn(mut command: ProcessCommand, path: &Path) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let log = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(log.try_clone()?)
            .spawn()?;
        Ok(Self {
            input: child.stdin.take().context("fixture stdin missing")?,
            output: BufReader::new(child.stdout.take().context("fixture stdout missing")?),
            child,
            log,
        })
    }
    pub fn send(&mut self, value: &Value) -> Result<()> {
        serde_json::to_writer(&mut self.input, value)?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        Ok(())
    }
    pub fn next(&mut self, prefix: Option<&str>) -> Result<Value> {
        loop {
            let mut line = String::new();
            let count = (&mut self.output).take(1024 * 1024).read_line(&mut line)?;
            ensure!(
                count > 0 && count < 1024 * 1024,
                "fixture stopped or response exceeded bound; inspect retained log"
            );
            if let Some(prefix) = prefix {
                if let Some(raw) = line.strip_prefix(prefix) {
                    return Ok(serde_json::from_str(raw)?);
                }
                self.log.write_all(line.as_bytes())?;
            } else {
                return Ok(serde_json::from_str(&line)?);
            }
        }
    }
    pub fn call_native(&mut self, value: &Value) -> Result<Value> {
        self.send(value)?;
        let reply = self.next(Some("ZARK_FIXTURE_REPLY "))?;
        ensure!(reply["ok"] == true, "native fixture rejected request");
        Ok(reply["value"].clone())
    }
    pub fn completed(&mut self) -> Result<()> {
        let status = self.child.wait()?;
        ensure!(
            status.success(),
            "SDK driver process failed; inspect retained log"
        );
        Ok(())
    }
}

/// Helpers built inside the container by `integrations/spark/sdk/build.py`.
fn helper_path(name: &str) -> String {
    format!("/src/open-ssp/.regtest/native-tools/{name}")
}
impl Drop for Pipe {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl crate::native_observation::NativeObservationSource for Pipe {
    fn completed_leaf(
        &mut self,
        query: &crate::native_observation::LeafQuery<'_>,
    ) -> Result<Value> {
        self.call_native(&json!({"op":"observe","directory":NATIVE,
            "transfer_id":query.transfer,"leaf_id":query.leaf,"receiver":query.receiver}))
    }
}
