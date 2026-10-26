//! Links the host-built cb-mpc prefix from `scripts/build-cbmpc.sh`. The prefix
//! must name the pinned sources and blind-signing patch, and still hold the
//! libraries it recorded.
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

const CBMPC_COMMIT: &str = "0b716706f998633912ee2be9b9bf8909aed66088";
const OPENSSL: &str = "3.6.4 9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef";
const PATCH: &str = "cbmpc-blind-sign.patch";

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    println!("cargo:rerun-if-env-changed=ZARK_CBMPC_PREFIX");
    let prefix = env::var_os("ZARK_CBMPC_PREFIX")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../../work/cbmpc"));
    let info_path = prefix.join("BUILD-INFO");
    println!("cargo:rerun-if-changed={}", info_path.display());
    let info = fs::read_to_string(&info_path).unwrap_or_else(|_| {
        panic!(
            "missing {}; run scripts/build-cbmpc.sh",
            info_path.display()
        )
    });
    let patch_path = manifest.join("../../../scripts").join(PATCH);
    println!("cargo:rerun-if-changed={}", patch_path.display());
    let patch = hex::encode(Sha256::digest(fs::read(&patch_path).expect("cb-mpc patch")));
    let lines: Vec<&str> = info.lines().collect();
    assert!(
        lines.first() == Some(&format!("cb-mpc {CBMPC_COMMIT}").as_str())
            && lines.get(1) == Some(&format!("openssl {OPENSSL}").as_str())
            && lines.get(2) == Some(&format!("patch {PATCH} {patch}").as_str()),
        "cb-mpc prefix was not built from the pinned sources and patch; rerun scripts/build-cbmpc.sh"
    );
    for library in ["libcbmpc.a", "libcrypto.a"] {
        let path = prefix.join("lib").join(library);
        println!("cargo:rerun-if-changed={}", path.display());
        let digest = hex::encode(Sha256::digest(fs::read(&path).expect("cb-mpc library")));
        assert!(
            lines
                .iter()
                .any(|line| *line == format!("{digest}  {library}")),
            "{library} differs from BUILD-INFO; rerun scripts/build-cbmpc.sh"
        );
    }
    println!(
        "cargo:rustc-link-search=native={}",
        prefix.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=cbmpc");
    println!("cargo:rustc-link-lib=static=crypto");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=dylib=c++");
        println!("cargo:rustc-link-lib=framework=CoreServices");
        println!("cargo:rustc-link-lib=framework=IOKit");
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }
}
