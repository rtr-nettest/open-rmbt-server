// Resolve the version embedded in the binary at build time.
//
// The version reported by the server (greeting string, logs, `--version`,
// structured events) is not hardcoded in the source. Both the greeting and the
// package version fall back to "0.0.0-dev" (see Cargo.toml) and are overwritten
// here with the current git tag, so a release binary reports the tag it was
// built from.
//
// Resolution order:
//   1. `RMBTD_VERSION` env var — set by CI from the release tag (deterministic,
//      also works when building from a source tarball without a `.git`).
//   2. `git describe --tags` — the nearest tag for local/tagged builds.
//   3. `CARGO_PKG_VERSION` ("0.0.0-dev") — the hardcoded fallback.
//
// A single leading `v` is stripped (tags are `v1.7.0`) so the greeting reads
// `RMBTv1.7.0`, not `RMBTvv1.7.0`.

use std::process::Command;

fn main() {
    let version = env_override()
        .or_else(git_describe)
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    let version = version.strip_prefix('v').unwrap_or(&version);

    println!("cargo:rustc-env=RMBTD_VERSION={version}");

    // Rebuild when the tag or the override changes.
    println!("cargo:rerun-if-env-changed=RMBTD_VERSION");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
}

/// An explicit `RMBTD_VERSION` set in the build environment, if non-empty.
fn env_override() -> Option<String> {
    std::env::var("RMBTD_VERSION")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The nearest git tag via `git describe --tags`, if git and a tag are present.
fn git_describe() -> Option<String> {
    let out = Command::new("git")
        .args(["describe", "--tags", "--dirty"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!v.is_empty()).then_some(v)
}
