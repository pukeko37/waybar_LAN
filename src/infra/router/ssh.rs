//! SSH execution against the OpenWrt router's dispatcher whitelist.
//!
//! The router's `andrew` account has no shell — every SSH session is forced
//! through a dispatcher script that only executes an exact-string command
//! whitelist (see the `router-integration` decision and `ssh-setup-notes`
//! in the project wiki). This module sends exactly one of those literal
//! alias strings per call; it never constructs an arbitrary command line.

use anyhow::{Context, Result};
use std::process::Command;

/// Runs one dispatcher-whitelisted command on the router over SSH.
///
/// `host` is `user@host` (e.g. `andrew@192.168.1.1`); `command` is one of
/// the dispatcher's literal whitelist strings (`leases`, `neigh`,
/// `wg-dump`, `wg-peers`, `clients`).
///
/// Only the `ssh` exit code determines success or failure. Every
/// invocation emits a PQ-key-exchange advisory to stderr regardless of
/// outcome (local `ssh`-client noise, unrelated to the router) — stderr
/// content must never be treated as a failure signal.
pub fn run_dispatch_command(host: &str, command: &str) -> Result<String> {
    let output = Command::new("ssh")
        .arg(host)
        .arg(command)
        .output()
        .with_context(|| format!("Failed to execute ssh for router command '{command}'"))?;

    if !output.status.success() {
        anyhow::bail!(
            "Router command '{command}' failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
