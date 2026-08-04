//! LAN monitoring application with domain-driven design and type safety.
//! Monitors devices on the local network and outputs JSON for Waybar.
//!
//! This file is the composition root: it constructs concrete adapters and
//! delegates to the application layer.

use anyhow::Result;
use std::path::PathBuf;
use waybar_lan::app::{merge_network_and_router, NetworkFetcher, NetworkFormatter, RouterFetcher, RouterSnapshot};
use waybar_lan::infra::display::WaybarFormatter;
use waybar_lan::infra::dump;
use waybar_lan::infra::network::{history, NetworkCollector};
use waybar_lan::infra::router::SshRouterFetcher;

/// Configuration parsed from command line arguments
struct Config {
    /// Optional directory to dump device data to JSON files
    dump_dir: Option<PathBuf>,
    /// Whether to sanitize IPs and MACs when dumping
    sanitize: bool,
}

impl Config {
    /// Parse configuration from command line arguments
    fn from_args() -> Result<Self> {
        let args: Vec<String> = std::env::args().collect();
        let mut dump_dir = None;
        let mut sanitize = false;
        let mut i = 1; // Skip program name

        while i < args.len() {
            match args[i].as_str() {
                "--dump-devices" => {
                    i += 1;
                    if i >= args.len() {
                        anyhow::bail!("--dump-devices requires a directory path argument");
                    }
                    dump_dir = Some(PathBuf::from(&args[i]));
                }
                "--sanitize" => {
                    sanitize = true;
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                arg => {
                    anyhow::bail!("Unknown argument: {}\nUse --help for usage information", arg);
                }
            }
            i += 1;
        }

        Ok(Self { dump_dir, sanitize })
    }
}

/// Print help message
fn print_help() {
    println!("waybar_lan - LAN network monitor for Waybar");
    println!();
    println!("USAGE:");
    println!("    waybar_lan [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --dump-devices <DIR>   Dump discovered device data to JSON files in DIR");
    println!("    --sanitize             Sanitize IPs and MACs when dumping (use with --dump-devices)");
    println!("    -h, --help             Print this help message");
    println!();
    println!("ENVIRONMENT:");
    println!("    WAYBAR_LAN_ROUTER      user@host for an OpenWrt router to merge as a second");
    println!("                           device source (e.g. andrew@192.168.1.1). Unset by");
    println!("                           default: no router fetch is attempted.");
    println!();
    println!("EXAMPLES:");
    println!("    waybar_lan                                    # Normal operation");
    println!("    waybar_lan --dump-devices /tmp/devices        # Dump device data");
    println!("    waybar_lan --dump-devices /tmp --sanitize     # Dump with anonymized data");
}

fn main() -> Result<()> {
    let config = Config::from_args()?;
    let collector = NetworkCollector::new()?;
    let formatter = WaybarFormatter::new();

    // If dumping, collect raw data and exit
    if let Some(dump_dir) = &config.dump_dir {
        let raw_data = collector.collect_raw_network_data()?;
        dump::dump_raw_network_data(&raw_data, dump_dir, config.sanitize)?;
        return Ok(());
    }

    // Normal operation: exponential backoff for device discovery
    let retry_delays_secs = [1u64, 2, 4, 8];
    let total_attempts = retry_delays_secs.len() + 1;

    let network_data = std::iter::once(None)
        .chain(retry_delays_secs.iter().map(|&delay| Some(delay)))
        .enumerate()
        .find_map(|(attempt, delay_option)| {
            // Sleep before retry attempts (not before initial attempt)
            if let Some(delay_secs) = delay_option {
                std::thread::sleep(std::time::Duration::from_secs(delay_secs));
            }

            match collector.collect() {
                // Success with devices found - return immediately
                Ok(data) if !data.devices.is_empty() => Some(Ok(data)),

                // Last attempt - return even if no devices
                Ok(data) if attempt == total_attempts - 1 => Some(Ok(data)),

                // No devices yet - continue retrying
                Ok(_) => None,

                // Error - fail immediately without retrying
                Err(e) => Some(Err(e)),
            }
        })
        .unwrap_or_else(|| {
            // Safety: Should never reach here as last attempt always returns Some
            // Include fallback for absolute safety
            collector.collect()
        });

    // Router presence is binary: unset WAYBAR_LAN_ROUTER means no SSH is
    // attempted; set-but-unreachable is a full collection failure, not a
    // silent fallback to local-only data. The merge/history step below
    // always runs regardless of router presence — per
    // [[device-recency-and-removal]], that's what makes the persisted
    // last-observed/`Removed` treatment apply uniformly to every source,
    // not just to router users.
    let history_path = history::default_path();
    let loaded_history = history_path.as_deref().map(history::load).unwrap_or_default();

    let network_data = network_data.and_then(|data| {
        let router_snapshot = match std::env::var("WAYBAR_LAN_ROUTER") {
            Ok(host) => SshRouterFetcher::new(host).collect()?,
            Err(_) => RouterSnapshot::default(),
        };
        Ok(merge_network_and_router(data, router_snapshot, &loaded_history))
    });

    // Every path from here to stdout funnels through create_error_output on
    // failure — formatting and JSON-serialization errors get the same
    // "always emit valid JSON" treatment collection errors already had.
    // Config::from_args()'s own failure (a misconfigured Waybar exec line,
    // not a runtime condition) deliberately still exits loudly instead —
    // see [[main-module-rules]].
    let output_json = network_data
        .and_then(|(data, updated_history)| {
            if let Some(path) = &history_path {
                // Best-effort: a failed write shouldn't block the widget
                // from rendering output it has already computed.
                let _ = history::save(path, &updated_history);
            }
            formatter.format(&data)
        })
        .map_or_else(
            |e| serde_json::to_string(&WaybarFormatter::create_error_output(e)),
            |output| serde_json::to_string(&output),
        );

    // Safety: if even the error payload fails to serialize, something is
    // badly wrong beyond what create_error_output can express — fall back
    // to a hardcoded literal rather than propagate and break the "always
    // valid JSON" contract on the very last line able to honour it.
    println!(
        "{}",
        output_json.unwrap_or_else(|_| r#"{"text":"🖧 error","tooltip":"internal error"}"#.to_string())
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_handling_flow() {
        let error = anyhow::anyhow!("Test error");
        let error_output = WaybarFormatter::create_error_output(error);

        assert!(error_output.text.contains("unavailable"));
        assert!(error_output.tooltip.contains("Test error"));

        // Validate JSON serialization
        let json = serde_json::to_string(&error_output).unwrap();
        assert!(json.contains("text"));
        assert!(json.contains("tooltip"));
    }
}
