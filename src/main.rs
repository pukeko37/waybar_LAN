//! LAN monitoring application with domain-driven design and type safety.
//! Monitors devices on the local network and outputs JSON for Waybar.
//!
//! This file is the composition root: it constructs concrete adapters and
//! delegates to the application layer.

use anyhow::Result;
use std::path::PathBuf;
use waybar_lan::app::{NetworkFetcher, NetworkFormatter};
use waybar_lan::infra::display::WaybarFormatter;
use waybar_lan::infra::dump;
use waybar_lan::infra::network::NetworkCollector;

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

    match network_data {
        Ok(data) => {
            let output = formatter.format(&data)?;
            println!("{}", serde_json::to_string(&output)?);
        }
        Err(e) => {
            let error_output = WaybarFormatter::create_error_output(e);
            println!("{}", serde_json::to_string(&error_output)?);
        }
    }

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
