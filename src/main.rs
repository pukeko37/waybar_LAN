//! LAN monitoring application with domain-driven design and type safety.
//! Monitors devices on the local network and outputs JSON for Waybar.

#![allow(clippy::upper_case_acronyms)] // NAS is standard industry acronym

mod data;
mod display;
mod domain;

use anyhow::{Context, Result};
use data::{NetworkCollector, RawNetworkData};
use display::WaybarFormatter;
use std::path::PathBuf;

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

/// Dump raw network data to JSON file for analysis
fn dump_raw_network_data(
    raw_data: &RawNetworkData,
    dump_dir: &std::path::Path,
    sanitize: bool,
) -> Result<()> {
    use std::fs;
    use std::collections::HashMap;

    // Create dump directory if it doesn't exist
    fs::create_dir_all(dump_dir)
        .context(format!("Failed to create dump directory: {}", dump_dir.display()))?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let data_to_dump = if sanitize {
        // Create sanitized version
        let mut sanitized = raw_data.clone();

        // Create IP mapping for consistent anonymization
        let ip_map: HashMap<std::net::IpAddr, std::net::IpAddr> = sanitized
            .mdns_services
            .keys()
            .chain(sanitized.dns_lookups.keys())
            .enumerate()
            .map(|(i, ip)| {
                let anon_ip = match ip {
                    std::net::IpAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, i as u8 + 1)),
                    std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, i as u16 + 1)),
                };
                (*ip, anon_ip)
            })
            .collect();

        // Sanitize neighbor table lines (replace IPs and MACs)
        // Format: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        sanitized.neighbor_table_raw = sanitized
            .neighbor_table_raw
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Find lladdr position and replace MAC
                let mac_replacement = format!("00:00:00:00:00:{:02X}", i);
                let ip_replacement = format!("10.0.0.{}", i + 1);

                let new_parts: Vec<String> = parts.iter().enumerate().map(|(idx, &part)| {
                    if idx == 0 {
                        // First part is IP
                        ip_replacement.clone()
                    } else if idx > 0 && parts.get(idx - 1) == Some(&"lladdr") {
                        // Part after "lladdr" is MAC
                        mac_replacement.clone()
                    } else {
                        part.to_string()
                    }
                }).collect();

                new_parts.join(" ")
            })
            .collect();

        // Sanitize ARP table lines (replace IPs and MACs)
        sanitized.arp_table_raw = sanitized
            .arp_table_raw
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    format!(
                        "10.0.0.{:<15} {} {} 00:00:00:00:00:{:02X} {} {}",
                        i + 1, parts[1], parts[2], i, parts[4], parts[5]
                    )
                } else {
                    line.clone()
                }
            })
            .collect();

        // Sanitize mDNS services (remap IPs)
        sanitized.mdns_services = sanitized
            .mdns_services
            .into_iter()
            .filter_map(|(ip, services)| {
                ip_map.get(&ip).map(|anon_ip| (*anon_ip, services))
            })
            .collect();

        // Sanitize DNS lookups (remap IPs, sanitize hostnames)
        sanitized.dns_lookups = sanitized
            .dns_lookups
            .into_iter()
            .enumerate()
            .filter_map(|(i, (ip, hostname))| {
                let sanitized_hostname = match hostname {
                    domain::Hostname::Resolved(_) => domain::Hostname::Resolved(format!("device-{}", i)),
                    other => other,
                };
                ip_map.get(&ip).map(|anon_ip| (*anon_ip, sanitized_hostname))
            })
            .collect();

        sanitized
    } else {
        raw_data.clone()
    };

    // Write single comprehensive JSON file
    let filename = format!("raw_network_data_{}.json", timestamp);
    let filepath = dump_dir.join(&filename);

    let json = serde_json::to_string_pretty(&data_to_dump)?;
    fs::write(&filepath, json)
        .context(format!("Failed to write raw data dump to {}", filepath.display()))?;

    // Write summary
    let summary_path = dump_dir.join(format!("summary_{}.txt", timestamp));
    let summary = format!(
        "Raw Network Data Dump Summary\n\
         ==============================\n\
         Timestamp: {}\n\
         Neighbor table entries: {}\n\
         ARP entries (legacy): {}\n\
         mDNS services: {} IPs\n\
         DNS lookups: {}\n\
         Interfaces: {}\n\
         Sanitized: {}\n\
         \n\
         Main file: {}\n\
         \n\
         This dump contains ALL raw collection data including:\n\
         - Neighbor table with state (REACHABLE/STALE/etc)\n\
         - Legacy ARP table (including incomplete/stale entries)\n\
         - All mDNS service discoveries\n\
         - All DNS lookup results\n\
         \n\
         Use this data to analyze device fingerprinting patterns.\n\
         Submit anonymized dumps to improve device classification!\n",
        timestamp,
        data_to_dump.neighbor_table_raw.len(),
        data_to_dump.arp_table_raw.len(),
        data_to_dump.mdns_services.len(),
        data_to_dump.dns_lookups.len(),
        data_to_dump.interfaces.len(),
        if sanitize { "yes" } else { "no" },
        filename
    );

    fs::write(&summary_path, summary)
        .context(format!("Failed to write summary to {}", summary_path.display()))?;

    eprintln!("✓ Dumped raw network data to {}/{}", dump_dir.display(), filename);
    eprintln!("  {} neighbor entries, {} mDNS IPs",
        data_to_dump.neighbor_table_raw.len(),
        data_to_dump.mdns_services.len()
    );

    Ok(())
}

fn main() -> Result<()> {
    let config = Config::from_args()?;
    let collector = NetworkCollector::new()?;
    let formatter = WaybarFormatter::new();

    // If dumping, collect raw data and exit
    if let Some(dump_dir) = &config.dump_dir {
        let raw_data = collector.collect_raw_network_data()?;
        dump_raw_network_data(&raw_data, dump_dir, config.sanitize)?;
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

            match collector.collect_network_info() {
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
            collector.collect_network_info()
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
mod integration_tests {
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
