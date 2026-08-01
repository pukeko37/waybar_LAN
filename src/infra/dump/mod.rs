//! `--dump-devices` diagnostic feature: dumps raw network collection data
//! to JSON files for analysis. Not behind a port trait — invoked directly
//! from the composition root, same as any other concrete `infra` module.

use crate::domain;
use crate::infra::network::RawNetworkData;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Dump raw network data to JSON file for analysis
pub fn dump_raw_network_data(
    raw_data: &RawNetworkData,
    dump_dir: &Path,
    sanitize: bool,
) -> Result<()> {
    // Create dump directory if it doesn't exist
    fs::create_dir_all(dump_dir)
        .context(format!("Failed to create dump directory: {}", dump_dir.display()))?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let data_to_dump = if sanitize {
        sanitize_raw_data(raw_data)
    } else {
        raw_data.clone()
    };

    // Write single comprehensive JSON file
    let filename = format!("raw_network_data_{}.json", timestamp);
    let filepath = dump_dir.join(&filename);

    let json = serde_json::to_string_pretty(&data_to_dump)?;
    fs::write(&filepath, json)
        .context(format!("Failed to write raw data dump to {}", filepath.display()))?;

    write_summary(dump_dir, &data_to_dump, &filename, timestamp, sanitize)?;

    eprintln!("✓ Dumped raw network data to {}/{}", dump_dir.display(), filename);
    eprintln!("  {} neighbor entries, {} mDNS IPs",
        data_to_dump.neighbor_table_raw.len(),
        data_to_dump.mdns_services.len()
    );

    Ok(())
}

/// Produce an anonymized copy of raw network data: IPs, MACs, and resolved
/// hostnames are replaced with consistent placeholders.
fn sanitize_raw_data(raw_data: &RawNetworkData) -> RawNetworkData {
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
    sanitized.mdns_services = std::mem::take(&mut sanitized.mdns_services)
        .into_iter()
        .filter_map(|(ip, services)| {
            ip_map.get(&ip).map(|anon_ip| (*anon_ip, services))
        })
        .collect();

    // Sanitize DNS lookups (remap IPs, sanitize hostnames)
    sanitized.dns_lookups = std::mem::take(&mut sanitized.dns_lookups)
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
}

/// Write a human-readable summary alongside the JSON dump.
fn write_summary(
    dump_dir: &Path,
    data_to_dump: &RawNetworkData,
    filename: &str,
    timestamp: u64,
    sanitize: bool,
) -> Result<()> {
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

    Ok(())
}
