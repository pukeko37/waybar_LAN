//! Parsers for /proc filesystem network data

use crate::domain::{Gateway, Hostname, InterfaceName, MacAddress, NetworkDevice, NetworkInterface};
use anyhow::{Context, Result};
use network_interface::{NetworkInterface as NetIface, NetworkInterfaceConfig};
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Stdio};

/// Parses /proc/net/arp to get neighbor table entries
/// Format: IP address  HW type  Flags  HW address  Mask  Device
/// Flag 0x2 = complete entry, 0x0 = incomplete
pub fn parse_arp_table() -> Result<Vec<NetworkDevice>> {
    let content = fs::read_to_string("/proc/net/arp")
        .context("Failed to read /proc/net/arp")?;

    let mut devices = Vec::new();

    for line in content.lines().skip(1) {
        // Skip header line
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue; // Skip malformed lines
        }

        // Parse flag to check if entry is complete
        let flags = parts[2];
        if flags != "0x2" {
            continue; // Skip incomplete entries
        }

        // Parse IP address
        let ip: IpAddr = match parts[0].parse() {
            Ok(ip) => ip,
            Err(_) => continue, // Skip invalid IPs
        };

        // Parse MAC address
        let mac_str = parts[3];
        let mac = match MacAddress::new(mac_str.to_string()) {
            Ok(mac) => mac,
            Err(_) => continue, // Skip invalid MACs
        };

        // Get interface name
        let interface_name = parts[5].to_string();

        devices.push(NetworkDevice::new(ip, mac, InterfaceName::new(interface_name)));
    }

    Ok(devices)
}

/// Parses /proc/net/route to find the default gateway
/// Format: Iface  Destination  Gateway  Flags  RefCnt  Use  Metric  Mask  MTU  Window  IRTT
/// Gateway is in hex, little-endian format
/// Destination 00000000 = default route
pub fn parse_default_gateway() -> Result<Option<Gateway>> {
    let content = fs::read_to_string("/proc/net/route")
        .context("Failed to read /proc/net/route")?;

    for line in content.lines().skip(1) {
        // Skip header line
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let destination = parts[1];
        let gateway_hex = parts[2];

        // Look for default route (destination = 00000000)
        if destination != "00000000" {
            continue;
        }

        // Parse hex gateway address (little-endian)
        if let Ok(ip) = parse_hex_ip(gateway_hex) {
            return Ok(Some(Gateway::new(IpAddr::V4(ip))));
        }
    }

    Ok(None)
}

/// Converts hex IP address from /proc/net/route to Ipv4Addr
/// Format is little-endian: 0101A8C0 = 192.168.1.1
fn parse_hex_ip(hex: &str) -> Result<Ipv4Addr> {
    if hex.len() != 8 {
        anyhow::bail!("Invalid hex IP length: {}", hex);
    }

    let value = u32::from_str_radix(hex, 16)
        .context("Invalid hex IP")?;

    // Convert from little-endian to octets
    let a = (value & 0xFF) as u8;
    let b = ((value >> 8) & 0xFF) as u8;
    let c = ((value >> 16) & 0xFF) as u8;
    let d = ((value >> 24) & 0xFF) as u8;

    Ok(Ipv4Addr::new(a, b, c, d))
}

/// Enumerates all network interfaces on the system
pub fn get_network_interfaces() -> Result<Vec<NetworkInterface>> {
    let system_interfaces = NetIface::show()
        .context("Failed to enumerate network interfaces")?;

    let mut interfaces = Vec::new();

    for iface in system_interfaces {
        // Get the first IPv4 address for each interface
        if let Some(addr) = iface.addr.iter().find(|a| matches!(a.ip(), IpAddr::V4(_))) {
            let ip = addr.ip();

            // Try to get MAC address
            let mac = iface.mac_addr
                .and_then(|mac_str| MacAddress::new(mac_str).ok());

            interfaces.push(NetworkInterface::new(
                InterfaceName::new(iface.name.clone()),
                ip,
                mac,
            ));
        }
    }

    Ok(interfaces)
}

/// Performs reverse DNS lookup for an IP address
/// Returns Hostname::Unknown if lookup fails or times out
pub fn reverse_dns_lookup(ip: &IpAddr) -> Hostname {
    // Use std::net's lookup_host which uses the system resolver
    // This can block, but it's simple and uses OS DNS cache
    match dns_lookup::lookup_addr(ip) {
        Ok(hostname) => Hostname::resolved(hostname),
        Err(_) => Hostname::Unknown,
    }
}

/// Parses /etc/resolv.conf to get DNS servers
/// Format: nameserver <IP address>
pub fn parse_dns_servers() -> Result<Vec<IpAddr>> {
    let content = fs::read_to_string("/etc/resolv.conf")
        .context("Failed to read /etc/resolv.conf")?;

    let mut dns_servers = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse nameserver lines
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "nameserver" && let Ok(ip) = parts[1].parse::<IpAddr>() {
            dns_servers.push(ip);
        }
    }

    Ok(dns_servers)
}

/// Generates all IPs in a /24 subnet from a base IP
/// Example: 192.168.1.50 -> [192.168.1.1 ... 192.168.1.254]
fn generate_subnet_ips(base_ip: &Ipv4Addr) -> Vec<Ipv4Addr> {
    let octets = base_ip.octets();
    (1..=254)
        .map(|last| Ipv4Addr::new(octets[0], octets[1], octets[2], last))
        .collect()
}

/// Performs parallel ping sweep of subnet to populate ARP table
/// Spawns concurrent ping processes for all IPs in the /24 subnet
/// Does not parse output - relies on kernel updating ARP table
/// Deduplicates subnets - only scans each unique /24 once
pub fn ping_sweep_subnet(interfaces: &[NetworkInterface]) -> Result<()> {
    // Track unique /24 subnets by first 3 octets to avoid duplicate scans
    let mut seen_subnets = HashSet::new();
    let mut subnets_to_scan = Vec::new();

    // Collect unique /24 subnets from all IPv4 interfaces
    for iface in interfaces {
        if let IpAddr::V4(ipv4) = iface.ip {
            // Skip loopback
            if ipv4.is_loopback() {
                continue;
            }

            // Extract /24 subnet prefix (first 3 octets)
            let octets = ipv4.octets();
            let subnet_prefix = (octets[0], octets[1], octets[2]);

            // Only add if we haven't seen this /24 subnet before
            if seen_subnets.insert(subnet_prefix) {
                subnets_to_scan.push(ipv4);
            }
        }
    }

    // For each unique subnet, spawn ping processes for all 254 IPs
    for base_ip in subnets_to_scan {
        let ips = generate_subnet_ips(&base_ip);

        for ip in ips {
            // Spawn ping process in background
            // -c 1: send 1 packet
            // -W 1: timeout 1 second
            // -q: quiet mode (no output)
            // We don't wait for completion - just spawn and let them populate ARP table
            let _ = Command::new("ping")
                .args(["-c", "1", "-W", "1", "-q", &ip.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            // Ignore errors - some IPs won't respond
        }
    }

    // Give pings a brief moment to start populating ARP table
    // This is a small delay to catch quick responses
    std::thread::sleep(std::time::Duration::from_millis(200));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_arp_line_complete() {
        let line = "192.168.1.50     0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0";
        let parts: Vec<&str> = line.split_whitespace().collect();

        assert_eq!(parts[0], "192.168.1.50");
        assert_eq!(parts[2], "0x2");
        assert_eq!(parts[3], "aa:bb:cc:dd:ee:ff");
        assert_eq!(parts[5], "eth0");
    }

    #[test]
    fn test_parse_arp_line_incomplete() {
        let line = "192.168.1.51     0x1         0x0         00:00:00:00:00:00     *        eth0";
        let parts: Vec<&str> = line.split_whitespace().collect();

        assert_eq!(parts[2], "0x0"); // Incomplete flag
    }

    #[test]
    fn test_mac_address_validation() {
        let valid_mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string());
        assert!(valid_mac.is_ok());

        let invalid_mac = MacAddress::new("00:00:00:00:00:00".to_string());
        assert!(invalid_mac.is_ok()); // Still valid format, just all zeros
    }

    #[test]
    fn test_parse_hex_ip() {
        // 0101A8C0 = 192.168.1.1 (little-endian)
        let ip = parse_hex_ip("0101A8C0").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));

        // 00000000 = 0.0.0.0
        let ip = parse_hex_ip("00000000").unwrap();
        assert_eq!(ip, Ipv4Addr::new(0, 0, 0, 0));

        // FE00A8C0 = 192.168.0.254
        let ip = parse_hex_ip("FE00A8C0").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 0, 254));
    }

    #[test]
    fn test_parse_hex_ip_invalid() {
        let result = parse_hex_ip("ZZZZ");
        assert!(result.is_err());

        let result = parse_hex_ip("01A8C0"); // Too short
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_route_line() {
        let line = "eno1\t00000000\t0101A8C0\t0003\t0\t0\t1002\t00000000\t0\t0\t0";
        let parts: Vec<&str> = line.split_whitespace().collect();

        assert_eq!(parts[1], "00000000"); // Default route
        assert_eq!(parts[2], "0101A8C0"); // Gateway hex
    }

    #[test]
    fn test_generate_subnet_ips() {
        let base_ip = Ipv4Addr::new(192, 168, 1, 100);
        let ips = generate_subnet_ips(&base_ip);

        assert_eq!(ips.len(), 254);
        assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ips[253], Ipv4Addr::new(192, 168, 1, 254));

        // Check we don't include 0 or 255
        assert!(!ips.contains(&Ipv4Addr::new(192, 168, 1, 0)));
        assert!(!ips.contains(&Ipv4Addr::new(192, 168, 1, 255)));
    }

    #[test]
    fn test_subnet_deduplication() {
        use crate::domain::NetworkInterface;
        use std::net::IpAddr;

        // Create two interfaces on the same /24 subnet
        let iface1 = NetworkInterface::new(
            InterfaceName::new("eth0".to_string()),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            None,
        );
        let iface2 = NetworkInterface::new(
            InterfaceName::new("wlan0".to_string()),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 150)),
            None,
        );
        let iface3 = NetworkInterface::new(
            InterfaceName::new("eth1".to_string()),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
            None,
        );

        let interfaces = vec![iface1, iface2, iface3];

        // Extract unique subnets using same logic as ping_sweep_subnet
        let mut seen_subnets = HashSet::new();
        let mut unique_subnets = Vec::new();

        for iface in &interfaces {
            if let IpAddr::V4(ipv4) = iface.ip {
                if !ipv4.is_loopback() {
                    let octets = ipv4.octets();
                    let subnet_prefix = (octets[0], octets[1], octets[2]);
                    if seen_subnets.insert(subnet_prefix) {
                        unique_subnets.push(subnet_prefix);
                    }
                }
            }
        }

        // Should only have 2 unique subnets: 192.168.1 and 10.0.0
        assert_eq!(unique_subnets.len(), 2);
        assert!(unique_subnets.contains(&(192, 168, 1)));
        assert!(unique_subnets.contains(&(10, 0, 0)));
    }

    #[test]
    fn test_parse_resolv_conf() {
        use std::net::{IpAddr, Ipv4Addr};

        // Simulate resolv.conf content
        let content = "# Generated by resolvconf\ndomain lan\nnameserver 192.168.1.1\nnameserver 8.8.8.8\nnameserver fd25:a234:e8f7::1\noptions edns0\n";

        let mut dns_servers = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[0] == "nameserver" {
                if let Ok(ip) = parts[1].parse::<IpAddr>() {
                    dns_servers.push(ip);
                }
            }
        }

        assert_eq!(dns_servers.len(), 3);
        assert_eq!(dns_servers[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(dns_servers[1], IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(matches!(dns_servers[2], IpAddr::V6(_)));
    }
}
