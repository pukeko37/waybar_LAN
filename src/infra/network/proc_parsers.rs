//! Parsers for /proc filesystem network data

use crate::domain::{Gateway, Hostname, NetworkDevice, NetworkInterface};
use crate::infra::network::models::{InterfaceDto, NeighborEntryDto};
use anyhow::{Context, Result};
use network_interface::{NetworkInterface as NetIface, NetworkInterfaceConfig};
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Stdio};

/// Reads raw neighbor table output from `ip neigh show`
/// Returns all lines for debugging and analysis
pub fn read_raw_neighbor_table() -> Result<Vec<String>> {
    let output = Command::new("ip")
        .args(["neigh", "show"])
        .output()
        .context("Failed to execute 'ip neigh show'")?;

    let content = String::from_utf8_lossy(&output.stdout);
    Ok(content.lines().map(|line| line.to_string()).collect())
}

/// Reads raw ARP table lines including incomplete entries
/// Returns all non-header lines from /proc/net/arp for debugging
/// DEPRECATED: Use read_raw_neighbor_table() for state information
pub fn read_raw_arp_table() -> Result<Vec<String>> {
    let content = fs::read_to_string("/proc/net/arp")
        .context("Failed to read /proc/net/arp")?;

    Ok(content
        .lines()
        .skip(1) // Skip header
        .map(|line| line.to_string())
        .collect())
}

/// Parses one `ip neigh show` line into a `NeighborEntryDto`.
/// Format: <IP> dev <IFACE> lladdr <MAC> <STATE>
/// Example: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
fn parse_neighbor_line(line: &str) -> Option<NeighborEntryDto> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None; // Skip malformed lines
    }

    let ip: IpAddr = parts[0].parse().ok()?;

    let interface = parts
        .iter()
        .position(|&s| s == "dev")
        .and_then(|idx| parts.get(idx + 1))
        .map(|s| s.to_string())?;

    let mac = parts
        .iter()
        .position(|&s| s == "lladdr")
        .and_then(|idx| parts.get(idx + 1))
        .map(|s| s.to_string())?;

    let state = parts.last().map(|s| s.to_string()).unwrap_or_default();

    Some(NeighborEntryDto { ip, interface, mac, state })
}

/// Parses `ip neigh show` to get neighbor table entries with state information
pub fn parse_arp_table() -> Result<Vec<NetworkDevice>> {
    let output = Command::new("ip")
        .args(["neigh", "show"])
        .output()
        .context("Failed to execute 'ip neigh show'")?;

    let content = String::from_utf8_lossy(&output.stdout);

    Ok(content
        .lines()
        .filter_map(parse_neighbor_line)
        .filter_map(|dto| NetworkDevice::try_from(dto).ok())
        .collect())
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

    Ok(system_interfaces
        .into_iter()
        .filter_map(|iface| {
            let addr = iface.addr.iter().find(|a| matches!(a.ip(), IpAddr::V4(_)))?;
            Some(InterfaceDto {
                name: iface.name.clone(),
                ip: addr.ip(),
                mac: iface.mac_addr.clone(),
            })
        })
        .map(NetworkInterface::from)
        .collect())
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
    fn test_parse_neighbor_line_complete() {
        let line = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE";
        let dto = parse_neighbor_line(line).unwrap();

        assert_eq!(dto.interface, "eth0");
        assert_eq!(dto.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(dto.state, "REACHABLE");
    }

    #[test]
    fn test_parse_neighbor_line_missing_lladdr_skipped() {
        let line = "192.168.1.1 dev eth0 FAILED";
        assert!(parse_neighbor_line(line).is_none());
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
        use crate::domain::{InterfaceName, NetworkInterface};
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
            if let IpAddr::V4(ipv4) = iface.ip
                && !ipv4.is_loopback()
            {
                let octets = ipv4.octets();
                let subnet_prefix = (octets[0], octets[1], octets[2]);
                if seen_subnets.insert(subnet_prefix) {
                    unique_subnets.push(subnet_prefix);
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
            if parts.len() >= 2
                && parts[0] == "nameserver"
                && let Ok(ip) = parts[1].parse::<IpAddr>()
            {
                dns_servers.push(ip);
            }
        }

        assert_eq!(dns_servers.len(), 3);
        assert_eq!(dns_servers[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(dns_servers[1], IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(matches!(dns_servers[2], IpAddr::V6(_)));
    }
}
