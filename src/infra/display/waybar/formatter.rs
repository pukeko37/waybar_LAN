//! `WaybarFormatter`: assembles `WaybarOutput` from `NetworkData` — the
//! filtering, grouping, and tooltip-building logic that consumes the
//! presentation primitives in `format.rs`.

use super::format::{colorize, format_identity, format_utc_timestamp, signal_suffix, sub_indent, INDENT};
use crate::app::NetworkFormatter;
use crate::domain::{is_private_address, ActivityStatus, DeviceId, NetworkData, NetworkDevice};
use anyhow::Result;
use serde::Serialize;
use std::time::SystemTime;

/// Waybar output format
#[derive(Debug, Clone, Serialize)]
pub struct WaybarOutput {
    pub text: String,
    pub tooltip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage: Option<u8>,
}

/// Formats network data as Waybar JSON
pub struct WaybarFormatter;

impl WaybarFormatter {
    /// Creates a new WaybarFormatter instance
    pub fn new() -> Self {
        Self
    }

    /// Restricts the device list to private/ULA addresses, per
    /// [[private-address-only-display]]. Within each device, addresses
    /// failing `is_private_address` (public IPv4, IPv6 link-local, IPv6
    /// global unicast) are dropped from `addresses`; a device left with no
    /// addresses at all — typically the router's WAN-side neighbour,
    /// surfaced by `neigh` observations that span every router interface —
    /// is dropped entirely. Applied once, before either the device-count
    /// text or the tooltip is built, so the two never disagree.
    fn filter_to_private_devices(&self, devices: &[NetworkDevice]) -> Vec<NetworkDevice> {
        devices
            .iter()
            .filter_map(|device| {
                let addresses: Vec<_> = device
                    .addresses
                    .iter()
                    .filter(|a| is_private_address(&a.ip))
                    .cloned()
                    .collect();
                if addresses.is_empty() {
                    return None;
                }
                let mut device = device.clone();
                device.addresses = addresses;
                Some(device)
            })
            .collect()
    }

    /// Drops any device whose `activity_status()` is `Removed` — not seen
    /// (or, for WireGuard, never handshaked) within the last 24 hours, per
    /// [[device-recency-and-removal]]. No "recently removed" grace state:
    /// a `Removed` device is simply absent from the output, same treatment
    /// as `filter_to_private_devices` above.
    fn filter_to_active_devices(&self, devices: &[NetworkDevice]) -> Vec<NetworkDevice> {
        devices
            .iter()
            .filter(|device| device.activity_status() != ActivityStatus::Removed)
            .cloned()
            .collect()
    }

    /// Builds the tooltip: a brief preamble listing this host's own local
    /// interfaces (informational only, not a grouping mechanism — see
    /// [[flat-device-list-display]]), followed by a two-level device tree
    /// grouped by access path (see [[nested-tree-by-access-path]]), and a
    /// trailing "Updated:" timestamp footer (see [[updated-timestamp-footer]]).
    fn build_tooltip(&self, network_data: &NetworkData) -> String {
        let body = if network_data.interfaces.is_empty() {
            "No network interfaces found".to_string()
        } else {
            let mut lines: Vec<String> = network_data
                .interfaces
                .iter()
                .map(|interface| self.format_interface_header(interface))
                .collect();
            lines.push(String::new());

            if network_data.devices.is_empty() {
                lines.push("No devices".to_string());
            } else {
                let sorted_devices = self.sort_devices(&network_data.devices);
                let groups = self.group_devices_by_access_path(&sorted_devices);
                lines.extend(self.format_groups(&groups, network_data));
            }

            lines.join("\n").trim_end().to_string()
        };

        format!("{}\n\n🕐 Updated: {}", body, format_utc_timestamp(SystemTime::now()))
    }

    /// Format interface header line
    fn format_interface_header(&self, interface: &crate::domain::NetworkInterface) -> String {
        if let Some(mac) = &interface.mac {
            format!("{}: {} ({})", interface.name, interface.ip, mac)
        } else {
            format!("{}: {}", interface.name, interface.ip)
        }
    }

    /// Sort devices by primary address (IPv4-preferred).
    fn sort_devices<'a>(&self, devices: &'a [crate::domain::NetworkDevice])
        -> Vec<&'a crate::domain::NetworkDevice> {
        let mut sorted: Vec<&crate::domain::NetworkDevice> = devices.iter().collect();
        sorted.sort_by_key(|d| d.primary_address());
        sorted
    }

    /// Groups already-sorted devices by `access_path_annotation`'s value
    /// (`via Router` when `None` — per [[via-router-heading-rename]], every
    /// device landing here is known only from a router-reported record,
    /// never a live signal this poll), in first-appearance order — whichever
    /// group's first member appears earliest in `devices` is first in the
    /// returned list. Within each group, devices keep their existing
    /// relative order: a stable partition of `devices`, not a re-sort. Per
    /// [[nested-tree-by-access-path]].
    fn group_devices_by_access_path<'a>(&self, devices: &[&'a crate::domain::NetworkDevice])
        -> Vec<(String, Vec<&'a crate::domain::NetworkDevice>)> {
        let mut groups: Vec<(String, Vec<&crate::domain::NetworkDevice>)> = Vec::new();
        for &device in devices {
            let heading = self.access_path_annotation(device).unwrap_or_else(|| "via Router".to_string());
            match groups.iter_mut().find(|(existing, _)| existing == &heading) {
                Some((_, members)) => members.push(device),
                None => groups.push((heading, vec![device])),
            }
        }
        groups
    }

    /// Format every group as a flush-left heading line followed by its
    /// member devices, indented one `INDENT` step. Per
    /// [[wifi-signal-new-device-and-flat-layout]].
    fn format_groups(&self, groups: &[(String, Vec<&crate::domain::NetworkDevice>)],
        network_data: &NetworkData) -> Vec<String> {
        groups.iter().flat_map(|(heading, members)| self.format_group(heading, members, network_data)).collect()
    }

    /// Format one heading line and its nested member device rows.
    fn format_group(&self, heading: &str, members: &[&crate::domain::NetworkDevice],
        network_data: &NetworkData) -> Vec<String> {
        let mut lines = vec![heading.to_string()];
        lines.extend(members.iter().flat_map(|device| self.format_device_entry(device, network_data)));
        lines
    }

    /// Access path for a device — `via Wi-Fi` when tagged by a `clients`
    /// (assoclist) MAC match, `via eno1` when a `DeviceAddress` carries a
    /// local `interface_name`, `via WireGuard` when only a
    /// WireGuard-key-correlated address is known. No heuristic guessing
    /// beyond what the device's own fields state directly, per
    /// [[flat-device-list-display]]. Since [[nested-tree-by-access-path]],
    /// this value becomes a group heading rather than inline per-row text.
    /// `on_wifi` is checked first: per [[device-recency-and-removal]], it
    /// shouldn't collide with the other two in practice (`interface_name`
    /// only ever comes from a *locally* observed address, `clients` only
    /// ever tags router-sourced devices), but takes precedence if a future
    /// source ever makes more than one true for the same device.
    fn access_path_annotation(&self, device: &crate::domain::NetworkDevice) -> Option<String> {
        if device.on_wifi {
            return Some("via Wi-Fi".to_string());
        }
        if let Some(name) = device.addresses.iter().find_map(|a| a.interface_name.as_ref()) {
            return Some(format!("via {}", name));
        }
        if matches!(device.id, DeviceId::WireGuardKey(_)) {
            return Some("via WireGuard".to_string());
        }
        None
    }

    /// Format a single device entry with its services and gateway info,
    /// indented one `INDENT` step under its group heading. The line ends
    /// with, in order: the primary address parenthetical, the new-device
    /// star marker, then the Wi-Fi signal-strength suffix — per
    /// [[wifi-signal-icon-at-line-end]], the signal glyph sits last on the
    /// line rather than prepended before the device-type icon.
    fn format_device_entry(&self, device: &crate::domain::NetworkDevice,
        network_data: &NetworkData) -> Vec<String> {
        let mut lines = Vec::new();

        // Main device line
        let display_name = format_identity(&device.identity);
        let colored_name = colorize(device.activity_status(), &display_name);
        let new_marker = if device.is_newly_observed() { " <span color='#00FF00'>★</span>" } else { "" };
        let signal = signal_suffix(device.wifi_signal);
        lines.push(format!("{INDENT}{colored_name} ({}){new_marker}{signal}", device.primary_address()));

        // Services
        if let Some(services_line) = self.format_services(device) {
            lines.push(services_line);
        }

        // Gateway/DNS info
        lines.extend(self.format_gateway_info(device, network_data));

        lines
    }

    /// Format services list for a device
    fn format_services(&self, device: &crate::domain::NetworkDevice) -> Option<String> {
        if device.services.is_empty() {
            return None;
        }

        let mut unique_services: Vec<String> = device.services
            .iter()
            .map(|s| s.friendly_type().to_string())
            .collect();
        unique_services.sort();
        unique_services.dedup();

        if unique_services.is_empty() {
            None
        } else {
            Some(format!("{}Services: {}", sub_indent(), unique_services.join(", ")))
        }
    }

    /// Format gateway and DNS information for a device
    fn format_gateway_info(&self, device: &crate::domain::NetworkDevice,
        network_data: &NetworkData) -> Vec<String> {
        use std::net::IpAddr;

        let Some(gateway) = network_data.gateway else { return Vec::new() };
        if !device.addresses.iter().any(|a| a.ip == gateway.0) {
            return Vec::new();
        }

        let mut lines = Vec::new();
        let info_prefix = sub_indent();

        // Gateway label
        let dns_matches_gateway = network_data.dns_servers.iter().any(|dns| dns == &gateway.0);
        if dns_matches_gateway {
            lines.push(format!("{}Gateway (also DNS)", info_prefix));
        } else {
            lines.push(format!("{}Gateway", info_prefix));
        }

        // WAN address, per [[wan-ip-display]]
        if let Some(wan_address) = network_data.wan_address {
            lines.push(format!("{}WAN: {}", info_prefix, wan_address));
        }

        // Additional DNS servers
        let other_dns: Vec<&IpAddr> = network_data.dns_servers
            .iter()
            .filter(|dns| *dns != &gateway.0)
            .collect();

        if !other_dns.is_empty() {
            let dns_list: Vec<String> = other_dns
                .iter()
                .map(|dns| self.format_dns_entry(dns))
                .collect();
            lines.push(format!("{}DNS: {}", info_prefix, dns_list.join(", ")));
        }

        lines
    }

    /// Format a single DNS entry with local/external label. "Local" means
    /// private/ULA, via `domain::is_private_address` — the same predicate
    /// [[private-address-only-display]] uses for device filtering, replacing
    /// this method's previous IPv4-only octet check (which mislabelled every
    /// IPv6 DNS server "external" regardless of whether it was actually a
    /// ULA address).
    fn format_dns_entry(&self, dns: &std::net::IpAddr) -> String {
        if is_private_address(dns) {
            format!("{} (local)", dns)
        } else {
            format!("{} (external)", dns)
        }
    }

    /// Creates error output for Waybar
    pub fn create_error_output(error: anyhow::Error) -> WaybarOutput {
        WaybarOutput {
            text: "🖧 -- Network unavailable".to_string(),
            tooltip: format!("Unable to fetch network data\n\nError: {}", error),
            alt: Some("error".to_string()),
            class: Some(vec!["error".to_string()]),
            percentage: None,
        }
    }
}

impl NetworkFormatter for WaybarFormatter {
    type Output = WaybarOutput;

    /// Formats network data for Waybar display
    fn format(&self, network_data: &NetworkData) -> Result<WaybarOutput> {
        let mut network_data = network_data.clone();
        network_data.devices = self.filter_to_private_devices(&network_data.devices);
        network_data.devices = self.filter_to_active_devices(&network_data.devices);
        let network_data = &network_data;

        let device_count = network_data.devices.len();

        // Main text: device count
        let text = if device_count == 0 {
            "🖧 No devices".to_string()
        } else if device_count == 1 {
            "🖧 1 device".to_string()
        } else {
            format!("🖧 {} devices", device_count)
        };

        // Build tooltip with tree structure
        let tooltip = self.build_tooltip(network_data);

        // CSS classes based on state
        let classes = if device_count > 0 {
            vec!["network".to_string(), "active".to_string()]
        } else {
            vec!["network".to_string()]
        };

        Ok(WaybarOutput {
            text,
            tooltip,
            alt: Some("network".to_string()),
            class: Some(classes),
            percentage: None,
        })
    }
}

impl Default for WaybarFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Gateway, MacAddress, NetworkDevice, NetworkInterface, SignalStrength};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_formatter_creation() {
        let _formatter = WaybarFormatter::new();
    }

    #[test]
    fn test_error_output() {
        let error = anyhow::anyhow!("Test error");
        let output = WaybarFormatter::create_error_output(error);

        assert!(output.text.contains("unavailable"));
        assert!(output.tooltip.contains("Test error"));
        assert_eq!(output.alt, Some("error".to_string()));
    }

    #[test]
    fn test_format_empty_network() {
        let formatter = WaybarFormatter::new();
        let data = NetworkData::new(vec![], vec![], None, vec![]);
        let output = formatter.format(&data).unwrap();

        assert_eq!(output.text, "🖧 No devices");
        assert!(!output.tooltip.is_empty());
    }

    fn local_device(ip: IpAddr, mac: MacAddress, interface: &str) -> NetworkDevice {
        let address = crate::domain::DeviceAddress {
            ip,
            interface_name: Some(crate::domain::InterfaceName::new(interface.to_string())),
            neighbor_state: crate::domain::NeighborState::Unknown,
        };
        NetworkDevice::new(crate::domain::DeviceId::Mac(mac.clone()), vec![address], Some(mac))
    }

    #[test]
    fn test_format_with_devices() {
        let formatter = WaybarFormatter::new();

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let gateway_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mac1 = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let mac2 = MacAddress::new("11:22:33:44:55:66".to_string()).unwrap();
        let mac3 = MacAddress::new("00:11:22:33:44:55".to_string()).unwrap();

        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eth0".to_string()), ip1, Some(mac1.clone()));
        let device = local_device(ip2, mac2, "eth0");
        let router = local_device(gateway_ip, mac3, "eth0").build_identity(); // Build identity so it shows as "Router"

        let gateway = Gateway::new(gateway_ip);

        let data = NetworkData::new(vec![interface], vec![router, device], Some(gateway), vec![]);
        let output = formatter.format(&data).unwrap();

        assert_eq!(output.text, "🖧 2 devices");
        assert!(output.tooltip.contains("eth0"));
        assert!(output.tooltip.contains("192.168.1.50"));
        assert!(output.tooltip.contains("192.168.1.1"));
        assert!(output.tooltip.contains("Gateway"));
    }

    #[test]
    fn test_format_annotates_device_with_local_interface() {
        let formatter = WaybarFormatter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eth0".to_string()), ip, Some(mac.clone()));
        let device = local_device(ip, mac, "eth0");

        let data = NetworkData::new(vec![interface], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        assert!(output.tooltip.contains("via eth0"));
    }

    #[test]
    fn test_format_renders_router_only_device_annotated_via_wireguard() {
        let formatter = WaybarFormatter::new();
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let local_mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eth0".to_string()), local_ip, Some(local_mac.clone()));
        let local = local_device(local_ip, local_mac, "eth0");

        // A WireGuard peer with no local presence: no mac, no interface_name,
        // identified only by its WireGuard public key.
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let key = crate::domain::WireGuardPublicKey::new("pubkey123".to_string());
        let peer_address = crate::domain::DeviceAddress { ip: peer_ip, interface_name: None, neighbor_state: crate::domain::NeighborState::Unknown };
        let peer = NetworkDevice::new(crate::domain::DeviceId::WireGuardKey(key), vec![peer_address], None);

        let data = NetworkData::new(vec![interface], vec![local, peer], None, vec![]);
        let output = formatter.format(&data).unwrap();

        assert_eq!(output.text, "🖧 2 devices");
        assert!(output.tooltip.contains("10.20.30.3"));
        assert!(output.tooltip.contains("via WireGuard"));
    }

    #[test]
    fn test_format_drops_never_handshaked_wireguard_device() {
        // Regression test for the bug motivating [[device-recency-and-removal]]:
        // a never-handshaked WireGuard peer must not appear in the tooltip
        // or device count at all, not merely render grey.
        let formatter = WaybarFormatter::new();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let key = crate::domain::WireGuardPublicKey::new("pubkey123".to_string());
        let peer_address = crate::domain::DeviceAddress { ip: peer_ip, interface_name: None, neighbor_state: crate::domain::NeighborState::Unknown };
        let mut peer = NetworkDevice::new(crate::domain::DeviceId::WireGuardKey(key.clone()), vec![peer_address], None);
        peer.wireguard_activity = crate::domain::WireGuardActivity::Never(key);

        let data = NetworkData::new(vec![], vec![peer], None, vec![]);
        let output = formatter.format(&data).unwrap();

        assert_eq!(output.text, "🖧 No devices");
        assert!(!output.tooltip.contains("10.20.30.3"));
    }

    #[test]
    fn test_format_groups_wifi_tagged_device_under_via_wifi() {
        let formatter = WaybarFormatter::new();
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let local_mac = MacAddress::new("11:22:33:44:55:66".to_string()).unwrap();
        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eth0".to_string()), local_ip, Some(local_mac));

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 77));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let address = crate::domain::DeviceAddress { ip, interface_name: None, neighbor_state: crate::domain::NeighborState::Unknown };
        let mut device = NetworkDevice::new(crate::domain::DeviceId::Mac(mac.clone()), vec![address], Some(mac));
        device.on_wifi = true;

        let data = NetworkData::new(vec![interface], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        assert!(output.tooltip.contains("via Wi-Fi"));
    }

    #[test]
    fn test_format_collapses_dual_homed_device_to_one_tooltip_row() {
        let formatter = WaybarFormatter::new();
        let lan_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let wg_ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();

        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eth0".to_string()), lan_ip, Some(mac.clone()));
        let addresses = vec![
            crate::domain::DeviceAddress { ip: lan_ip, interface_name: Some(crate::domain::InterfaceName::new("eth0".to_string())), neighbor_state: crate::domain::NeighborState::Unknown },
            crate::domain::DeviceAddress { ip: wg_ip, interface_name: None, neighbor_state: crate::domain::NeighborState::Unknown },
        ];
        let device = NetworkDevice::new(crate::domain::DeviceId::Mac(mac.clone()), addresses, Some(mac));

        let data = NetworkData::new(vec![interface], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        // One device, one device row nested under one group heading — not
        // two rows for the two addresses. Per
        // [[wifi-signal-new-device-and-flat-layout]] a device row is any
        // line starting with exactly one INDENT step (not two, which would
        // be a Services/Gateway sub-line).
        assert_eq!(output.text, "🖧 1 device");
        let device_row_count = output
            .tooltip
            .lines()
            .filter(|l| l.starts_with(INDENT) && !l.starts_with(&format!("{INDENT}{INDENT}")))
            .count();
        assert_eq!(device_row_count, 1);
    }

    #[test]
    fn test_format_drops_device_with_only_public_address() {
        // The router's WAN-side neighbour: a real, identified device (has a
        // MAC) but not a LAN device — per [[private-address-only-display]]
        // it must not appear at all, not even in the device count.
        let formatter = WaybarFormatter::new();
        let public_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let address = crate::domain::DeviceAddress { ip: public_ip, interface_name: None, neighbor_state: crate::domain::NeighborState::Unknown };
        let device = NetworkDevice::new(crate::domain::DeviceId::Mac(mac.clone()), vec![address], Some(mac));

        let data = NetworkData::new(vec![], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        assert_eq!(output.text, "🖧 No devices");
        assert!(!output.tooltip.contains("203.0.113.7"));
    }

    #[test]
    fn test_format_hides_public_address_but_keeps_multi_homed_device() {
        let formatter = WaybarFormatter::new();
        let private_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let public_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let addresses = vec![
            crate::domain::DeviceAddress { ip: private_ip, interface_name: Some(crate::domain::InterfaceName::new("eth0".to_string())), neighbor_state: crate::domain::NeighborState::Unknown },
            crate::domain::DeviceAddress { ip: public_ip, interface_name: None, neighbor_state: crate::domain::NeighborState::Unknown },
        ];
        let device = NetworkDevice::new(crate::domain::DeviceId::Mac(mac.clone()), addresses, Some(mac));

        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eth0".to_string()), private_ip, None);
        let data = NetworkData::new(vec![interface], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        assert_eq!(output.text, "🖧 1 device");
        assert!(output.tooltip.contains("192.168.1.50"));
        assert!(!output.tooltip.contains("203.0.113.7"));
    }

    #[test]
    fn test_format_hides_ipv6_link_local_address() {
        let formatter = WaybarFormatter::new();
        let link_local: IpAddr = "fe80::1".parse().unwrap();
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let address = crate::domain::DeviceAddress { ip: link_local, interface_name: None, neighbor_state: crate::domain::NeighborState::Unknown };
        let device = NetworkDevice::new(crate::domain::DeviceId::Mac(mac.clone()), vec![address], Some(mac));

        let data = NetworkData::new(vec![], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        assert_eq!(output.text, "🖧 No devices");
    }

    #[test]
    fn test_format_gateway_info_includes_wan_address() {
        let formatter = WaybarFormatter::new();
        let gateway_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mac = MacAddress::new("00:11:22:33:44:55".to_string()).unwrap();
        let address = crate::domain::DeviceAddress { ip: gateway_ip, interface_name: Some(crate::domain::InterfaceName::new("eth0".to_string())), neighbor_state: crate::domain::NeighborState::Unknown };
        let router = NetworkDevice::new(crate::domain::DeviceId::Mac(mac.clone()), vec![address], Some(mac)).build_identity();

        let wan_address = crate::domain::WanAddress::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eth0".to_string()), gateway_ip, None);
        let data = NetworkData::new(vec![interface], vec![router], Some(Gateway::new(gateway_ip)), vec![])
            .with_wan_address(wan_address);
        let output = formatter.format(&data).unwrap();

        assert!(output.tooltip.contains("Gateway"));
        assert!(output.tooltip.contains("WAN: 203.0.113.7"));
    }

    #[test]
    fn test_format_dns_entry_labels_ipv6_ula_as_local() {
        let formatter = WaybarFormatter::new();
        let ula: IpAddr = "fd25:a234:e8f7::1".parse().unwrap();
        assert_eq!(formatter.format_dns_entry(&ula), "fd25:a234:e8f7::1 (local)");
    }

    #[test]
    fn test_format_dns_entry_labels_public_ipv6_as_external() {
        let formatter = WaybarFormatter::new();
        let public: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(formatter.format_dns_entry(&public), "2001:db8::1 (external)");
    }

    #[test]
    fn test_tooltip_ends_with_updated_footer() {
        let formatter = WaybarFormatter::new();
        let data = NetworkData::new(vec![], vec![], None, vec![]);
        let output = formatter.format(&data).unwrap();

        assert!(output.tooltip.contains("\n\n🕐 Updated: "));
        assert!(output.tooltip.ends_with('Z'));
    }

    #[test]
    fn test_tooltip_groups_devices_by_access_path_with_via_router_bucket() {
        let formatter = WaybarFormatter::new();

        let eno1_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let eno1_mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let eno1_device = local_device(eno1_ip, eno1_mac, "eno1");

        let wg_ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let wg_key = crate::domain::WireGuardPublicKey::new("pubkey123".to_string());
        let wg_address = crate::domain::DeviceAddress { ip: wg_ip, interface_name: None, neighbor_state: crate::domain::NeighborState::Unknown };
        let wg_device = NetworkDevice::new(crate::domain::DeviceId::WireGuardKey(wg_key), vec![wg_address], None);

        // No local interface_name and not WireGuard-keyed: falls into "via Router".
        let other_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let other_mac = MacAddress::new("11:22:33:44:55:66".to_string()).unwrap();
        let other_address = crate::domain::DeviceAddress { ip: other_ip, interface_name: None, neighbor_state: crate::domain::NeighborState::Unknown };
        let other_device = NetworkDevice::new(crate::domain::DeviceId::Mac(other_mac.clone()), vec![other_address], Some(other_mac));

        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eno1".to_string()), eno1_ip, None);
        let data = NetworkData::new(vec![interface], vec![eno1_device, wg_device, other_device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        assert!(output.tooltip.contains("via eno1"));
        assert!(output.tooltip.contains("via WireGuard"));
        assert!(output.tooltip.contains("via Router"));
        // Group order is first-appearance order in the address-sorted device
        // list: 10.20.30.3 (WireGuard) < 192.168.1.50 (eno1) < 192.168.1.200
        // (via Router) numerically, so that's the expected heading order.
        let wg_pos = output.tooltip.find("via WireGuard").unwrap();
        let eno1_pos = output.tooltip.find("via eno1").unwrap();
        let other_pos = output.tooltip.find("via Router").unwrap();
        assert!(wg_pos < eno1_pos);
        assert!(eno1_pos < other_pos);
    }

    #[test]
    fn test_device_row_nests_under_group_heading() {
        let formatter = WaybarFormatter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eno1".to_string()), ip, Some(mac.clone()));
        let device = local_device(ip, mac, "eno1");

        let data = NetworkData::new(vec![interface], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        // Heading flush left, device row indented one INDENT step deeper.
        assert!(output.tooltip.lines().any(|l| l == "via eno1"));
        assert!(output.tooltip.lines().any(|l| l.starts_with(INDENT) && !l.starts_with("via")));
        // The inline "via eno1" annotation is gone from the device row itself
        // (only the heading states it) — the device row's own parenthesised
        // location is just the address.
        assert!(output.tooltip.contains(&format!("({})", ip)));
    }

    #[test]
    fn test_services_sub_line_indents_one_step_deeper_than_device_row() {
        let formatter = WaybarFormatter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eno1".to_string()), ip, Some(mac.clone()));
        let mut device = local_device(ip, mac, "eno1");
        device.services.push(crate::domain::ServiceInfo::new(
            crate::domain::ServiceType::new("_ssh._tcp.local.".to_string()),
            crate::domain::ServiceInstanceName::new("my-nas".to_string()),
            22,
        ));

        let data = NetworkData::new(vec![interface], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        let services_line = output.tooltip.lines().find(|l| l.contains("Services:")).unwrap();
        assert!(services_line.starts_with(&format!("{INDENT}{INDENT}")));
        // Not a third INDENT step — exactly one deeper than the device row.
        assert!(!services_line.starts_with(&format!("{INDENT}{INDENT}{INDENT}")));
    }

    #[test]
    fn test_no_tree_glyphs_remain_in_tooltip() {
        let formatter = WaybarFormatter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eno1".to_string()), ip, Some(mac.clone()));
        let device = local_device(ip, mac, "eno1");

        let data = NetworkData::new(vec![interface], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        assert!(!output.tooltip.contains('├'));
        assert!(!output.tooltip.contains('└'));
        assert!(!output.tooltip.contains('│'));
    }

    #[test]
    fn test_wifi_device_gets_signal_suffix_at_line_end_non_wifi_gets_none() {
        // Per [[wifi-signal-icon-at-line-end]]: the signal glyph now trails
        // the device line entirely rather than prepending a fixed-width
        // column before the device-type icon — every row's INDENT + icon
        // starts at the same position regardless of Wi-Fi status, and a
        // non-Wi-Fi row carries no signal-related content at all.
        let formatter = WaybarFormatter::new();

        let wifi_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 77));
        let wifi_mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let mut wifi_device = NetworkDevice::new(
            crate::domain::DeviceId::Mac(wifi_mac.clone()),
            vec![crate::domain::DeviceAddress {
                ip: wifi_ip,
                interface_name: None,
                neighbor_state: crate::domain::NeighborState::Unknown,
            }],
            Some(wifi_mac),
        );
        wifi_device.on_wifi = true;
        wifi_device.wifi_signal = Some(SignalStrength::from_snr_db(35));

        let wired_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let wired_mac = MacAddress::new("11:22:33:44:55:66".to_string()).unwrap();
        let wired_device = local_device(wired_ip, wired_mac.clone(), "eno1");
        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eno1".to_string()), wired_ip, Some(wired_mac));

        let data = NetworkData::new(vec![interface], vec![wifi_device, wired_device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        // Match on "(ip)" specifically, not a bare ip — the interface
        // preamble line also contains the wired IP, but never parenthesised.
        let wifi_row = output.tooltip.lines().find(|l| l.contains(&format!("({wifi_ip})"))).unwrap();
        let wired_row = output.tooltip.lines().find(|l| l.contains(&format!("({wired_ip})"))).unwrap();

        assert!(wifi_row.ends_with(" █"));
        assert!(!wired_row.contains('█'));

        // Neither row carries a leading signal-glyph column any more — both
        // start with exactly INDENT and nothing variable-width ahead of the
        // device-type icon, which is what actually fixes the alignment bug
        // [[wifi-signal-icon-at-line-end]] was written for.
        assert!(wifi_row.starts_with(INDENT));
        assert!(wired_row.starts_with(INDENT));
        for glyph in ['▂', '▄', '▆', '█'] {
            assert!(!wifi_row[INDENT.len()..].starts_with(glyph));
            assert!(!wired_row[INDENT.len()..].starts_with(glyph));
        }
    }

    #[test]
    fn test_newly_observed_device_gets_green_star_before_signal_suffix_at_line_end() {
        let formatter = WaybarFormatter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 77));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eno1".to_string()), ip, Some(mac.clone()));
        let mut device = NetworkDevice::new(
            crate::domain::DeviceId::Mac(mac.clone()),
            vec![crate::domain::DeviceAddress {
                ip,
                interface_name: None,
                neighbor_state: crate::domain::NeighborState::Unknown,
            }],
            Some(mac),
        );
        device.on_wifi = true;
        device.wifi_signal = Some(SignalStrength::from_snr_db(35));
        device.first_observed = Some(std::time::SystemTime::now() - std::time::Duration::from_secs(3600));

        let data = NetworkData::new(vec![interface], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        let device_row = output.tooltip.lines().find(|l| l.contains(&format!("({ip})"))).unwrap();
        // Star comes before the signal suffix — the signal glyph is the
        // true last thing on the line.
        assert!(device_row.ends_with("★</span> █"));
    }

    #[test]
    fn test_newly_observed_device_gets_green_star_appended_at_line_end() {
        let formatter = WaybarFormatter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eno1".to_string()), ip, Some(mac.clone()));
        let mut device = local_device(ip, mac, "eno1");
        device.first_observed = Some(std::time::SystemTime::now() - std::time::Duration::from_secs(3600));

        let data = NetworkData::new(vec![interface], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        let device_row = output.tooltip.lines().find(|l| l.contains(&format!("({ip})"))).unwrap();
        assert!(device_row.ends_with("★</span>"));
        assert!(device_row.contains("#00FF00"));
    }

    #[test]
    fn test_device_over_24h_old_gets_no_star() {
        let formatter = WaybarFormatter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eno1".to_string()), ip, Some(mac.clone()));
        let mut device = local_device(ip, mac, "eno1");
        device.first_observed = Some(std::time::SystemTime::now() - std::time::Duration::from_secs(86401));

        let data = NetworkData::new(vec![interface], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        let device_row = output.tooltip.lines().find(|l| l.contains(&format!("({ip})"))).unwrap();
        assert!(!device_row.contains('★'));
    }

    #[test]
    fn test_device_with_no_first_observed_gets_no_star() {
        let formatter = WaybarFormatter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eno1".to_string()), ip, Some(mac.clone()));
        let device = local_device(ip, mac, "eno1"); // first_observed left at its None default

        let data = NetworkData::new(vec![interface], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        let device_row = output.tooltip.lines().find(|l| l.contains(&format!("({ip})"))).unwrap();
        assert!(!device_row.contains('★'));
    }
}
