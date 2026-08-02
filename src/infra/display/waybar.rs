//! Waybar JSON output formatting for network data.

use crate::app::NetworkFormatter;
use crate::domain::{ActivityStatus, DeviceId, DeviceIdentity, DeviceType, NetworkData};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Waybar output format
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Get Pango markup for coloring text based on activity status
fn pango_color(status: ActivityStatus) -> (&'static str, &'static str) {
    match status {
        ActivityStatus::Active => ("<span color='#00FF00'>", "</span>"), // Green
        ActivityStatus::Recent => ("<span color='#FFFF00'>", "</span>"), // Yellow
        ActivityStatus::Idle => ("", ""),                                // White (default)
        ActivityStatus::Stale => ("<span color='#888888'>", "</span>"), // Grey
    }
}

/// Wrap text with color markup based on activity status
fn colorize(status: ActivityStatus, text: &str) -> String {
    let (start, end) = pango_color(status);
    format!("{}{}{}", start, text, end)
}

/// Emoji for a device type
fn device_type_emoji(device_type: DeviceType) -> &'static str {
    match device_type {
        DeviceType::Television => "📺",
        DeviceType::Printer => "🖨 ",     // Extra space for alignment
        DeviceType::Router => "🌐",
        DeviceType::Computer => "💻",
        DeviceType::NAS => "🗄",
        DeviceType::MobileDevice => "📞", // Telephone receiver for phones
        DeviceType::Tablet => "📋",       // Clipboard for tablets
        DeviceType::Speaker => "🔊",
        DeviceType::StreamingDevice => "📺",
        DeviceType::SmartHome => "🏠",
        DeviceType::Unknown => "🖥 ",     // Extra space for alignment
    }
}

/// Format device identity with emoji and available information
/// Format: {Emoji} {Manufacturer} {Model} or {Emoji} {FriendlyName} or just {Emoji}
fn format_identity(identity: &DeviceIdentity) -> String {
    let emoji = device_type_emoji(identity.device_type);

    match (&identity.manufacturer, &identity.model) {
        (Some(mfr), Some(model)) => format!("{} {} {}", emoji, mfr.as_str(), model.as_str()),
        (Some(mfr), None) => format!("{} {}", emoji, mfr.as_str()),
        (None, Some(model)) => format!("{} {}", emoji, model.as_str()),
        (None, None) => {
            if let Some(name) = &identity.friendly_name {
                format!("{} {}", emoji, name.as_str())
            } else {
                // Add device type name as fallback
                format!("{} {}", emoji, identity.device_type.as_str())
            }
        }
    }
}

/// Formats network data as Waybar JSON
pub struct WaybarFormatter;

impl WaybarFormatter {
    /// Creates a new WaybarFormatter instance
    pub fn new() -> Self {
        Self
    }

    /// Builds the tooltip: a brief preamble listing this host's own local
    /// interfaces (informational only, not a grouping mechanism — see
    /// [[flat-device-list-display]]), followed by one flat device list
    /// sorted by primary address. No per-interface or per-source grouping:
    /// a multi-address device (dual-homed via two local interfaces, or
    /// with several IPv6 addresses alongside an IPv4 one) renders as one
    /// row, not one row per address.
    fn build_tooltip(&self, network_data: &NetworkData) -> String {
        if network_data.interfaces.is_empty() {
            return "No network interfaces found".to_string();
        }

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
            lines.extend(self.format_devices(&sorted_devices, network_data));
        }

        lines.join("\n").trim_end().to_string()
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

    /// Format all devices in the flat list
    fn format_devices(&self, devices: &[&crate::domain::NetworkDevice], network_data: &NetworkData)
        -> Vec<String> {
        let device_count = devices.len();
        devices.iter().enumerate().flat_map(|(i, device)| {
            let is_last = i == device_count - 1;
            self.format_device_entry(device, is_last, network_data)
        }).collect()
    }

    /// Inline access-path annotation replacing section placement — e.g.
    /// `via eno1` when a `DeviceAddress` carries a local `interface_name`,
    /// `via WireGuard` when only a WireGuard-key-correlated address is
    /// known. No heuristic guessing beyond what the device's own fields
    /// state directly, per [[flat-device-list-display]].
    fn access_path_annotation(&self, device: &crate::domain::NetworkDevice) -> Option<String> {
        if let Some(name) = device.addresses.iter().find_map(|a| a.interface_name.as_ref()) {
            return Some(format!("via {}", name));
        }
        if matches!(device.id, DeviceId::WireGuardKey(_)) {
            return Some("via WireGuard".to_string());
        }
        None
    }

    /// Format a single device entry with its services and gateway info
    fn format_device_entry(&self, device: &crate::domain::NetworkDevice, is_last: bool,
        network_data: &NetworkData) -> Vec<String> {
        let mut lines = Vec::new();
        let prefix = if is_last { "  └─ " } else { "  ├─ " };

        // Main device line
        let display_name = format_identity(&device.identity);
        let colored_name = colorize(device.activity_status(), &display_name);
        let location = match self.access_path_annotation(device) {
            Some(annotation) => format!("{}, {}", device.primary_address(), annotation),
            None => device.primary_address().to_string(),
        };
        lines.push(format!("{}{} ({})", prefix, colored_name, location));

        // Services
        if let Some(services_line) = self.format_services(device, is_last) {
            lines.push(services_line);
        }

        // Gateway/DNS info
        lines.extend(self.format_gateway_info(device, is_last, network_data));

        lines
    }

    /// Format services list for a device
    fn format_services(&self, device: &crate::domain::NetworkDevice, is_last: bool) -> Option<String> {
        if device.services.is_empty() {
            return None;
        }

        let service_prefix = if is_last { "      " } else { "  │   " };
        let mut unique_services: Vec<String> = device.services
            .iter()
            .map(|s| s.friendly_type().to_string())
            .collect();
        unique_services.sort();
        unique_services.dedup();

        if unique_services.is_empty() {
            None
        } else {
            Some(format!("{}  Services: {}", service_prefix, unique_services.join(", ")))
        }
    }

    /// Format gateway and DNS information for a device
    fn format_gateway_info(&self, device: &crate::domain::NetworkDevice, is_last: bool,
        network_data: &NetworkData) -> Vec<String> {
        use std::net::IpAddr;

        let Some(gateway) = network_data.gateway else { return Vec::new() };
        if !device.addresses.iter().any(|a| a.ip == gateway.0) {
            return Vec::new();
        }

        let mut lines = Vec::new();
        let info_prefix = if is_last { "      " } else { "  │   " };

        // Gateway label
        let dns_matches_gateway = network_data.dns_servers.iter().any(|dns| dns == &gateway.0);
        if dns_matches_gateway {
            lines.push(format!("{}  Gateway (also DNS)", info_prefix));
        } else {
            lines.push(format!("{}  Gateway", info_prefix));
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
            lines.push(format!("{}  DNS: {}", info_prefix, dns_list.join(", ")));
        }

        lines
    }

    /// Format a single DNS entry with local/external label
    fn format_dns_entry(&self, dns: &std::net::IpAddr) -> String {
        use std::net::IpAddr;

        let is_local = match dns {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                octets[0] == 192 && octets[1] == 168
                    || octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            }
            IpAddr::V6(_) => false,
        };

        if is_local {
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
    use crate::domain::{Gateway, MacAddress, NetworkDevice, NetworkInterface};
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
        let mut router = local_device(gateway_ip, mac3, "eth0");
        router.build_identity(); // Build identity so it shows as "Router"

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
        let peer_address = crate::domain::DeviceAddress { ip: peer_ip, interface_name: None };
        let peer = NetworkDevice::new(crate::domain::DeviceId::WireGuardKey(key), vec![peer_address], None);

        let data = NetworkData::new(vec![interface], vec![local, peer], None, vec![]);
        let output = formatter.format(&data).unwrap();

        assert_eq!(output.text, "🖧 2 devices");
        assert!(output.tooltip.contains("10.20.30.3"));
        assert!(output.tooltip.contains("via WireGuard"));
    }

    #[test]
    fn test_format_collapses_dual_homed_device_to_one_tooltip_row() {
        let formatter = WaybarFormatter::new();
        let lan_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let wg_ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();

        let interface = NetworkInterface::new(crate::domain::InterfaceName::new("eth0".to_string()), lan_ip, Some(mac.clone()));
        let addresses = vec![
            crate::domain::DeviceAddress { ip: lan_ip, interface_name: Some(crate::domain::InterfaceName::new("eth0".to_string())) },
            crate::domain::DeviceAddress { ip: wg_ip, interface_name: None },
        ];
        let device = NetworkDevice::new(crate::domain::DeviceId::Mac(mac.clone()), addresses, Some(mac));

        let data = NetworkData::new(vec![interface], vec![device], None, vec![]);
        let output = formatter.format(&data).unwrap();

        // One device, one row — the badge count and the number of tree
        // glyphs ("├─"/"└─") in the tooltip must agree.
        assert_eq!(output.text, "🖧 1 device");
        let row_count = output.tooltip.matches("└─").count() + output.tooltip.matches("├─").count();
        assert_eq!(row_count, 1);
    }
}
