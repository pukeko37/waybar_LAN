//! Waybar JSON output formatting for network data.

use crate::domain::NetworkData;
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

/// Formats network data as Waybar JSON
pub struct WaybarFormatter;

impl WaybarFormatter {
    /// Creates a new WaybarFormatter instance
    pub fn new() -> Self {
        Self
    }

    /// Formats network data for Waybar display
    pub fn format(&self, network_data: &NetworkData) -> Result<WaybarOutput> {
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

    /// Builds the tooltip with tree structure
    fn build_tooltip(&self, network_data: &NetworkData) -> String {
        if network_data.interfaces.is_empty() {
            return "No network interfaces found".to_string();
        }

        let devices_by_interface = network_data.devices_by_interface();
        let mut lines = Vec::new();

        for interface in &network_data.interfaces {
            lines.push(self.format_interface_header(interface));

            if let Some(devices) = devices_by_interface.get(&interface.name) {
                let sorted_devices = self.sort_devices(devices);
                lines.extend(self.format_devices(&sorted_devices, network_data));
            } else {
                lines.push("  └─ No devices".to_string());
            }

            lines.push(String::new()); // Empty line between interfaces
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

    /// Sort devices by IP address
    fn sort_devices<'a>(&self, devices: &[&'a crate::domain::NetworkDevice])
        -> Vec<&'a crate::domain::NetworkDevice> {
        let mut sorted = devices.to_vec();
        sorted.sort_by_key(|d| d.ip);
        sorted
    }

    /// Format all devices for an interface
    fn format_devices(&self, devices: &[&crate::domain::NetworkDevice], network_data: &NetworkData)
        -> Vec<String> {
        let device_count = devices.len();
        devices.iter().enumerate().flat_map(|(i, device)| {
            let is_last = i == device_count - 1;
            self.format_device_entry(device, is_last, network_data)
        }).collect()
    }

    /// Format a single device entry with its services and gateway info
    fn format_device_entry(&self, device: &crate::domain::NetworkDevice, is_last: bool,
        network_data: &NetworkData) -> Vec<String> {
        let mut lines = Vec::new();
        let prefix = if is_last { "  └─ " } else { "  ├─ " };

        // Main device line
        let display_name = device.identity.format();
        let colored_name = device.activity_status().colorize(&display_name);
        lines.push(format!("{}{} ({})", prefix, colored_name, device.ip));

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
        if device.ip != gateway.0 {
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
        let device = NetworkDevice::new(ip2, mac2, crate::domain::InterfaceName::new("eth0".to_string()));
        let mut router = NetworkDevice::new(gateway_ip, mac3, crate::domain::InterfaceName::new("eth0".to_string()));
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
}
