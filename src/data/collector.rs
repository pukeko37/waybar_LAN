//! Network data collection from system interfaces.

use crate::domain::{NetworkData, NetworkSnapshot, UpnpInfo, FriendlyName, ManufacturerName, ModelName, DeviceTypeName};
use crate::data::{mdns_discovery::MdnsDiscovery, proc_parsers, ssdp_discovery::SsdpDiscovery};
use anyhow::Result;
use std::time::Duration;

/// Collects network information from local system
pub struct NetworkCollector;

impl NetworkCollector {
    /// Creates a new NetworkCollector instance
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Collects current network information snapshot
    pub fn collect_network_info(&self) -> Result<NetworkData> {
        // Get all network interfaces
        let interfaces = proc_parsers::get_network_interfaces()?;

        // Perform ping sweep to populate ARP table with all active devices
        // This spawns concurrent ping processes for the entire subnet
        proc_parsers::ping_sweep_subnet(&interfaces)?;

        // Get devices from ARP table (now populated by ping sweep)
        let devices = proc_parsers::parse_arp_table()?;

        // Discover mDNS services (with 3 second timeout to catch all responses)
        let mdns_services = MdnsDiscovery::new()
            .and_then(|discovery| discovery.discover_services(Duration::from_secs(3)))
            .unwrap_or_default();

        // Discover SSDP/UPnP devices (with 2 second timeout)
        let ssdp_devices = SsdpDiscovery::new()
            .discover_devices(Duration::from_secs(2))
            .unwrap_or_default();

        // Enrich devices with mDNS and UPnP information
        // Extract mDNS instance names for later hostname priority decision
        let (devices, mdns_names) = devices.into_iter().fold(
            (Vec::new(), std::collections::HashMap::new()),
            |(mut enriched, mut names), mut device| {
                // Add mDNS services and extract instance name
                if let Some(services) = mdns_services.get(&device.ip) {
                    device.services = services.clone();
                    device.update_last_seen();

                    // Extract hostname from mDNS instance name (e.g., "hostname.local.")
                    if let Some(service) = services.first()
                        && let Some(hostname) = service.instance_name.as_str().split('.').next()
                        && !hostname.is_empty() && hostname != "_"
                    {
                        names.insert(device.ip, hostname.to_string());
                    }
                }

                // Add UPnP device info
                if let Some(upnp_device_info) = ssdp_devices.get(&device.ip) {
                    device.upnp_info = Some(UpnpInfo {
                        friendly_name: upnp_device_info.friendly_name.as_ref().map(|s| FriendlyName::new(s.clone())),
                        manufacturer: upnp_device_info.manufacturer.as_ref().map(|s| ManufacturerName::new(s.clone())),
                        model_name: upnp_device_info.model_name.as_ref().map(|s| ModelName::new(s.clone())),
                        device_type: upnp_device_info.device_type.as_ref().map(|s| DeviceTypeName::new(s.clone())),
                    });
                    device.update_last_seen();
                }

                enriched.push(device);
                (enriched, names)
            },
        );

        // Perform reverse DNS lookups in parallel and apply hostname priority logic
        // Priority: UPnP friendly_name > DNS > mDNS instance name > Unknown
        let devices = {
            let device_ips: Vec<_> = devices.iter().map(|d| d.ip).collect();

            let dns_results: Vec<_> = std::thread::scope(|s| {
                device_ips
                    .iter()
                    .map(|ip| {
                        s.spawn(move || proc_parsers::reverse_dns_lookup(ip))
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|handle| handle.join().unwrap_or(crate::domain::Hostname::Unknown))
                    .collect()
            });

            devices
                .into_iter()
                .zip(dns_results)
                .map(|(mut device, dns_hostname)| {
                    // Apply hostname priority logic
                    device.hostname = if let Some(upnp) = &device.upnp_info {
                        if let Some(friendly_name) = &upnp.friendly_name {
                            if !friendly_name.as_str().is_empty() {
                                crate::domain::Hostname::resolved(friendly_name.as_str().to_string())
                            } else {
                                dns_hostname
                            }
                        } else {
                            dns_hostname
                        }
                    } else if let crate::domain::Hostname::Resolved(_) = dns_hostname {
                        dns_hostname
                    } else if let Some(mdns_name) = mdns_names.get(&device.ip) {
                        crate::domain::Hostname::resolved(mdns_name.clone())
                    } else {
                        crate::domain::Hostname::Unknown
                    };

                    // Build device identity
                    device.build_identity();
                    device
                })
                .collect()
        };

        // Get default gateway
        let gateway = proc_parsers::parse_default_gateway()?;

        // Get DNS servers
        let dns_servers = proc_parsers::parse_dns_servers().unwrap_or_default();

        Ok(NetworkSnapshot::new(interfaces, devices, gateway, dns_servers))
    }
}

impl Default for NetworkCollector {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_creation() {
        let collector = NetworkCollector::new();
        assert!(collector.is_ok());
    }

    #[test]
    fn test_collect_network_info() {
        let collector = NetworkCollector::new().unwrap();
        let result = collector.collect_network_info();

        // Should succeed even if no devices found
        assert!(result.is_ok());

        let snapshot = result.unwrap();
        // We should have at least loopback interface
        // (though it might not have an IPv4 address)
        println!("Found {} interfaces", snapshot.interfaces.len());
        println!("Found {} devices", snapshot.devices.len());
        if let Some(gw) = snapshot.gateway {
            println!("Gateway: {}", gw);
        }
    }
}
