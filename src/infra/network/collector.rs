//! Network data collection from system interfaces.

use crate::app::NetworkFetcher;
use crate::domain::{NetworkData, NetworkSnapshot, ServiceInfo, NetworkInterface, Gateway, Hostname};
use crate::infra::network::{mdns_discovery::MdnsDiscovery, proc_parsers};
use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Raw network collection data before processing
/// Contains all discovered data including incomplete/stale entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawNetworkData {
    /// All lines from ip neigh show (with state information)
    pub neighbor_table_raw: Vec<String>,
    /// All lines from /proc/net/arp (including incomplete entries) - DEPRECATED
    pub arp_table_raw: Vec<String>,
    /// mDNS services discovered
    pub mdns_services: HashMap<IpAddr, Vec<ServiceInfo>>,
    /// Reverse DNS lookup results
    pub dns_lookups: HashMap<IpAddr, Hostname>,
    /// Network interfaces
    pub interfaces: Vec<NetworkInterface>,
    /// Default gateway
    pub gateway: Option<Gateway>,
    /// DNS servers
    pub dns_servers: Vec<IpAddr>,
}

/// Collects network information from local system
pub struct NetworkCollector;

impl NetworkCollector {
    /// Creates a new NetworkCollector instance
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Collects raw network data including all ARP entries (even incomplete)
    /// This is useful for debugging and analyzing what data is available
    pub fn collect_raw_network_data(&self) -> Result<RawNetworkData> {
        // Get all network interfaces
        let interfaces = proc_parsers::get_network_interfaces()?;

        // Perform ping sweep to populate neighbor table
        proc_parsers::ping_sweep_subnet(&interfaces)?;

        // Read raw neighbor table (with state information)
        let neighbor_table_raw = proc_parsers::read_raw_neighbor_table()?;

        // Read raw ARP table (all lines, including incomplete entries) - kept for compatibility
        let arp_table_raw = proc_parsers::read_raw_arp_table()?;

        // Get devices from neighbor table (for DNS lookups)
        let arp_devices = proc_parsers::parse_arp_table()?;

        // Discover mDNS services (longer timeout for comprehensive discovery)
        eprintln!("Discovering mDNS services (5s timeout)...");
        let mdns_services = match MdnsDiscovery::new()
            .and_then(|discovery| discovery.discover_services(Duration::from_secs(5))) {
            Ok(services) => {
                eprintln!("  Found mDNS services on {} IPs", services.len());
                services
            }
            Err(e) => {
                eprintln!("  mDNS discovery failed: {}", e);
                HashMap::new()
            }
        };

        // Perform reverse DNS lookups for all ARP devices
        let device_ips: Vec<_> = arp_devices.iter().map(|d| d.primary_address()).collect();
        eprintln!("Performing reverse DNS lookups for {} IPs...", device_ips.len());
        let dns_lookups: HashMap<IpAddr, Hostname> = std::thread::scope(|s| {
            device_ips
                .iter()
                .map(|ip| {
                    let ip_val = *ip;
                    (ip_val, s.spawn(move || proc_parsers::reverse_dns_lookup(&ip_val)))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|(ip_val, handle)| (ip_val, handle.join().unwrap_or(Hostname::Unknown)))
                .collect()
        });
        let resolved_count = dns_lookups.values().filter(|h| matches!(h, Hostname::Resolved(_))).count();
        eprintln!("  Resolved {} hostnames", resolved_count);

        // Get default gateway
        let gateway = proc_parsers::parse_default_gateway()?;

        // Get DNS servers
        let dns_servers = proc_parsers::parse_dns_servers().unwrap_or_default();

        Ok(RawNetworkData {
            neighbor_table_raw,
            arp_table_raw,
            mdns_services,
            dns_lookups,
            interfaces,
            gateway,
            dns_servers,
        })
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

        // Enrich devices with mDNS information
        // Extract mDNS instance names for later hostname priority decision
        let (devices, mdns_names) = devices.into_iter().fold(
            (Vec::new(), std::collections::HashMap::new()),
            |(mut enriched, mut names), mut device| {
                // Add mDNS services and extract instance name
                let device_ip = device.primary_address();
                if let Some(services) = mdns_services.get(&device_ip) {
                    device.services = services.clone();
                    device = device.update_last_seen();

                    // Extract hostname from mDNS instance name (e.g., "hostname.local.")
                    if let Some(service) = services.first()
                        && let Some(hostname) = service.instance_name.as_str().split('.').next()
                        && !hostname.is_empty() && hostname != "_"
                    {
                        names.insert(device_ip, hostname.to_string());
                    }
                }

                enriched.push(device);
                (enriched, names)
            },
        );

        // Perform reverse DNS lookups in parallel and apply hostname priority logic
        // Priority: DNS > mDNS instance name > Unknown
        let devices = {
            let device_ips: Vec<_> = devices.iter().map(|d| d.primary_address()).collect();

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
                    // Apply hostname priority logic: DNS > mDNS > Unknown
                    device.hostname = if let crate::domain::Hostname::Resolved(_) = dns_hostname {
                        dns_hostname
                    } else if let Some(mdns_name) = mdns_names.get(&device.primary_address()) {
                        crate::domain::Hostname::resolved(mdns_name.clone())
                    } else {
                        crate::domain::Hostname::Unknown
                    };

                    // Build device identity
                    device.build_identity()
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

impl NetworkFetcher for NetworkCollector {
    fn collect(&self) -> Result<NetworkSnapshot, anyhow::Error> {
        self.collect_network_info()
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
}
