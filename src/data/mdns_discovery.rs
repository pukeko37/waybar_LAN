//! mDNS service discovery using mdns-sd crate.

use crate::domain::{ServiceInfo, ServiceType, ServiceInstanceName};
use anyhow::Result;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Discovers mDNS services on the local network
pub struct MdnsDiscovery {
    daemon: ServiceDaemon,
}

impl MdnsDiscovery {
    /// Creates a new MdnsDiscovery instance
    pub fn new() -> Result<Self> {
        let daemon = ServiceDaemon::new()?;
        Ok(Self { daemon })
    }

    /// Discover services with a timeout
    /// Returns a map of IP addresses to their discovered services
    pub fn discover_services(
        &self,
        timeout: Duration,
    ) -> Result<HashMap<IpAddr, Vec<ServiceInfo>>> {
        let mut services_by_ip: HashMap<IpAddr, Vec<ServiceInfo>> = HashMap::new();

        // Common service types to browse for
        let service_types = [
            "_airplay._tcp.local.",
            "_ssh._tcp.local.",
            "_http._tcp.local.",
            "_smb._tcp.local.",
            "_afpovertcp._tcp.local.",
            "_printer._tcp.local.",
            "_ipp._tcp.local.",
            "_googlecast._tcp.local.",
            "_homekit._tcp.local.",
            "_spotify-connect._tcp.local.",
            "_raop._tcp.local.",
            "_device-info._tcp.local.",
        ];

        // Browse for all service types at once and collect receivers
        let receivers: Vec<_> = service_types
            .iter()
            .filter_map(|service_type| self.daemon.browse(service_type).ok())
            .collect();

        // Poll all receivers together with a single timeout
        // Use longer per-receiver timeout to actually wait for responses
        let start = std::time::Instant::now();
        let check_interval = Duration::from_millis(100);

        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            let wait_time = check_interval.min(remaining);

            for receiver in &receivers {
                // Check each receiver with a reasonable timeout
                if let Ok(ServiceEvent::ServiceResolved(info)) = receiver.recv_timeout(wait_time) {
                    // Extract IP addresses from the service info
                    // Access fields directly as they are public
                    for scoped_addr in &info.addresses {
                        // Convert ScopedIp to IpAddr
                        let ip = match scoped_addr {
                            mdns_sd::ScopedIp::V4(v4) => IpAddr::V4(*v4.addr()),
                            mdns_sd::ScopedIp::V6(v6) => IpAddr::V6(*v6.addr()),
                            _ => continue, // Skip unknown IP types
                        };

                        let service_info = ServiceInfo::new(
                            ServiceType::new(info.ty_domain.clone()),
                            ServiceInstanceName::new(info.fullname.clone()),
                            info.port,
                        );

                        services_by_ip
                            .entry(ip)
                            .or_default()
                            .push(service_info);
                    }
                }
            }
        }

        Ok(services_by_ip)
    }
}

impl Default for MdnsDiscovery {
    fn default() -> Self {
        Self::new().expect("Failed to create mDNS discovery daemon")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdns_discovery_creation() {
        let discovery = MdnsDiscovery::new();
        assert!(discovery.is_ok());
    }

    #[test]
    fn test_discover_services() {
        let discovery = MdnsDiscovery::new().unwrap();
        let services = discovery.discover_services(Duration::from_secs(2));
        assert!(services.is_ok());

        // We may or may not find services depending on the network
        let services = services.unwrap();
        println!("Found services on {} IPs", services.len());
    }
}
