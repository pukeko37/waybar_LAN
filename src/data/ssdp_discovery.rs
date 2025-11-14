//! SSDP/UPnP device discovery using ssdp-client crate.

use anyhow::Result;
use futures::StreamExt;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// UPnP device information discovered via SSDP
#[derive(Debug, Clone)]
pub struct UpnpDeviceInfo {
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub device_type: Option<String>,
}

impl UpnpDeviceInfo {
    pub fn new() -> Self {
        Self {
            friendly_name: None,
            manufacturer: None,
            model_name: None,
            device_type: None,
        }
    }
}

impl Default for UpnpDeviceInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Discovers SSDP/UPnP devices on the local network
pub struct SsdpDiscovery;

impl SsdpDiscovery {
    /// Creates a new SsdpDiscovery instance
    pub fn new() -> Self {
        Self
    }

    /// Discover UPnP devices with a timeout
    /// Returns a map of IP addresses to their UPnP device information
    pub fn discover_devices(&self, timeout: Duration) -> Result<HashMap<IpAddr, UpnpDeviceInfo>> {
        // Create a tokio runtime for async operations
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        runtime.block_on(self.discover_devices_async(timeout))
    }

    async fn discover_devices_async(&self, timeout: Duration) -> Result<HashMap<IpAddr, UpnpDeviceInfo>> {
        let mut devices: HashMap<IpAddr, UpnpDeviceInfo> = HashMap::new();

        // Search for all UPnP root devices
        let search_target = ssdp_client::SearchTarget::RootDevice;

        let mut responses = ssdp_client::search(&search_target, timeout, 2, None).await?;

        // Collect responses with timeout
        let deadline = tokio::time::Instant::now() + timeout;

        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout_at(deadline, responses.next()).await {
                Ok(Some(Ok(response))) => {
                    // Extract IP address from the location URL
                    if let Some(ip) = Self::extract_ip_from_location(response.location()) {
                        let device_info = UpnpDeviceInfo {
                            friendly_name: None,
                            manufacturer: None,
                            model_name: None,
                            device_type: Some(format!("{:?}", response.search_target())),
                        };

                        devices.insert(ip, device_info);
                    }
                }
                Ok(Some(Err(_))) => {
                    // Skip errors
                    continue;
                }
                Ok(None) => {
                    // No more responses
                    break;
                }
                Err(_) => {
                    // Timeout
                    break;
                }
            }
        }

        Ok(devices)
    }

    /// Extract IP address from a UPnP location URL
    fn extract_ip_from_location(location: &str) -> Option<IpAddr> {
        // Location format: http://192.168.1.100:1234/description.xml
        let url = location.strip_prefix("http://")?;
        let host_port = url.split('/').next()?;
        let host = host_port.split(':').next()?;
        host.parse::<IpAddr>().ok()
    }
}

impl Default for SsdpDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssdp_discovery_creation() {
        let _discovery = SsdpDiscovery::new();
    }

    #[test]
    fn test_extract_ip() {
        let location = "http://192.168.1.100:1234/description.xml";
        let ip = SsdpDiscovery::extract_ip_from_location(location);
        assert_eq!(ip, Some(IpAddr::from([192, 168, 1, 100])));

        let location2 = "http://10.0.0.5:8080/device.xml";
        let ip2 = SsdpDiscovery::extract_ip_from_location(location2);
        assert_eq!(ip2, Some(IpAddr::from([10, 0, 0, 5])));
    }

    #[test]
    fn test_discover_devices() {
        let discovery = SsdpDiscovery::new();
        let devices = discovery.discover_devices(Duration::from_secs(2));

        // Should succeed even if no devices found
        assert!(devices.is_ok());

        let devices = devices.unwrap();
        println!("Found {} UPnP devices", devices.len());
    }
}
