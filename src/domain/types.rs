//! Type-safe domain models for network monitoring.
//!
//! This module contains value objects that enforce invariants at compile time:
//! - All primitives are wrapped in semantic newtypes
//! - Validation happens at construction time
//! - Invalid states are unrepresentable

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// Validated MAC address
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddress(String);

impl MacAddress {
    /// Creates a new MacAddress from a string
    /// Accepts formats: AA:BB:CC:DD:EE:FF, aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF
    pub fn new(mac: String) -> Result<Self> {
        let normalized = mac.to_uppercase().replace('-', ":");

        // Basic validation: should be 17 chars with colons
        if normalized.len() != 17 {
            anyhow::bail!("Invalid MAC address length: {}", mac);
        }

        let parts: Vec<&str> = normalized.split(':').collect();
        if parts.len() != 6 {
            anyhow::bail!("Invalid MAC address format: {}", mac);
        }

        // Validate each octet is valid hex
        for part in parts {
            if part.len() != 2 {
                anyhow::bail!("Invalid MAC address octet: {}", part);
            }
            u8::from_str_radix(part, 16)
                .context(format!("Invalid hex in MAC address: {}", part))?;
        }

        Ok(Self(normalized))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// mDNS service type (e.g., "_airplay._tcp.local.")
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceType(String);

impl ServiceType {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// mDNS service instance name
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceInstanceName(String);

impl ServiceInstanceName {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServiceInstanceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Manufacturer name (e.g., "Samsung", "Brother")
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManufacturerName(String);

impl ManufacturerName {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Device model name (e.g., "QN90B", "HL-2270DW")
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelName(String);

impl ModelName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// User-friendly device name
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriendlyName(String);

impl FriendlyName {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Network interface name (e.g., "eth0", "wlan0")
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InterfaceName(String);

impl InterfaceName {
    pub fn new(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Hostname resolution state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Hostname {
    /// DNS lookup is in progress
    Resolving,
    /// Hostname was successfully resolved
    Resolved(String),
    /// DNS lookup failed or timed out
    Unknown,
}

/// mDNS service information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Service type (e.g., "_airplay._tcp", "_ssh._tcp")
    pub service_type: ServiceType,
    /// Service instance name
    pub instance_name: ServiceInstanceName,
    /// Port number
    pub port: u16,
}

impl ServiceInfo {
    pub fn new(service_type: ServiceType, instance_name: ServiceInstanceName, port: u16) -> Self {
        Self {
            service_type,
            instance_name,
            port,
        }
    }

    /// Get a friendly display name for the service type
    pub fn friendly_type(&self) -> &str {
        match self.service_type.as_str() {
            "_airplay._tcp.local." => "AirPlay",
            "_ssh._tcp.local." => "SSH",
            "_http._tcp.local." => "HTTP",
            "_https._tcp.local." => "HTTPS",
            "_smb._tcp.local." => "File Sharing",
            "_afpovertcp._tcp.local." => "AFP",
            "_printer._tcp.local." => "Printer",
            "_ipp._tcp.local." => "Printer",
            "_googlecast._tcp.local." => "Chromecast",
            "_homekit._tcp.local." => "HomeKit",
            "_spotify-connect._tcp.local." => "Spotify",
            "_raop._tcp.local." => "AirTunes",
            _ => {
                // Strip .local. suffix and underscores for display
                self.service_type
                    .as_str()
                    .trim_end_matches(".local.")
                    .trim_start_matches('_')
                    .split('.')
                    .next()
                    .unwrap_or(self.service_type.as_str())
            }
        }
    }
}

/// Kernel neighbor table state from `ip neigh show`
/// Represents the reachability state maintained by the kernel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NeighborState {
    /// Neighbor is reachable (recently confirmed)
    Reachable,
    /// Cached but not recently confirmed - may be offline
    Stale,
    /// Sending probe to verify reachability
    Delay,
    /// Actively probing neighbor
    Probe,
    /// Neighbor is unreachable
    Failed,
    /// No state available (e.g., from old /proc/net/arp parsing)
    Unknown,
}

impl NeighborState {
    /// Parse neighbor state from ip neigh show output
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "REACHABLE" => Self::Reachable,
            "STALE" => Self::Stale,
            "DELAY" => Self::Delay,
            "PROBE" => Self::Probe,
            "FAILED" => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

/// Device activity status based on last seen time
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivityStatus {
    Active,      // < 30 seconds
    Recent,      // < 5 minutes
    Idle,        // < 30 minutes
    Stale,       // > 30 minutes
}

impl ActivityStatus {
    /// Calculate activity status from last seen time
    pub fn from_last_seen(last_seen: SystemTime) -> Self {
        let elapsed = SystemTime::now()
            .duration_since(last_seen)
            .unwrap_or(Duration::from_secs(0));

        if elapsed < Duration::from_secs(30) {
            Self::Active
        } else if elapsed < Duration::from_secs(300) {
            Self::Recent
        } else if elapsed < Duration::from_secs(1800) {
            Self::Idle
        } else {
            Self::Stale
        }
    }

    /// Get Pango markup for coloring text
    pub fn pango_color(&self) -> (&'static str, &'static str) {
        match self {
            Self::Active => ("<span color='#00FF00'>", "</span>"),   // Green
            Self::Recent => ("<span color='#FFFF00'>", "</span>"),   // Yellow
            Self::Idle => ("", ""),                                   // White (default)
            Self::Stale => ("<span color='#888888'>", "</span>"),    // Grey
        }
    }

    /// Wrap text with color markup based on activity status
    pub fn colorize(&self, text: &str) -> String {
        let (start, end) = self.pango_color();
        format!("{}{}{}", start, text, end)
    }
}

impl Hostname {
    pub fn resolved(name: String) -> Self {
        if name.is_empty() {
            Self::Unknown
        } else {
            Self::Resolved(name)
        }
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Hostname::Resolving => write!(f, "Resolving..."),
            Hostname::Resolved(name) => write!(f, "{}", name),
            Hostname::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Device type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    Television,
    Printer,
    Router,
    Computer,
    NAS,
    MobileDevice,
    Tablet,
    Speaker,
    StreamingDevice,
    SmartHome,
    Unknown,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Television => "Television",
            Self::Printer => "Printer",
            Self::Router => "Router",
            Self::Computer => "Computer",
            Self::NAS => "NAS",
            Self::MobileDevice => "Mobile Device",
            Self::Tablet => "Tablet",
            Self::Speaker => "Speaker",
            Self::StreamingDevice => "Streaming Device",
            Self::SmartHome => "Smart Home",
            Self::Unknown => "Device",
        }
    }

    pub fn as_emoji(&self) -> &'static str {
        match self {
            Self::Television => "📺",
            Self::Printer => "🖨 ",      // Extra space for alignment
            Self::Router => "🌐",
            Self::Computer => "💻",
            Self::NAS => "🗄",
            Self::MobileDevice => "📞",  // Telephone receiver for phones
            Self::Tablet => "📋",        // Clipboard for tablets
            Self::Speaker => "🔊",
            Self::StreamingDevice => "📺",
            Self::SmartHome => "🏠",
            Self::Unknown => "🖥 ",      // Extra space for alignment
        }
    }
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Structured device identity with classification and naming
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Inferred device type
    pub device_type: DeviceType,
    /// Manufacturer name (Samsung, Brother, etc.)
    pub manufacturer: Option<ManufacturerName>,
    /// Model identifier (QN90B, HL-2270DW, etc.)
    pub model: Option<ModelName>,
    /// User-friendly name or network hostname
    pub friendly_name: Option<FriendlyName>,
}

impl DeviceIdentity {
    pub fn new() -> Self {
        Self {
            device_type: DeviceType::Unknown,
            manufacturer: None,
            model: None,
            friendly_name: None,
        }
    }

    /// Format device name with emoji and available information
    /// Format: {Emoji} {Manufacturer} {Model} or {Emoji} {FriendlyName} or just {Emoji}
    pub fn format(&self) -> String {
        let emoji = self.device_type.as_emoji();

        match (&self.manufacturer, &self.model) {
            (Some(mfr), Some(model)) => format!("{} {} {}", emoji, mfr.as_str(), model.as_str()),
            (Some(mfr), None) => format!("{} {}", emoji, mfr.as_str()),
            (None, Some(model)) => format!("{} {}", emoji, model.as_str()),
            (None, None) => {
                if let Some(name) = &self.friendly_name {
                    format!("{} {}", emoji, name.as_str())
                } else {
                    // Add device type name as fallback
                    format!("{} {}", emoji, self.device_type.as_str())
                }
            }
        }
    }
}

impl Default for DeviceIdentity {
    fn default() -> Self {
        Self::new()
    }
}

/// Network device discovered on the LAN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDevice {
    pub ip: IpAddr,
    pub mac: MacAddress,
    pub hostname: Hostname,
    pub interface_name: InterfaceName,
    pub services: Vec<ServiceInfo>,
    pub last_seen: SystemTime,
    pub neighbor_state: NeighborState,
    pub identity: DeviceIdentity,
}

impl NetworkDevice {
    pub fn new(ip: IpAddr, mac: MacAddress, interface_name: InterfaceName) -> Self {
        Self {
            ip,
            mac,
            hostname: Hostname::Resolving,
            interface_name,
            services: Vec::new(),
            last_seen: SystemTime::now(),
            neighbor_state: NeighborState::Unknown,
            identity: DeviceIdentity::new(),
        }
    }

    /// Get activity status based on neighbor state and last seen time
    /// Prioritizes kernel neighbor table state over time-based calculation
    pub fn activity_status(&self) -> ActivityStatus {
        match self.neighbor_state {
            NeighborState::Reachable | NeighborState::Delay | NeighborState::Probe => {
                ActivityStatus::Active
            }
            NeighborState::Stale => ActivityStatus::Stale,
            NeighborState::Failed => ActivityStatus::Stale,
            NeighborState::Unknown => ActivityStatus::from_last_seen(self.last_seen),
        }
    }

    /// Update last seen time to now
    pub fn update_last_seen(&mut self) {
        self.last_seen = SystemTime::now();
    }

    /// Build DeviceIdentity from collected information
    /// Uses priority-based inference for device type, manufacturer, model, and friendly name
    pub fn build_identity(&mut self) {
        self.identity = DeviceIdentity {
            device_type: self.infer_device_type(),
            manufacturer: self.extract_manufacturer(),
            model: self.extract_model(),
            friendly_name: self.extract_friendly_name(),
        };
    }

    /// Infer device type from available information
    fn infer_device_type(&self) -> DeviceType {
        self.infer_from_services()
            .or_else(|| self.infer_from_manufacturer_and_model())
            .or_else(|| self.infer_from_hostname())
            .unwrap_or(DeviceType::Unknown)
    }

    /// Infer device type from mDNS service types
    fn infer_from_services(&self) -> Option<DeviceType> {
        if self.has_service("_printer") || self.has_service("_ipp") {
            return Some(DeviceType::Printer);
        }
        if self.has_service("_googlecast")
            || (self.has_service("_airplay") && self.has_service("_spotify-connect")) {
            return Some(DeviceType::Television);
        }
        if self.has_service("_raop") && !self.has_service("_airplay") {
            return Some(DeviceType::Speaker);
        }
        if self.has_service("_ssh") && self.has_service("_smb") {
            return Some(DeviceType::NAS);
        }
        if self.has_service("_homekit") {
            return Some(DeviceType::SmartHome);
        }
        None
    }

    /// Infer device type from manufacturer and model with service heuristics
    fn infer_from_manufacturer_and_model(&self) -> Option<DeviceType> {
        let manufacturer_from_hostname = if let Hostname::Resolved(hostname) = &self.hostname {
            Some(hostname.to_lowercase())
        } else {
            None
        };

        // Check for TV brands with media services
        let is_tv_brand = |name: &str| {
            name.contains("samsung") || name.contains("lg") || name.contains("sony")
                || name.contains("vizio") || name.contains("tcl") || name.contains("hisense")
        };
        let has_tv_brand = manufacturer_from_hostname.as_ref().map(|m| is_tv_brand(m)).unwrap_or(false);

        if has_tv_brand && (self.has_service("_airplay") || self.has_service("_googlecast")
            || self.has_service("_spotify-connect") || self.has_service("_raop")) {
            return Some(DeviceType::Television);
        }

        // Check for printer brands
        let is_printer_brand = |name: &str| {
            name.contains("brother") || name.contains("hp") || name.contains("canon")
                || name.contains("epson") || name.contains("xerox")
        };
        let has_printer_brand = manufacturer_from_hostname.as_ref().map(|m| is_printer_brand(m)).unwrap_or(false);

        if has_printer_brand {
            return Some(DeviceType::Printer);
        }

        // Check for NAS manufacturers in hostname
        if let Some(hostname) = &manufacturer_from_hostname
            && (hostname.contains("synology") || hostname.contains("qnap"))
        {
            return Some(DeviceType::NAS);
        }

        None
    }

    /// Infer device type from hostname patterns
    fn infer_from_hostname(&self) -> Option<DeviceType> {
        let Hostname::Resolved(hostname) = &self.hostname else { return None };
        let hostname_lower = hostname.to_lowercase();

        if hostname_lower.contains("router") || hostname_lower.contains("gateway") {
            return Some(DeviceType::Router);
        }
        if hostname_lower.contains("nas") {
            return Some(DeviceType::NAS);
        }
        if hostname_lower.contains("printer") {
            return Some(DeviceType::Printer);
        }
        // Check for tablets before phones (since "Galaxy Tab" contains "galaxy")
        if hostname_lower.contains("ipad") || hostname_lower.contains("tablet")
            || hostname_lower.contains("-tab-") || hostname_lower.contains(" tab ")
            || hostname_lower.starts_with("tab") {
            return Some(DeviceType::Tablet);
        }
        if hostname_lower.contains("iphone") || hostname_lower.contains("galaxy")
            || hostname_lower.contains("pixel") {
            return Some(DeviceType::MobileDevice);
        }
        None
    }

    /// Extract manufacturer from available sources
    fn extract_manufacturer(&self) -> Option<ManufacturerName> {
        // Extract from hostname
        if let Hostname::Resolved(hostname) = &self.hostname {
            let hostname_lower = hostname.to_lowercase();
            let known_manufacturers = ["samsung", "lg", "sony", "brother", "hp",
                                      "canon", "epson", "apple", "google", "amazon"];
            for mfr in &known_manufacturers {
                if hostname_lower.contains(mfr) {
                    // Capitalize first letter
                    let capitalized = format!("{}{}",
                        &mfr[0..1].to_uppercase(),
                        &mfr[1..]);
                    return Some(ManufacturerName::new(capitalized));
                }
            }
        }

        None
    }

    /// Extract model from available sources
    fn extract_model(&self) -> Option<ModelName> {
        // Currently no sources for model name without UPnP
        // Could be extended to parse from mDNS TXT records if available
        None
    }

    /// Extract friendly name from available sources
    fn extract_friendly_name(&self) -> Option<FriendlyName> {
        // DNS hostname (if available and descriptive)
        if let Hostname::Resolved(hostname) = &self.hostname
            && !hostname.is_empty() && !hostname.starts_with('_')
        {
            return Some(FriendlyName::new(hostname.clone()));
        }

        None
    }

    /// Check if device has a specific mDNS service (case-insensitive partial match)
    fn has_service(&self, service_type: &str) -> bool {
        self.services.iter().any(|s|
            s.service_type.as_str().to_lowercase().contains(&service_type.to_lowercase())
        )
    }
}

/// Network interface on this machine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: InterfaceName,
    pub ip: IpAddr,
    pub mac: Option<MacAddress>,
}

impl NetworkInterface {
    pub fn new(name: InterfaceName, ip: IpAddr, mac: Option<MacAddress>) -> Self {
        Self { name, ip, mac }
    }
}

/// Default gateway address
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Gateway(pub IpAddr);

impl Gateway {
    pub fn new(ip: IpAddr) -> Self {
        Self(ip)
    }
}

impl fmt::Display for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Complete network snapshot at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub interfaces: Vec<NetworkInterface>,
    pub devices: Vec<NetworkDevice>,
    pub gateway: Option<Gateway>,
    pub dns_servers: Vec<IpAddr>,
}

impl NetworkSnapshot {
    pub fn new(
        interfaces: Vec<NetworkInterface>,
        devices: Vec<NetworkDevice>,
        gateway: Option<Gateway>,
        dns_servers: Vec<IpAddr>,
    ) -> Self {
        Self {
            interfaces,
            devices,
            gateway,
            dns_servers,
        }
    }

    /// Groups devices by their interface name
    pub fn devices_by_interface(&self) -> std::collections::HashMap<InterfaceName, Vec<&NetworkDevice>> {
        self.devices.iter().fold(std::collections::HashMap::new(), |mut map, device| {
            map.entry(device.interface_name.clone())
                .or_default()
                .push(device);
            map
        })
    }
}

// For backward compatibility with existing code
pub type NetworkData = NetworkSnapshot;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_mac_address_creation() {
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string());
        assert!(mac.is_ok());
        assert_eq!(format!("{}", mac.unwrap()), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_mac_address_lowercase() {
        let mac = MacAddress::new("aa:bb:cc:dd:ee:ff".to_string());
        assert!(mac.is_ok());
        assert_eq!(format!("{}", mac.unwrap()), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_mac_address_with_dashes() {
        let mac = MacAddress::new("AA-BB-CC-DD-EE-FF".to_string());
        assert!(mac.is_ok());
        assert_eq!(format!("{}", mac.unwrap()), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_mac_address_invalid_length() {
        let mac = MacAddress::new("AA:BB:CC".to_string());
        assert!(mac.is_err());
    }

    #[test]
    fn test_mac_address_invalid_hex() {
        let mac = MacAddress::new("ZZ:BB:CC:DD:EE:FF".to_string());
        assert!(mac.is_err());
    }

    #[test]
    fn test_hostname_states() {
        assert_eq!(
            format!("{}", Hostname::Resolving),
            "Resolving..."
        );
        assert_eq!(
            format!("{}", Hostname::Resolved("test.local".to_string())),
            "test.local"
        );
        assert_eq!(
            format!("{}", Hostname::Unknown),
            "Unknown"
        );
    }

    #[test]
    fn test_hostname_resolved_empty() {
        let hostname = Hostname::resolved("".to_string());
        assert_eq!(hostname, Hostname::Unknown);
    }

    #[test]
    fn test_network_device_creation() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let device = NetworkDevice::new(ip, mac, InterfaceName::new("eth0".to_string()));

        assert_eq!(device.ip, ip);
        assert_eq!(device.interface_name, InterfaceName::new("eth0".to_string()));
        assert_eq!(device.hostname, Hostname::Resolving);
    }

    #[test]
    fn test_gateway_creation() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let gateway = Gateway::new(ip);
        assert_eq!(format!("{}", gateway), "192.168.1.1");
    }

    #[test]
    fn test_network_snapshot_devices_by_interface() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 51));
        let mac1 = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let mac2 = MacAddress::new("11:22:33:44:55:66".to_string()).unwrap();

        let device1 = NetworkDevice::new(ip1, mac1, InterfaceName::new("eth0".to_string()));
        let device2 = NetworkDevice::new(ip2, mac2, InterfaceName::new("wlan0".to_string()));

        let snapshot = NetworkSnapshot::new(
            vec![],
            vec![device1, device2],
            None,
            vec![],
        );

        let by_interface = snapshot.devices_by_interface();
        assert_eq!(by_interface.len(), 2);
        assert_eq!(by_interface.get(&InterfaceName::new("eth0".to_string())).unwrap().len(), 1);
        assert_eq!(by_interface.get(&InterfaceName::new("wlan0".to_string())).unwrap().len(), 1);
    }
}
