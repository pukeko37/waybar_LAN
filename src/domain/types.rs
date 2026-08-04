//! Type-safe domain models for network monitoring.
//!
//! This module contains value objects that enforce invariants at compile time:
//! - All primitives are wrapped in semantic newtypes
//! - Validation happens at construction time
//! - Invalid states are unrepresentable

use crate::domain::error::NetworkError;
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
    pub fn new(mac: String) -> Result<Self, NetworkError> {
        let normalized = mac.to_uppercase().replace('-', ":");

        // Basic validation: should be 17 chars with colons
        if normalized.len() != 17 {
            return Err(NetworkError::InvalidMacLength(mac));
        }

        let parts: Vec<&str> = normalized.split(':').collect();
        if parts.len() != 6 {
            return Err(NetworkError::InvalidMacFormat(mac));
        }

        // Validate each octet is valid hex
        for part in &parts {
            if part.len() != 2 || u8::from_str_radix(part, 16).is_err() {
                return Err(NetworkError::InvalidMacOctet((*part).to_string()));
            }
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
    pub fn from_label(s: &str) -> Self {
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

    /// Activity status for a WireGuard peer, from its tunnel's latest
    /// handshake time — a plain two-way split, `Active` within the last
    /// hour else `Stale`, deliberately not the four-tier `from_last_seen`
    /// scheme: "minutes since last poll noticed you" isn't meaningful for
    /// a tunnel peer the way it is for a freshly-discovered LAN device. See
    /// [[wireguard-handshake-activity]].
    pub fn from_wireguard_handshake(latest_handshake: SystemTime) -> Self {
        let elapsed = SystemTime::now()
            .duration_since(latest_handshake)
            .unwrap_or(Duration::from_secs(0));

        if elapsed < Duration::from_secs(3600) {
            Self::Active
        } else {
            Self::Stale
        }
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
    /// User-friendly name or network hostname
    pub friendly_name: Option<FriendlyName>,
}

impl DeviceIdentity {
    pub fn new() -> Self {
        Self {
            device_type: DeviceType::Unknown,
            manufacturer: None,
            friendly_name: None,
        }
    }
}

impl Default for DeviceIdentity {
    fn default() -> Self {
        Self::new()
    }
}

/// A WireGuard peer's public key. WireGuard peers have no MAC address (a
/// WireGuard tunnel is Layer-3-only — there is no Ethernet frame to carry
/// one), so this is the strongest identity/correlation signal available for
/// them, per [[device-catalogue-identity]].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WireGuardPublicKey(String);

impl WireGuardPublicKey {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WireGuardPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Device identity: a priority-ordered choice of the strongest signal
/// available, not a raw address. `Mac` > `WireGuardKey` > `Hostname` > `Ip`
/// as a last resort — the same "strongest available signal wins" idea
/// [[app-module-rules]] already applies to per-field merge priority, now
/// applied to identity itself. See [[device-catalogue-identity]], which
/// superseded the earlier `DeviceId(IpAddr)` design: keying identity on one
/// specific address meant a device with more than one address (dual-homed
/// via LAN and WireGuard, or simply IPv6 SLAAC/link-local/temporary
/// addresses alongside an IPv4 one) rendered as multiple devices.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeviceId {
    Mac(MacAddress),
    WireGuardKey(WireGuardPublicKey),
    Hostname(String),
    Ip(IpAddr),
}

/// One address a device is reachable at, plus which of *this host's own*
/// interfaces it was seen on locally (`None` for a router-only address —
/// there is no local NIC to attribute it to).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAddress {
    pub ip: IpAddr,
    pub interface_name: Option<InterfaceName>,
}

/// A partial per-address record contributed by one data source (local
/// collection or the router), consumed by `app`'s merge fold. Every field
/// but `ip` is optional — a source reports what it happens to know.
/// Grouped first by exact `ip` (the same address genuinely is the same
/// address), then correlated across different addresses of the same
/// physical device via `mac`/`wireguard_public_key`/`hostname` — see
/// [[device-catalogue-identity]].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceObservation {
    pub ip: IpAddr,
    pub mac: Option<MacAddress>,
    pub hostname: Option<String>,
    pub friendly_name: Option<FriendlyName>,
    pub interface_name: Option<InterfaceName>,
    pub neighbor_state: Option<NeighborState>,
    pub wireguard_public_key: Option<WireGuardPublicKey>,
    /// A WireGuard peer's last handshake time, per [[wireguard-handshake-activity]]
    /// — `None` means no handshake has ever been reported (including
    /// `wg-dump`'s "never handshaked" `0` sentinel), not "unknown".
    pub wireguard_latest_handshake: Option<SystemTime>,
}

impl DeviceObservation {
    /// A bare observation carrying only its address — enrichment fields are
    /// filled in with builder-style `with_*` calls as a source reports them.
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            mac: None,
            hostname: None,
            friendly_name: None,
            interface_name: None,
            neighbor_state: None,
            wireguard_public_key: None,
            wireguard_latest_handshake: None,
        }
    }

    pub fn with_mac(mut self, mac: MacAddress) -> Self {
        self.mac = Some(mac);
        self
    }

    pub fn with_hostname(mut self, hostname: String) -> Self {
        self.hostname = Some(hostname);
        self
    }

    pub fn with_friendly_name(mut self, friendly_name: FriendlyName) -> Self {
        self.friendly_name = Some(friendly_name);
        self
    }

    pub fn with_neighbor_state(mut self, neighbor_state: NeighborState) -> Self {
        self.neighbor_state = Some(neighbor_state);
        self
    }

    pub fn with_wireguard_public_key(mut self, key: WireGuardPublicKey) -> Self {
        self.wireguard_public_key = Some(key);
        self
    }

    pub fn with_wireguard_latest_handshake(mut self, latest_handshake: SystemTime) -> Self {
        self.wireguard_latest_handshake = Some(latest_handshake);
        self
    }
}

/// Network device discovered on the LAN — a catalogue entry, not an
/// address. May be reachable at more than one `DeviceAddress` (dual-homed
/// via two local interfaces, or multiple IPv6 addresses alongside an IPv4
/// one); see [[device-catalogue-identity]].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDevice {
    pub id: DeviceId,
    pub addresses: Vec<DeviceAddress>,
    pub mac: Option<MacAddress>,
    pub hostname: Hostname,
    pub services: Vec<ServiceInfo>,
    pub last_seen: SystemTime,
    pub neighbor_state: NeighborState,
    pub identity: DeviceIdentity,
    /// See [[wireguard-handshake-activity]] — `Some` overrides `activity_status()`'s
    /// usual `neighbor_state`/`last_seen`-based calculation.
    pub wireguard_latest_handshake: Option<SystemTime>,
}

impl NetworkDevice {
    pub fn new(id: DeviceId, addresses: Vec<DeviceAddress>, mac: Option<MacAddress>) -> Self {
        Self {
            id,
            addresses,
            mac,
            hostname: Hostname::Resolving,
            services: Vec::new(),
            last_seen: SystemTime::now(),
            neighbor_state: NeighborState::Unknown,
            identity: DeviceIdentity::new(),
            wireguard_latest_handshake: None,
        }
    }

    /// This device's primary/display address: first IPv4 address, else the
    /// first address of any kind.
    ///
    /// Safety: `addresses` is never empty — every `NetworkDevice` is built
    /// from at least one clustered address (see `app::merge_network_and_router`)
    /// or one DTO-derived address (see `infra::network::models`).
    pub fn primary_address(&self) -> IpAddr {
        self.addresses
            .iter()
            .find(|a| a.ip.is_ipv4())
            .or_else(|| self.addresses.first())
            .map(|a| a.ip)
            .expect("NetworkDevice always has at least one address")
    }

    /// Get activity status. A WireGuard peer's `wireguard_latest_handshake`,
    /// when present, takes priority over `neighbor_state`/`last_seen` — see
    /// [[wireguard-handshake-activity]]: WireGuard peers never appear in the
    /// kernel neighbor table (`neighbor_state` is always `Unknown` for them),
    /// and `last_seen` is reset to "now" on every poll's device rebuild, so
    /// falling through to the time-based calculation always read `Active`
    /// regardless of real tunnel activity.
    pub fn activity_status(&self) -> ActivityStatus {
        if let Some(latest_handshake) = self.wireguard_latest_handshake {
            return ActivityStatus::from_wireguard_handshake(latest_handshake);
        }

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
    /// Uses priority-based inference for device type, manufacturer, and friendly name
    pub fn build_identity(&mut self) {
        self.identity = DeviceIdentity {
            device_type: self.infer_device_type(),
            manufacturer: self.extract_manufacturer(),
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
                        mfr[0..1].to_uppercase(),
                        &mfr[1..]);
                    return Some(ManufacturerName::new(capitalized));
                }
            }
        }

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

/// The router's external (WAN-side) address, as reported by the router
/// itself over SSH — see [[wan-ip-display]]. Mirrors `Gateway`'s shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WanAddress(pub IpAddr);

impl WanAddress {
    pub fn new(ip: IpAddr) -> Self {
        Self(ip)
    }
}

impl fmt::Display for WanAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Whether an address is a private (RFC1918 IPv4) or IPv6 Unique Local
/// Address (`fc00::/7`). IPv6 link-local (`fe80::/10`) deliberately returns
/// `false` here — per [[private-address-only-display]], it isn't treated as
/// private for this widget's purposes. A pure classification fact, not a
/// filtering policy — see that decision for where the policy of what to do
/// with a non-private address lives.
pub fn is_private_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            (octets[0] & 0xfe) == 0xfc
        }
    }
}

/// Complete network snapshot at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub interfaces: Vec<NetworkInterface>,
    pub devices: Vec<NetworkDevice>,
    pub gateway: Option<Gateway>,
    pub dns_servers: Vec<IpAddr>,
    pub wan_address: Option<WanAddress>,
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
            wan_address: None,
        }
    }

    /// Attaches the router's WAN address, per [[wan-ip-display]]. Builder
    /// style, matching `DeviceObservation`'s existing `with_*` methods —
    /// avoids a fifth positional `NetworkSnapshot::new` argument that every
    /// existing call site (most of which never know a WAN address) would
    /// otherwise have to thread through.
    pub fn with_wan_address(mut self, wan_address: WanAddress) -> Self {
        self.wan_address = Some(wan_address);
        self
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
        let address = DeviceAddress { ip, interface_name: Some(InterfaceName::new("eth0".to_string())) };
        let device = NetworkDevice::new(DeviceId::Mac(mac.clone()), vec![address], Some(mac));

        assert_eq!(device.primary_address(), ip);
        assert_eq!(device.addresses[0].interface_name, Some(InterfaceName::new("eth0".to_string())));
        assert_eq!(device.hostname, Hostname::Resolving);
    }

    #[test]
    fn test_network_device_mac_is_optional() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let address = DeviceAddress { ip, interface_name: Some(InterfaceName::new("wg0".to_string())) };
        let device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);

        assert_eq!(device.mac, None);
        assert_eq!(device.id, DeviceId::Ip(ip));
    }

    #[test]
    fn test_network_device_interface_name_is_optional_for_router_only_devices() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 5));
        let address = DeviceAddress { ip, interface_name: None };
        let device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);

        assert_eq!(device.addresses[0].interface_name, None);
    }

    #[test]
    fn test_network_device_primary_address_prefers_ipv4() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let ipv6: IpAddr = "fe80::1".parse().unwrap();
        let addresses = vec![
            DeviceAddress { ip: ipv6, interface_name: None },
            DeviceAddress { ip: ipv4, interface_name: None },
        ];
        let device = NetworkDevice::new(DeviceId::Ip(ipv4), addresses, None);

        assert_eq!(device.primary_address(), ipv4);
    }

    #[test]
    fn test_device_observation_starts_bare_and_builds_up() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();

        let observation = DeviceObservation::new(ip)
            .with_mac(mac.clone())
            .with_hostname("phone.lan".to_string());

        assert_eq!(observation.ip, ip);
        assert_eq!(observation.mac, Some(mac));
        assert_eq!(observation.hostname, Some("phone.lan".to_string()));
        assert_eq!(observation.friendly_name, None);
        assert_eq!(observation.neighbor_state, None);
        assert_eq!(observation.wireguard_public_key, None);
    }

    #[test]
    fn test_device_observation_with_wireguard_public_key() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let key = WireGuardPublicKey::new("gN4DvXs=".to_string());

        let observation = DeviceObservation::new(ip).with_wireguard_public_key(key.clone());

        assert_eq!(observation.wireguard_public_key, Some(key));
    }

    #[test]
    fn test_device_observation_with_wireguard_latest_handshake() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let handshake = SystemTime::now() - Duration::from_secs(120);

        let observation = DeviceObservation::new(ip).with_wireguard_latest_handshake(handshake);

        assert_eq!(observation.wireguard_latest_handshake, Some(handshake));
    }

    #[test]
    fn test_activity_status_from_wireguard_handshake_recent_is_active() {
        let handshake = SystemTime::now() - Duration::from_secs(120);
        assert_eq!(ActivityStatus::from_wireguard_handshake(handshake), ActivityStatus::Active);
    }

    #[test]
    fn test_activity_status_from_wireguard_handshake_over_an_hour_is_stale() {
        let handshake = SystemTime::now() - Duration::from_secs(3601);
        assert_eq!(ActivityStatus::from_wireguard_handshake(handshake), ActivityStatus::Stale);
    }

    #[test]
    fn test_network_device_activity_status_prefers_wireguard_handshake_over_stale_last_seen() {
        // Regression test for the bug motivating [[wireguard-handshake-activity]]:
        // a WireGuard peer's neighbor_state is always Unknown, and last_seen is
        // effectively always "now" (reset on every poll's device rebuild), so
        // without this override every peer always read as Active.
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let address = DeviceAddress { ip, interface_name: None };
        let mut device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);
        device.wireguard_latest_handshake = Some(SystemTime::now() - Duration::from_secs(7200));

        assert_eq!(device.activity_status(), ActivityStatus::Stale);
    }

    #[test]
    fn test_network_device_activity_status_wireguard_handshake_within_hour_is_active() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let address = DeviceAddress { ip, interface_name: None };
        let mut device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);
        device.wireguard_latest_handshake = Some(SystemTime::now() - Duration::from_secs(30));

        assert_eq!(device.activity_status(), ActivityStatus::Active);
    }

    #[test]
    fn test_gateway_creation() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let gateway = Gateway::new(ip);
        assert_eq!(format!("{}", gateway), "192.168.1.1");
    }

    #[test]
    fn test_wan_address_creation() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let wan = WanAddress::new(ip);
        assert_eq!(format!("{}", wan), "203.0.113.7");
    }

    #[test]
    fn test_network_snapshot_with_wan_address() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let snapshot = NetworkSnapshot::new(vec![], vec![], None, vec![])
            .with_wan_address(WanAddress::new(ip));
        assert_eq!(snapshot.wan_address, Some(WanAddress::new(ip)));
    }

    #[test]
    fn test_is_private_address_rfc1918_ipv4() {
        assert!(is_private_address(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_address(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_address(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    }

    #[test]
    fn test_is_private_address_public_ipv4_is_not_private() {
        assert!(!is_private_address(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
        assert!(!is_private_address(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_is_private_address_ula_ipv6() {
        let ula: IpAddr = "fd12:3456:789a::1".parse().unwrap();
        assert!(is_private_address(&ula));
        let ula_fc: IpAddr = "fc00::1".parse().unwrap();
        assert!(is_private_address(&ula_fc));
    }

    #[test]
    fn test_is_private_address_link_local_ipv6_is_not_private() {
        let link_local: IpAddr = "fe80::1".parse().unwrap();
        assert!(!is_private_address(&link_local));
    }

    #[test]
    fn test_is_private_address_public_ipv6_is_not_private() {
        let public: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!is_private_address(&public));
    }
}
