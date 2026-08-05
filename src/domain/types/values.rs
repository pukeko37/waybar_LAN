//! Simple validated newtypes with no dependency on any other domain type.

use crate::domain::error::NetworkError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

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

/// Wi-Fi signal quality for a station in the router's `clients` (`iwinfo
/// assoclist`) output — per [[wifi-signal-new-device-and-flat-layout]].
/// Wraps the output's own pre-computed SNR figure (dB), not the raw RSSI —
/// SNR is already a single "how good is this link" number, unlike RSSI
/// which needs a separate noise-floor comparison to mean anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignalStrength(i32);

impl SignalStrength {
    pub fn from_snr_db(snr_db: i32) -> Self {
        Self(snr_db)
    }

    pub fn snr_db(self) -> i32 {
        self.0
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
