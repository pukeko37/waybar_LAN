//! Top-level aggregates: this host's own interfaces, and the full
//! point-in-time network snapshot.

use super::device::NetworkDevice;
use super::values::{Gateway, InterfaceName, MacAddress, WanAddress};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
    fn test_network_snapshot_with_wan_address() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let snapshot = NetworkSnapshot::new(vec![], vec![], None, vec![])
            .with_wan_address(WanAddress::new(ip));
        assert_eq!(snapshot.wan_address, Some(WanAddress::new(ip)));
    }
}
