//! Data Transfer Objects mirroring the raw system data shapes, converted
//! to domain types via `TryFrom`/`From` rather than constructed directly.

use crate::domain::{DeviceAddress, DeviceId, InterfaceName, MacAddress, NeighborState, NetworkDevice, NetworkError, NetworkInterface};
use std::net::IpAddr;

/// One parsed line from `ip neigh show`.
#[derive(Debug, Clone)]
pub struct NeighborEntryDto {
    pub ip: IpAddr,
    pub interface: String,
    pub mac: String,
    pub state: String,
}

impl TryFrom<NeighborEntryDto> for NetworkDevice {
    type Error = NetworkError;

    fn try_from(dto: NeighborEntryDto) -> Result<Self, Self::Error> {
        let mac = MacAddress::new(dto.mac)?;
        let neighbor_state = NeighborState::from_label(&dto.state);
        let address =
            DeviceAddress { ip: dto.ip, interface_name: Some(InterfaceName::new(dto.interface)), neighbor_state };
        let mut device = NetworkDevice::new(DeviceId::Mac(mac.clone()), vec![address], Some(mac));
        device.neighbor_state = neighbor_state;
        Ok(device)
    }
}

/// One system network interface, as reported by the `network-interface` crate.
#[derive(Debug, Clone)]
pub struct InterfaceDto {
    pub name: String,
    pub ip: IpAddr,
    pub mac: Option<String>,
}

impl From<InterfaceDto> for NetworkInterface {
    fn from(dto: InterfaceDto) -> Self {
        let mac = dto.mac.and_then(|m| MacAddress::new(m).ok());
        NetworkInterface::new(InterfaceName::new(dto.name), dto.ip, mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_neighbor_entry_dto_converts_to_device() {
        let dto = NeighborEntryDto {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            interface: "eth0".to_string(),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            state: "REACHABLE".to_string(),
        };

        let device = NetworkDevice::try_from(dto).unwrap();
        assert_eq!(device.neighbor_state, NeighborState::Reachable);
    }

    #[test]
    fn test_neighbor_entry_dto_rejects_invalid_mac() {
        let dto = NeighborEntryDto {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            interface: "eth0".to_string(),
            mac: "not-a-mac".to_string(),
            state: "REACHABLE".to_string(),
        };

        assert!(NetworkDevice::try_from(dto).is_err());
    }

    #[test]
    fn test_interface_dto_converts_to_interface() {
        let dto = InterfaceDto {
            name: "eth0".to_string(),
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            mac: Some("AA:BB:CC:DD:EE:FF".to_string()),
        };

        let interface = NetworkInterface::from(dto);
        assert!(interface.mac.is_some());
    }
}
