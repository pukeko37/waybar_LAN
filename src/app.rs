//! Application layer: orchestrates domain logic through port traits.
//!
//! Defines the port traits (`NetworkFetcher`, `NetworkFormatter`) that
//! infrastructure adapters implement. No `use crate::infra::` imports here
//! outside `#[cfg(test)]`.

use crate::domain::{DeviceAddress, DeviceId, DeviceObservation, Hostname, MacAddress, NetworkDevice, NetworkSnapshot, WireGuardPublicKey};
use std::collections::HashMap;
use std::net::IpAddr;

/// Port trait for collecting a network snapshot.
///
/// Uses `anyhow::Error` because system/network collection errors are
/// genuinely open-ended infrastructure concerns.
pub trait NetworkFetcher {
    fn collect(&self) -> Result<NetworkSnapshot, anyhow::Error>;
}

/// A router-sourced device observation, keyed for the merge fold, plus the
/// router's own priority tier (see [[router-integration]]'s fixed source
/// order: DHCP lease > neighbour table > WireGuard).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouterSourceTier {
    DhcpLease,
    NeighborTable,
    WireGuard,
}

/// One partial device record from a specific router-side source, carrying
/// the tier it was observed at so the merge fold can rank it against other
/// sources.
#[derive(Debug, Clone)]
pub struct TieredObservation {
    pub tier: RouterSourceTier,
    pub observation: DeviceObservation,
}

/// Everything the router reports for one collection pass.
///
/// `observations` participate in `app`'s per-field priority fold, keyed by
/// `DeviceObservation::id`. `wifi_clients` (from the `clients` dispatcher
/// command) deliberately do not — they're a MAC-keyed side lookup applied
/// after the fold produces a device, not a ranked contributor to any folded
/// field (see [[router-integration]]).
#[derive(Debug, Clone, Default)]
pub struct RouterSnapshot {
    pub observations: Vec<TieredObservation>,
    pub wifi_clients: Vec<MacAddress>,
}

/// Port trait for collecting router-sourced device observations over SSH.
///
/// Mirrors `NetworkFetcher`'s shape and error-type choice. Router presence
/// is binary (see [[router-integration]]): a configured router that fails
/// to respond is a collection failure here, not a partial/degraded result —
/// callers propagate this `Err` rather than falling back to local-only data.
pub trait RouterFetcher {
    fn collect(&self) -> Result<RouterSnapshot, anyhow::Error>;
}

/// Port trait for formatting a network snapshot into some output representation.
///
/// The associated `Output` type lets each adapter choose its own output
/// (e.g., `WaybarOutput` for the Waybar formatter).
pub trait NetworkFormatter {
    type Output;
    fn format(&self, data: &NetworkSnapshot) -> Result<Self::Output, anyhow::Error>;
}

/// Collect a network snapshot and format it for output.
///
/// Generic over both ports, enabling test doubles for either side.
pub fn fetch_and_format<F: NetworkFetcher, Fmt: NetworkFormatter>(
    fetcher: &F,
    formatter: &Fmt,
) -> Result<Fmt::Output, anyhow::Error> {
    let data = fetcher.collect()?;
    formatter.format(&data)
}

/// Collect a network snapshot, collect router observations, merge them, and
/// format the result.
///
/// Router presence is binary (see [[router-integration]]): if
/// `router_fetcher.collect()` fails, that `Err` propagates as a full
/// collection failure — there is no fallback to local-only data.
pub fn fetch_merge_and_format<F: NetworkFetcher, R: RouterFetcher, Fmt: NetworkFormatter>(
    fetcher: &F,
    router_fetcher: &R,
    formatter: &Fmt,
) -> Result<Fmt::Output, anyhow::Error> {
    let local = fetcher.collect()?;
    let router = router_fetcher.collect()?;
    let merged = merge_network_and_router(local, router);
    formatter.format(&merged)
}

/// Where a `TieredObservation`'s tier ranks against local data. Lower rank
/// wins the fold. Router sources always outrank local, per
/// [[router-integration]]'s fixed priority order (DHCP lease > neighbour
/// table > WireGuard > local).
fn tier_rank(tier: RouterSourceTier) -> u8 {
    match tier {
        RouterSourceTier::DhcpLease => 0,
        RouterSourceTier::NeighborTable => 1,
        RouterSourceTier::WireGuard => 2,
    }
}

const LOCAL_RANK: u8 = 3;

/// Minimal union-find (no rank/size heuristics — device counts here are at
/// most a few hundred, not worth the extra bookkeeping) used to cluster
/// addresses into devices by shared identity signal.
struct UnionFind {
    parent: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self { parent: (0..n).collect() }
    }

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            self.parent[x] = self.find(self.parent[x]);
        }
        self.parent[x]
    }

    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[ra] = rb;
        }
    }
}

/// Merges a local `NetworkSnapshot` with router observations into one
/// `NetworkSnapshot` of *devices*, not addresses, per
/// [[device-catalogue-identity]]. Two passes:
///
/// 1. Observations sharing the exact same `IpAddr` are grouped (unchanged
///    from [[router-integration]] — the same address genuinely is the same
///    address).
/// 2. The resulting per-address groups are then clustered by shared
///    `mac`/`wireguard_public_key`/`hostname` (union-find, transitive), so a
///    device with more than one address — dual-homed via two local
///    interfaces, or with multiple IPv6 addresses alongside an IPv4 one —
///    becomes one `NetworkDevice`, not several.
///
/// `clients` (`router.wifi_clients`) does not participate in either pass —
/// see `RouterSnapshot`'s doc comment.
pub fn merge_network_and_router(local: NetworkSnapshot, router: RouterSnapshot) -> NetworkSnapshot {
    let mut by_ip: HashMap<IpAddr, Vec<(u8, DeviceObservation)>> = HashMap::new();
    let mut local_bases: HashMap<IpAddr, NetworkDevice> = HashMap::new();

    for device in local.devices {
        for address in &device.addresses {
            let mut observation = DeviceObservation::new(address.ip);
            if let Some(mac) = &device.mac {
                observation = observation.with_mac(mac.clone());
            }
            if let Hostname::Resolved(hostname) = &device.hostname {
                observation = observation.with_hostname(hostname.clone());
            }
            if let Some(friendly_name) = &device.identity.friendly_name {
                observation = observation.with_friendly_name(friendly_name.clone());
            }
            observation = observation.with_neighbor_state(device.neighbor_state);
            observation.interface_name = address.interface_name.clone();
            by_ip.entry(address.ip).or_default().push((LOCAL_RANK, observation));
        }
        for address in &device.addresses {
            local_bases.entry(address.ip).or_insert_with(|| device.clone());
        }
    }

    for tiered in router.observations {
        let ip = tiered.observation.ip;
        by_ip.entry(ip).or_default().push((tier_rank(tiered.tier), tiered.observation));
    }

    let devices = cluster_by_identity_signal(&by_ip)
        .into_iter()
        .filter_map(|cluster_ips| build_device(cluster_ips, &by_ip, &local_bases))
        .collect();

    NetworkSnapshot::new(local.interfaces, devices, local.gateway, local.dns_servers)
}

/// Clusters addresses sharing a `mac`/`wireguard_public_key`/`hostname`
/// signal (transitively — three addresses pairwise connected through
/// different shared signals still collapse into one cluster).
fn cluster_by_identity_signal(by_ip: &HashMap<IpAddr, Vec<(u8, DeviceObservation)>>) -> Vec<Vec<IpAddr>> {
    let ips: Vec<IpAddr> = by_ip.keys().copied().collect();
    let mut uf = UnionFind::new(ips.len());

    let mut mac_index: HashMap<MacAddress, usize> = HashMap::new();
    let mut wg_index: HashMap<WireGuardPublicKey, usize> = HashMap::new();
    let mut hostname_index: HashMap<String, usize> = HashMap::new();

    for (i, ip) in ips.iter().enumerate() {
        for (_, obs) in &by_ip[ip] {
            if let Some(mac) = &obs.mac {
                match mac_index.get(mac) {
                    Some(&j) => uf.union(i, j),
                    None => { mac_index.insert(mac.clone(), i); }
                }
            }
            if let Some(key) = &obs.wireguard_public_key {
                match wg_index.get(key) {
                    Some(&j) => uf.union(i, j),
                    None => { wg_index.insert(key.clone(), i); }
                }
            }
            if let Some(hostname) = &obs.hostname {
                match hostname_index.get(hostname) {
                    Some(&j) => uf.union(i, j),
                    None => { hostname_index.insert(hostname.clone(), i); }
                }
            }
        }
    }

    let mut clusters: HashMap<usize, Vec<IpAddr>> = HashMap::new();
    for (i, ip) in ips.iter().enumerate() {
        clusters.entry(uf.find(i)).or_default().push(*ip);
    }
    clusters.into_values().collect()
}

/// First IPv4 address in the slice, else the first address of any kind.
/// Safe to index: only ever called with a non-empty cluster.
fn primary_ip(ips: &[IpAddr]) -> IpAddr {
    ips.iter().find(|ip| ip.is_ipv4()).copied().unwrap_or(ips[0])
}

/// Builds one `NetworkDevice` from a cluster of correlated addresses, or
/// `None` if the cluster carries no identity signal at all (`mac`,
/// `wireguard_public_key`, and `hostname` all absent on every observation —
/// in practice, `neigh` lines with no `lladdr`: the kernel's own
/// incomplete/failed ARP entries, not real devices).
fn build_device(
    cluster_ips: Vec<IpAddr>,
    by_ip: &HashMap<IpAddr, Vec<(u8, DeviceObservation)>>,
    local_bases: &HashMap<IpAddr, NetworkDevice>,
) -> Option<NetworkDevice> {
    let mut flattened: Vec<&(u8, DeviceObservation)> =
        cluster_ips.iter().flat_map(|ip| by_ip[ip].iter()).collect();
    flattened.sort_by_key(|(rank, _)| *rank);

    let mac = flattened.iter().find_map(|(_, o)| o.mac.clone());
    let wireguard_public_key = flattened.iter().find_map(|(_, o)| o.wireguard_public_key.clone());
    let hostname = flattened.iter().find_map(|(_, o)| o.hostname.clone());

    if mac.is_none() && wireguard_public_key.is_none() && hostname.is_none() {
        return None;
    }

    let friendly_name = flattened.iter().find_map(|(_, o)| o.friendly_name.clone());
    let neighbor_state = flattened.iter().find_map(|(_, o)| o.neighbor_state);

    let id = match (&mac, &wireguard_public_key, &hostname) {
        (Some(mac), _, _) => DeviceId::Mac(mac.clone()),
        (None, Some(key), _) => DeviceId::WireGuardKey(key.clone()),
        (None, None, Some(hostname)) => DeviceId::Hostname(hostname.clone()),
        (None, None, None) => DeviceId::Ip(primary_ip(&cluster_ips)),
    };

    let mut addresses: Vec<DeviceAddress> = cluster_ips
        .iter()
        .map(|ip| {
            let interface_name = by_ip[ip].iter().find_map(|(_, o)| o.interface_name.clone());
            DeviceAddress { ip: *ip, interface_name }
        })
        .collect();
    addresses.sort_by_key(|a| a.ip);

    let base = cluster_ips.iter().find_map(|ip| local_bases.get(ip).cloned());
    let mut device = base.unwrap_or_else(|| NetworkDevice::new(id.clone(), addresses.clone(), mac.clone()));

    device.id = id;
    device.addresses = addresses;
    device.mac = mac;
    if let Some(hostname) = hostname {
        device.hostname = Hostname::resolved(hostname);
    }
    if let Some(state) = neighbor_state {
        device.neighbor_state = state;
    }

    device.build_identity();
    if let Some(friendly_name) = friendly_name {
        device.identity.friendly_name = Some(friendly_name);
    }

    Some(device)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::display::WaybarFormatter;

    struct StubNetworkFetcher {
        succeed: bool,
    }

    impl NetworkFetcher for StubNetworkFetcher {
        fn collect(&self) -> Result<NetworkSnapshot, anyhow::Error> {
            if self.succeed {
                Ok(NetworkSnapshot::new(vec![], vec![], None, vec![]))
            } else {
                Err(anyhow::anyhow!("collection failed"))
            }
        }
    }

    #[test]
    fn test_fetch_and_format_success() {
        let fetcher = StubNetworkFetcher { succeed: true };
        let formatter = WaybarFormatter::new();

        let output = fetch_and_format(&fetcher, &formatter).unwrap();

        assert_eq!(output.text, "🖧 No devices");
    }

    #[test]
    fn test_fetch_and_format_error() {
        let fetcher = StubNetworkFetcher { succeed: false };
        let formatter = WaybarFormatter::new();

        let result = fetch_and_format(&fetcher, &formatter);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("collection failed"));
    }

    use crate::domain::{FriendlyName, InterfaceName, NeighborState};

    fn local_device(ip: IpAddr, mac: &str, hostname: &str, interface: &str) -> NetworkDevice {
        let mac = MacAddress::new(mac.to_string()).unwrap();
        let address = DeviceAddress { ip, interface_name: Some(InterfaceName::new(interface.to_string())) };
        let mut device = NetworkDevice::new(DeviceId::Mac(mac.clone()), vec![address], Some(mac));
        device.hostname = Hostname::resolved(hostname.to_string());
        device.services.push(crate::domain::ServiceInfo::new(
            crate::domain::ServiceType::new("_ssh._tcp.local.".to_string()),
            crate::domain::ServiceInstanceName::new("my-nas".to_string()),
            22,
        ));
        device
    }

    #[test]
    fn test_merge_router_hostname_overrides_local() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let local = NetworkSnapshot::new(vec![], vec![local_device(ip, "AA:BB:CC:DD:EE:FF", "old-name", "eth0")], None, vec![]);

        let router = RouterSnapshot {
            observations: vec![TieredObservation {
                tier: RouterSourceTier::DhcpLease,
                observation: DeviceObservation::new(ip)
                    .with_mac(MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap())
                    .with_hostname("new-name".to_string()),
            }],
            wifi_clients: vec![],
        };

        let merged = merge_network_and_router(local, router);
        assert_eq!(merged.devices.len(), 1);
        assert_eq!(merged.devices[0].hostname, Hostname::Resolved("new-name".to_string()));
    }

    #[test]
    fn test_merge_preserves_local_services_and_falls_back_when_router_silent() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let local = NetworkSnapshot::new(vec![], vec![local_device(ip, "AA:BB:CC:DD:EE:FF", "old-name", "eth0")], None, vec![]);
        let router = RouterSnapshot::default();

        let merged = merge_network_and_router(local, router);
        assert_eq!(merged.devices.len(), 1);
        assert_eq!(merged.devices[0].services.len(), 1);
        assert_eq!(merged.devices[0].hostname, Hostname::Resolved("old-name".to_string()));
    }

    #[test]
    fn test_merge_creates_router_only_device_for_wireguard_peer_with_no_local_presence() {
        let ip: IpAddr = "10.20.30.3".parse().unwrap();
        let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);

        let router = RouterSnapshot {
            observations: vec![TieredObservation {
                tier: RouterSourceTier::WireGuard,
                observation: DeviceObservation::new(ip)
                    .with_wireguard_public_key(WireGuardPublicKey::new("pubkey123".to_string()))
                    .with_friendly_name(FriendlyName::new("Jamie phone".to_string())),
            }],
            wifi_clients: vec![],
        };

        let merged = merge_network_and_router(local, router);
        assert_eq!(merged.devices.len(), 1);
        let device = &merged.devices[0];
        assert_eq!(device.mac, None);
        assert_eq!(device.id, DeviceId::WireGuardKey(WireGuardPublicKey::new("pubkey123".to_string())));
        assert!(device.addresses.iter().all(|a| a.interface_name.is_none()));
        assert_eq!(device.identity.friendly_name, Some(FriendlyName::new("Jamie phone".to_string())));
    }

    #[test]
    fn test_merge_priority_order_dhcp_lease_beats_neighbor_table() {
        let ip: IpAddr = "192.168.1.60".parse().unwrap();
        let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);

        let dhcp_mac = MacAddress::new("AA:AA:AA:AA:AA:AA".to_string()).unwrap();

        let router = RouterSnapshot {
            observations: vec![
                TieredObservation {
                    tier: RouterSourceTier::NeighborTable,
                    observation: DeviceObservation::new(ip)
                        .with_mac(dhcp_mac.clone())
                        .with_neighbor_state(NeighborState::Reachable),
                },
                TieredObservation {
                    tier: RouterSourceTier::DhcpLease,
                    observation: DeviceObservation::new(ip)
                        .with_mac(dhcp_mac.clone())
                        .with_hostname("known-host".to_string()),
                },
            ],
            wifi_clients: vec![],
        };

        let merged = merge_network_and_router(local, router);
        assert_eq!(merged.devices.len(), 1);
        // DHCP lease's hostname wins despite being listed second...
        assert_eq!(merged.devices[0].hostname, Hostname::Resolved("known-host".to_string()));
        // ...while neighbor_state, which only the lower-priority tier
        // reported, still comes through via the fallback.
        assert_eq!(merged.devices[0].neighbor_state, NeighborState::Reachable);
    }

    #[test]
    fn test_merge_correlates_dual_homed_device_across_two_addresses_by_mac() {
        // Same physical device, seen locally on eno1 at one address, and
        // reported by the router's neighbour table at a *different*
        // address (e.g. an IPv6 link-local address) sharing the same MAC —
        // per [[device-catalogue-identity]], this collapses into one
        // device with two addresses, not two devices.
        let lan_ip: IpAddr = "192.168.1.50".parse().unwrap();
        let link_local_ip: IpAddr = "fe80::1".parse().unwrap();
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();

        let local = NetworkSnapshot::new(vec![], vec![local_device(lan_ip, "AA:BB:CC:DD:EE:FF", "desktop", "eno1")], None, vec![]);

        let router = RouterSnapshot {
            observations: vec![TieredObservation {
                tier: RouterSourceTier::NeighborTable,
                observation: DeviceObservation::new(link_local_ip).with_mac(mac),
            }],
            wifi_clients: vec![],
        };

        let merged = merge_network_and_router(local, router);
        assert_eq!(merged.devices.len(), 1);
        let device = &merged.devices[0];
        assert_eq!(device.addresses.len(), 2);
        assert!(device.addresses.iter().any(|a| a.ip == lan_ip));
        assert!(device.addresses.iter().any(|a| a.ip == link_local_ip));
    }

    #[test]
    fn test_merge_drops_signal_less_neighbor_only_clusters() {
        // A bare `neigh` entry with no `lladdr` at all — the kernel's own
        // incomplete/failed ARP entry, not a real device — carries no mac,
        // no wireguard_public_key, and no hostname. It must not appear in
        // the merged output.
        let ip: IpAddr = "192.168.1.99".parse().unwrap();
        let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);

        let router = RouterSnapshot {
            observations: vec![TieredObservation {
                tier: RouterSourceTier::NeighborTable,
                observation: DeviceObservation::new(ip).with_neighbor_state(NeighborState::Failed),
            }],
            wifi_clients: vec![],
        };

        let merged = merge_network_and_router(local, router);
        assert_eq!(merged.devices.len(), 0);
    }
}
