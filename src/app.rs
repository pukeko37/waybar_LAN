//! Application layer: orchestrates domain logic through port traits.
//!
//! Defines the port traits (`NetworkFetcher`, `NetworkFormatter`) that
//! infrastructure adapters implement. No `use crate::infra::` imports here
//! outside `#[cfg(test)]`.

use crate::domain::{DeviceAddress, DeviceId, DeviceObservation, Hostname, MacAddress, NetworkDevice, NetworkSnapshot, WanAddress, WireGuardActivity, WireGuardPublicKey};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

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
    pub wan_address: Option<WanAddress>,
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
///    `mac`/WireGuard public key/`hostname` (union-find, transitive), so a
///    device with more than one address — dual-homed via two local
///    interfaces, or with multiple IPv6 addresses alongside an IPv4 one —
///    becomes one `NetworkDevice`, not several.
///
/// Always runs, even with an empty/default `RouterSnapshot` (no router
/// configured) — per [[device-recency-and-removal]], this is what makes the
/// persisted-history/`Removed` treatment apply uniformly regardless of
/// source, not just to router users. `router.wifi_clients` does not
/// participate in either pass (see `RouterSnapshot`'s doc comment); it's
/// consulted per-device inside `build_device`, alongside `history`, to
/// populate `on_wifi` and to decide whether this poll counts as a fresh
/// observation. Returns the updated history alongside the snapshot — the
/// caller (`main`) is responsible for persisting it.
pub fn merge_network_and_router(
    local: NetworkSnapshot,
    router: RouterSnapshot,
    history: &HashMap<DeviceId, SystemTime>,
) -> (NetworkSnapshot, HashMap<DeviceId, SystemTime>) {
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

    let wifi_clients = router.wifi_clients;

    for tiered in router.observations {
        let ip = tiered.observation.ip;
        by_ip.entry(ip).or_default().push((tier_rank(tiered.tier), tiered.observation));
    }

    let ctx = BuildContext {
        by_ip: &by_ip,
        local_bases: &local_bases,
        wifi_clients: &wifi_clients,
        history,
        now: SystemTime::now(),
    };
    let mut new_history = history.clone();
    let devices: Vec<NetworkDevice> = cluster_by_identity_signal(&by_ip)
        .into_iter()
        .filter_map(|cluster_ips| build_device(cluster_ips, &ctx))
        .map(|(device, history_update)| {
            if let Some((id, seen_at)) = history_update {
                new_history.insert(id, seen_at);
            }
            device
        })
        .collect();

    let merged = NetworkSnapshot::new(local.interfaces, devices, local.gateway, local.dns_servers);
    let merged = match router.wan_address {
        Some(wan_address) => merged.with_wan_address(wan_address),
        None => merged,
    };
    (merged, new_history)
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
            if let Some(key) = obs.wireguard_activity.public_key() {
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

/// Everything `build_device` needs beyond the cluster's own addresses,
/// bundled per house style's four-parameter limit.
struct BuildContext<'a> {
    by_ip: &'a HashMap<IpAddr, Vec<(u8, DeviceObservation)>>,
    local_bases: &'a HashMap<IpAddr, NetworkDevice>,
    /// `router.wifi_clients` — MAC-keyed side lookup, not a fold
    /// participant (see `RouterSnapshot`'s doc comment).
    wifi_clients: &'a [MacAddress],
    /// Persisted per-device last-observed timestamps from the previous
    /// poll, per [[device-recency-and-removal]]. Never consulted for
    /// WireGuard-identified devices — their clock is `wireguard_activity`.
    history: &'a HashMap<DeviceId, SystemTime>,
    /// Captured once per merge, not re-read per device, so every device
    /// built from the same poll shares an identical "now".
    now: SystemTime,
}

/// Builds one `NetworkDevice` from a cluster of correlated addresses, or
/// `None` if the cluster carries no identity signal at all (`mac`,
/// WireGuard public key, and `hostname` all absent on every observation —
/// in practice, `neigh` lines with no `lladdr`: the kernel's own
/// incomplete/failed ARP entries, not real devices).
///
/// Alongside the device, returns the persisted-history update this device
/// should cause (`Some((id, now))` if this poll counted as a fresh
/// observation of a non-WireGuard device, `None` otherwise) — the caller
/// folds these into the returned history map. See
/// [[device-recency-and-removal]].
fn build_device(cluster_ips: Vec<IpAddr>, ctx: &BuildContext) -> Option<(NetworkDevice, Option<(DeviceId, SystemTime)>)> {
    let mut flattened: Vec<&(u8, DeviceObservation)> =
        cluster_ips.iter().flat_map(|ip| ctx.by_ip[ip].iter()).collect();
    flattened.sort_by_key(|(rank, _)| *rank);

    let mac = flattened.iter().find_map(|(_, o)| o.mac.clone());
    let wireguard_activity = flattened.iter().find_map(|(_, o)| match &o.wireguard_activity {
        WireGuardActivity::NotApplicable => None,
        activity => Some(activity.clone()),
    });
    let wireguard_public_key = wireguard_activity.as_ref().and_then(|a| a.public_key().cloned());
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
            let interface_name = ctx.by_ip[ip].iter().find_map(|(_, o)| o.interface_name.clone());
            DeviceAddress { ip: *ip, interface_name }
        })
        .collect();
    addresses.sort_by_key(|a| a.ip);

    // A "neigh vote" — this poll positively placed the device via a live
    // kernel-neighbour-table read, whether this host's own (`LOCAL_RANK`)
    // or the router's (`RouterSourceTier::NeighborTable`). Both are
    // equally valid "seen right now" evidence; `leases`/`wg-peers` never
    // vote (durable bindings, not activity) — see [[device-recency-and-removal]].
    let neigh_vote = flattened
        .iter()
        .any(|(rank, _)| *rank == LOCAL_RANK || *rank == tier_rank(RouterSourceTier::NeighborTable));

    let base = cluster_ips.iter().find_map(|ip| ctx.local_bases.get(ip).cloned());
    let mut device = base.unwrap_or_else(|| NetworkDevice::new(id.clone(), addresses.clone(), mac.clone()));

    device.id = id;
    device.addresses = addresses;
    device.mac = mac.clone();
    if let Some(hostname) = hostname {
        device.hostname = Hostname::resolved(hostname);
    }
    if let Some(state) = neighbor_state {
        device.neighbor_state = state;
    }
    device.wireguard_activity = wireguard_activity.unwrap_or(WireGuardActivity::NotApplicable);
    device.on_wifi = mac.is_some_and(|m| ctx.wifi_clients.contains(&m));

    device = device.build_identity();
    if let Some(friendly_name) = friendly_name {
        device.identity.friendly_name = Some(friendly_name);
    }

    // last_seen/history only applies to non-WireGuard devices — WireGuard's
    // own clock (wireguard_activity) is authoritative and never touches the
    // persisted history file. A device counts as freshly observed this poll
    // on a neigh_vote (mDNS can only ever enrich a device already found via
    // neigh, so it carries no separate vote) or a `clients` (Wi-Fi) match.
    // Not observed this poll falls back to the persisted value, or the
    // epoch if there's no persisted value either (a device known only via
    // a durable `leases`/`clients` binding, never corroborated by any
    // activity signal, correctly reads Removed rather than Active) — see
    // [[device-recency-and-removal]].
    let history_update = if device.wireguard_activity == WireGuardActivity::NotApplicable {
        if neigh_vote || device.on_wifi {
            device.last_seen = ctx.now;
            Some((device.id.clone(), ctx.now))
        } else {
            device.last_seen = ctx.history.get(&device.id).copied().unwrap_or(std::time::UNIX_EPOCH);
            None
        }
    } else {
        None
    };

    Some((device, history_update))
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
            wan_address: None,
        };

        let (merged, _history) = merge_network_and_router(local, router, &HashMap::new());
        assert_eq!(merged.devices.len(), 1);
        assert_eq!(merged.devices[0].hostname, Hostname::Resolved("new-name".to_string()));
    }

    #[test]
    fn test_merge_preserves_local_services_and_falls_back_when_router_silent() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let local = NetworkSnapshot::new(vec![], vec![local_device(ip, "AA:BB:CC:DD:EE:FF", "old-name", "eth0")], None, vec![]);
        let router = RouterSnapshot::default();

        let (merged, _history) = merge_network_and_router(local, router, &HashMap::new());
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
                    .with_wireguard_activity(WireGuardPublicKey::new("pubkey123".to_string()), None)
                    .with_friendly_name(FriendlyName::new("Jamie phone".to_string())),
            }],
            wifi_clients: vec![],
            wan_address: None,
        };

        let (merged, _history) = merge_network_and_router(local, router, &HashMap::new());
        assert_eq!(merged.devices.len(), 1);
        let device = &merged.devices[0];
        assert_eq!(device.mac, None);
        assert_eq!(device.id, DeviceId::WireGuardKey(WireGuardPublicKey::new("pubkey123".to_string())));
        assert!(device.addresses.iter().all(|a| a.interface_name.is_none()));
        assert_eq!(device.identity.friendly_name, Some(FriendlyName::new("Jamie phone".to_string())));
    }

    #[test]
    fn test_merge_carries_wireguard_latest_handshake_onto_device() {
        let ip: IpAddr = "10.20.30.3".parse().unwrap();
        let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);
        let handshake = std::time::SystemTime::now() - std::time::Duration::from_secs(30);

        let router = RouterSnapshot {
            observations: vec![TieredObservation {
                tier: RouterSourceTier::WireGuard,
                observation: DeviceObservation::new(ip)
                    .with_wireguard_activity(WireGuardPublicKey::new("pubkey123".to_string()), Some(handshake)),
            }],
            wifi_clients: vec![],
            wan_address: None,
        };

        let (merged, _history) = merge_network_and_router(local, router, &HashMap::new());
        assert_eq!(merged.devices.len(), 1);
        assert!(matches!(
            &merged.devices[0].wireguard_activity,
            crate::domain::WireGuardActivity::LastHandshake(_, t) if *t == handshake
        ));
        assert_eq!(merged.devices[0].activity_status(), crate::domain::ActivityStatus::Active);
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
            wan_address: None,
        };

        let (merged, _history) = merge_network_and_router(local, router, &HashMap::new());
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
            wan_address: None,
        };

        let (merged, _history) = merge_network_and_router(local, router, &HashMap::new());
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
            wan_address: None,
        };

        let (merged, _history) = merge_network_and_router(local, router, &HashMap::new());
        assert_eq!(merged.devices.len(), 0);
    }

    #[test]
    fn test_merge_carries_router_wan_address_onto_snapshot() {
        let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);
        let wan_address = WanAddress::new("203.0.113.7".parse().unwrap());

        let router = RouterSnapshot {
            observations: vec![],
            wifi_clients: vec![],
            wan_address: Some(wan_address),
        };

        let (merged, _history) = merge_network_and_router(local, router, &HashMap::new());
        assert_eq!(merged.wan_address, Some(wan_address));
    }

    #[test]
    fn test_merge_wan_address_absent_when_router_silent() {
        let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);
        let (merged, _history) = merge_network_and_router(local, RouterSnapshot::default(), &HashMap::new());
        assert_eq!(merged.wan_address, None);
    }
}
