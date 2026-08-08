//! Application layer: orchestrates domain logic through port traits.
//!
//! Defines the port traits (`NetworkFetcher`, `NetworkFormatter`) that
//! infrastructure adapters implement. No `use crate::infra::` imports here
//! outside `#[cfg(test)]`.

use crate::domain::{DeviceAddress, DeviceHistory, DeviceId, DeviceObservation, Hostname, MacAddress, NeighborState, NetworkDevice, NetworkSnapshot, SignalStrength, WanAddress, WireGuardActivity, WireGuardPublicKey};
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

/// One associated Wi-Fi station from the `clients` dispatcher command — a
/// MAC plus its signal quality, per
/// [[wifi-signal-new-device-and-flat-layout]]. Lives here (not
/// `infra::router`) for the same reason `TieredObservation`/`RouterSourceTier`
/// do: it's the shape `app` consumes, and `infra::router` constructs it to
/// match — production code never imports `infra` types into `app`.
/// `signal: None` if the source line's signal figure couldn't be parsed —
/// still counts as "on Wi-Fi" for `on_wifi` tagging below, matching
/// [[infra-network-module-rules]]'s "partial data beats no data" stance
/// rather than dropping the whole station over one unparseable figure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiClient {
    pub mac: MacAddress,
    pub signal: Option<SignalStrength>,
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
    pub wifi_clients: Vec<WifiClient>,
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
    history: &HashMap<DeviceId, DeviceHistory>,
) -> (NetworkSnapshot, HashMap<DeviceId, DeviceHistory>) {
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
            if let Some((id, device_history)) = history_update {
                new_history.insert(id, device_history);
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
    wifi_clients: &'a [WifiClient],
    /// Persisted per-device recency record from the previous poll, per
    /// [[device-recency-and-removal]] (`last_observed`) and
    /// [[wifi-signal-new-device-and-flat-layout]] (`first_observed`).
    /// Never consulted for WireGuard-identified devices — their clock is
    /// `wireguard_activity`.
    history: &'a HashMap<DeviceId, DeviceHistory>,
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
/// should cause (`Some((id, DeviceHistory))` if this poll counted as a
/// fresh observation of a non-WireGuard device, `None` otherwise) — the
/// caller folds these into the returned history map. See
/// [[device-recency-and-removal]] and
/// [[wifi-signal-new-device-and-flat-layout]].
fn build_device(cluster_ips: Vec<IpAddr>, ctx: &BuildContext) -> Option<(NetworkDevice, Option<(DeviceId, DeviceHistory)>)> {
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
            // Per-address reachability, not just the device-level fold
            // above — lets `primary_address()` tell this specific address
            // apart from a stale one sharing the same cluster/MAC. Same
            // "first found, unranked" lookup `interface_name` already uses.
            let neighbor_state =
                ctx.by_ip[ip].iter().find_map(|(_, o)| o.neighbor_state).unwrap_or(NeighborState::Unknown);
            DeviceAddress { ip: *ip, interface_name, neighbor_state }
        })
        .collect();
    addresses.sort_by_key(|a| a.ip);

    // A "neigh vote" — this poll positively placed the device via a live
    // kernel-neighbour-table read, whether this host's own (`LOCAL_RANK`)
    // or the router's (`RouterSourceTier::NeighborTable`) — *and* the
    // kernel's own reachability state for that reading says it's actually
    // current (`NeighborState::is_active`: `Reachable`/`Delay`/`Probe`),
    // not merely cached (`Stale`/`Unknown`) or explicitly dead (`Failed`).
    // `leases`/`wg-peers` never vote at all (durable bindings, not
    // activity) — see [[device-recency-and-removal]]. Per
    // [[neigh-state-activity-fidelity]]: a `Stale`/`Failed` neigh entry
    // that a router's kernel keeps re-reporting is not a fresh sighting —
    // it's a cache the kernel hasn't reconfirmed (or has confirmed dead)
    // — and must not keep resetting the clock the 24h `Removed` ceiling
    // depends on.
    let neigh_vote = flattened.iter().any(|(rank, observation)| {
        (*rank == LOCAL_RANK || *rank == tier_rank(RouterSourceTier::NeighborTable))
            && observation.neighbor_state.is_some_and(NeighborState::is_active)
    });

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
    let wifi_match = mac.as_ref().and_then(|m| ctx.wifi_clients.iter().find(|c| &c.mac == m));
    device.on_wifi = wifi_match.is_some();
    device.wifi_signal = wifi_match.and_then(|c| c.signal);

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
    //
    // first_observed (per [[wifi-signal-new-device-and-flat-layout]]) is
    // independent of the vote: it's set once, the moment a DeviceId first
    // gets a history entry at all, and carried forward unchanged on every
    // later poll regardless of whether that poll itself voted — a device
    // that's gone quiet for a while and then reappears is not "new" again.
    let prior = ctx.history.get(&device.id);
    let history_update = if device.wireguard_activity == WireGuardActivity::NotApplicable {
        if neigh_vote || device.on_wifi {
            device.last_seen = ctx.now;
            let first_observed = prior.map(|h| h.first_observed).unwrap_or(ctx.now);
            device.first_observed = Some(first_observed);
            Some((device.id.clone(), DeviceHistory { first_observed, last_observed: ctx.now }))
        } else {
            device.last_seen = prior.map(|h| h.last_observed).unwrap_or(std::time::UNIX_EPOCH);
            device.first_observed = prior.map(|h| h.first_observed);
            None
        }
    } else {
        None
    };

    Some((device, history_update))
}

#[cfg(test)]
mod tests;
