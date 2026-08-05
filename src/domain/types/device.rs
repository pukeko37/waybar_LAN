//! The device entity: its identity, its data model, and its state enums.
//! Heuristic identity inference (`build_identity` and friends) lives in the
//! sibling `inference` module, as a second `impl NetworkDevice` block.

use super::values::{FriendlyName, InterfaceName, MacAddress, ManufacturerName, ServiceInstanceName, ServiceType, SignalStrength, WireGuardPublicKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

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

    /// True for states the kernel currently reports as live or being
    /// actively verified. Used to prefer a device's currently-reachable
    /// address over a stale leftover one (e.g. an old DHCP lease's address
    /// still lingering in a router's ARP cache) when it has more than
    /// one — see `NetworkDevice::primary_address`.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Reachable | Self::Delay | Self::Probe)
    }
}

/// Device activity status based on last seen time
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivityStatus {
    Active,      // < 30 seconds
    Recent,      // < 5 minutes
    Idle,        // < 30 minutes
    Stale,       // < 24 hours
    /// Not seen for 24 hours or more — see [[device-recency-and-removal]].
    /// [[infra-display-module-rules]] filters devices in this state out of
    /// the tooltip entirely rather than colouring them.
    Removed,
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
        } else if elapsed < Duration::from_secs(86400) {
            Self::Stale
        } else {
            Self::Removed
        }
    }

    /// Activity status for a WireGuard peer, from its tunnel's latest
    /// handshake time — a plain two-way split below the `Removed` ceiling
    /// (`Active` within the last hour, else `Stale`), deliberately not the
    /// four-tier `from_last_seen` scheme: "minutes since last poll noticed
    /// you" isn't meaningful for a tunnel peer the way it is for a
    /// freshly-discovered LAN device. See [[wireguard-handshake-activity]]
    /// and [[device-recency-and-removal]].
    pub fn from_wireguard_handshake(latest_handshake: SystemTime) -> Self {
        let elapsed = SystemTime::now()
            .duration_since(latest_handshake)
            .unwrap_or(Duration::from_secs(0));

        if elapsed < Duration::from_secs(3600) {
            Self::Active
        } else if elapsed < Duration::from_secs(86400) {
            Self::Stale
        } else {
            Self::Removed
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

/// A device's relationship to WireGuard, replacing what used to be two
/// independent `Option`s (`wireguard_public_key`, `wireguard_latest_handshake`)
/// per [[device-recency-and-removal]]. Those two `Option`s let "not a
/// WireGuard device" and "a WireGuard device that's never handshaked" both
/// read as the same `None`, which is exactly why `NetworkDevice::activity_status`
/// couldn't tell them apart and every never-handshaked peer read as `Active`
/// — see that decision. `Never` is the bottom of a preorder: every real
/// handshake timestamp is "more recent" than it, and it maps unconditionally
/// to `ActivityStatus::Removed` rather than falling through to any
/// time-based calculation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireGuardActivity {
    /// Not a WireGuard peer at all.
    NotApplicable,
    /// A configured WireGuard peer whose tunnel has never handshaked.
    Never(WireGuardPublicKey),
    /// A configured WireGuard peer with a real handshake timestamp.
    LastHandshake(WireGuardPublicKey, SystemTime),
}

impl WireGuardActivity {
    /// The public key, if this is a WireGuard peer at all — the
    /// correlation signal `app`'s merge fold clusters WireGuard addresses
    /// by, since WireGuard peers have no MAC.
    pub fn public_key(&self) -> Option<&WireGuardPublicKey> {
        match self {
            Self::NotApplicable => None,
            Self::Never(key) | Self::LastHandshake(key, _) => Some(key),
        }
    }
}

/// One address a device is reachable at, plus which of *this host's own*
/// interfaces it was seen on locally (`None` for a router-only address —
/// there is no local NIC to attribute it to), and that specific address's
/// own neighbor-table reachability (`Unknown` when no source reported one —
/// e.g. an address known only via `leases`/`wg-peers`). Tracked per-address,
/// not just once per device, so a device with several addresses (the same
/// physical device seen at more than one address — see
/// [[device-catalogue-identity]]) can tell a currently-live address apart
/// from a stale leftover one; see `NetworkDevice::primary_address`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAddress {
    pub ip: IpAddr,
    pub interface_name: Option<InterfaceName>,
    pub neighbor_state: NeighborState,
}

/// A partial per-address record contributed by one data source (local
/// collection or the router), consumed by `app`'s merge fold. Every field
/// but `ip` is optional — a source reports what it happens to know.
/// Grouped first by exact `ip` (the same address genuinely is the same
/// address), then correlated across different addresses of the same
/// physical device via `mac`/the `wireguard_activity` public key/`hostname`
/// — see [[device-catalogue-identity]].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceObservation {
    pub ip: IpAddr,
    pub mac: Option<MacAddress>,
    pub hostname: Option<String>,
    pub friendly_name: Option<FriendlyName>,
    pub interface_name: Option<InterfaceName>,
    pub neighbor_state: Option<NeighborState>,
    pub wireguard_activity: WireGuardActivity,
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
            wireguard_activity: WireGuardActivity::NotApplicable,
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

    /// Sets this observation's WireGuard relationship. `latest_handshake:
    /// None` (the `wg-dump` "never handshaked" `0` sentinel) becomes
    /// `WireGuardActivity::Never`, not a state this method leaves
    /// unrepresented — see [[device-recency-and-removal]].
    pub fn with_wireguard_activity(mut self, key: WireGuardPublicKey, latest_handshake: Option<SystemTime>) -> Self {
        self.wireguard_activity = match latest_handshake {
            Some(t) => WireGuardActivity::LastHandshake(key, t),
            None => WireGuardActivity::Never(key),
        };
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
    /// See [[wireguard-handshake-activity]] and [[device-recency-and-removal]]
    /// — anything but `NotApplicable` overrides `activity_status()`'s usual
    /// `neighbor_state`/`last_seen`-based calculation.
    pub wireguard_activity: WireGuardActivity,
    /// Set by [[app-module-rules]]'s merge fold from a `clients` (Wi-Fi
    /// assoclist) MAC match — see [[device-recency-and-removal]]. Feeds
    /// [[infra-display-module-rules]]'s `via Wi-Fi` access-path grouping.
    pub on_wifi: bool,
    /// Set alongside `on_wifi` by the same `clients` MAC match — `None` for
    /// every non-Wi-Fi device. See [[wifi-signal-new-device-and-flat-layout]].
    pub wifi_signal: Option<SignalStrength>,
    /// When this `DeviceId` was first ever recorded in the persisted
    /// history file — set once, never updated again afterwards. `None` for
    /// WireGuard-identified devices (their clock is `wireguard_activity`,
    /// and they never touch the history file at all — same carve-out
    /// `last_seen` already has) and for any device with no history entry
    /// yet. See [[wifi-signal-new-device-and-flat-layout]].
    pub first_observed: Option<SystemTime>,
}

/// One device's persisted recency record from the history file — both
/// clocks together, not two parallel maps, per
/// [[wifi-signal-new-device-and-flat-layout]].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceHistory {
    pub first_observed: SystemTime,
    pub last_observed: SystemTime,
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
            wireguard_activity: WireGuardActivity::NotApplicable,
            on_wifi: false,
            wifi_signal: None,
            first_observed: None,
        }
    }

    /// Whether this device counts as newly observed — `first_observed`
    /// within the last 24h, reusing `ActivityStatus`'s existing `Removed`
    /// ceiling horizon rather than a fresh threshold. `false` for WireGuard
    /// devices (`first_observed` is always `None` for them) and for any
    /// device with no `first_observed` at all. See
    /// [[wifi-signal-new-device-and-flat-layout]].
    pub fn is_newly_observed(&self) -> bool {
        self.first_observed.is_some_and(|t| {
            SystemTime::now().duration_since(t).unwrap_or(Duration::from_secs(0)) < Duration::from_secs(86400)
        })
    }

    /// This device's primary/display address: the lowest-numbered IPv4
    /// address that's currently `is_active()` (Reachable/Delay/Probe),
    /// falling back to the lowest-numbered IPv4 address overall if none
    /// are, falling back to the first address at all if there's no IPv4.
    /// Computed independent of `addresses`' own order (`min_by_key`, not a
    /// positional `.first()`), so this doesn't depend on callers already
    /// having sorted it. Preferring an active address over a merely
    /// lower-numbered one matters once a device can have several — e.g. a
    /// stale ARP-cache entry at an old DHCP-leased address, still merged
    /// onto the same device (see [[device-catalogue-identity]]) as the
    /// address it actually holds now.
    ///
    /// Safety: `addresses` is never empty — every `NetworkDevice` is built
    /// from at least one clustered address (see `app::merge_network_and_router`)
    /// or one DTO-derived address (see `infra::network::models`).
    pub fn primary_address(&self) -> IpAddr {
        let ipv4 = self.addresses.iter().filter(|a| a.ip.is_ipv4());
        ipv4.clone()
            .filter(|a| a.neighbor_state.is_active())
            .min_by_key(|a| a.ip)
            .or_else(|| ipv4.min_by_key(|a| a.ip))
            .map(|a| a.ip)
            .or_else(|| self.addresses.first().map(|a| a.ip))
            .expect("NetworkDevice always has at least one address")
    }

    /// Get activity status. A WireGuard peer's `wireguard_activity`, when
    /// not `NotApplicable`, takes priority over `neighbor_state`/`last_seen`
    /// — see [[wireguard-handshake-activity]] and [[device-recency-and-removal]]:
    /// WireGuard peers never appear in the kernel neighbor table
    /// (`neighbor_state` is always `Unknown` for them), so before the
    /// original fix, every WireGuard peer read as `Active` regardless of
    /// real tunnel activity. `Never` (configured, no handshake ever) maps
    /// unconditionally to `Removed` rather than falling through to that
    /// same broken path — the bug the `Never` case originally hit.
    pub fn activity_status(&self) -> ActivityStatus {
        match &self.wireguard_activity {
            WireGuardActivity::NotApplicable => {}
            WireGuardActivity::Never(_) => return ActivityStatus::Removed,
            WireGuardActivity::LastHandshake(_, latest_handshake) => {
                return ActivityStatus::from_wireguard_handshake(*latest_handshake);
            }
        }

        match self.neighbor_state {
            NeighborState::Reachable | NeighborState::Delay | NeighborState::Probe => {
                ActivityStatus::Active
            }
            // Stale/Failed still consult last_seen's Removed ceiling — a
            // device the neighbor table keeps reporting as Stale/Failed
            // must not stay visible forever just because some source keeps
            // reasserting the entry; see [[device-recency-and-removal]]'s
            // "Removed, elapsed >= 24h" ceiling, applied uniformly rather
            // than only when neighbor_state is Unknown.
            NeighborState::Stale | NeighborState::Failed => {
                match ActivityStatus::from_last_seen(self.last_seen) {
                    ActivityStatus::Removed => ActivityStatus::Removed,
                    _ => ActivityStatus::Stale,
                }
            }
            NeighborState::Unknown => ActivityStatus::from_last_seen(self.last_seen),
        }
    }

    /// Update last seen time to now
    pub fn update_last_seen(mut self) -> Self {
        self.last_seen = SystemTime::now();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

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
        let address = DeviceAddress { ip, interface_name: Some(InterfaceName::new("eth0".to_string())), neighbor_state: NeighborState::Unknown };
        let device = NetworkDevice::new(DeviceId::Mac(mac.clone()), vec![address], Some(mac));

        assert_eq!(device.primary_address(), ip);
        assert_eq!(device.addresses[0].interface_name, Some(InterfaceName::new("eth0".to_string())));
        assert_eq!(device.hostname, Hostname::Resolving);
    }

    #[test]
    fn test_network_device_mac_is_optional() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let address = DeviceAddress { ip, interface_name: Some(InterfaceName::new("wg0".to_string())), neighbor_state: NeighborState::Unknown };
        let device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);

        assert_eq!(device.mac, None);
        assert_eq!(device.id, DeviceId::Ip(ip));
    }

    #[test]
    fn test_network_device_interface_name_is_optional_for_router_only_devices() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 5));
        let address = DeviceAddress { ip, interface_name: None, neighbor_state: NeighborState::Unknown };
        let device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);

        assert_eq!(device.addresses[0].interface_name, None);
    }

    #[test]
    fn test_network_device_primary_address_prefers_ipv4() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let ipv6: IpAddr = "fe80::1".parse().unwrap();
        let addresses = vec![
            DeviceAddress { ip: ipv6, interface_name: None, neighbor_state: NeighborState::Unknown },
            DeviceAddress { ip: ipv4, interface_name: None, neighbor_state: NeighborState::Unknown },
        ];
        let device = NetworkDevice::new(DeviceId::Ip(ipv4), addresses, None);

        assert_eq!(device.primary_address(), ipv4);
    }

    #[test]
    fn test_network_device_primary_address_prefers_active_over_lower_numbered_stale() {
        // Regression test: a device correlated across two addresses sharing
        // one MAC — e.g. a stale ARP-cache entry at an old DHCP-leased
        // address, still merged onto the same device as the address it
        // holds now — must show the currently-reachable address, not
        // whichever happens to sort lower numerically.
        let stale_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 156));
        let active_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 157));
        let addresses = vec![
            DeviceAddress { ip: stale_ip, interface_name: None, neighbor_state: NeighborState::Stale },
            DeviceAddress { ip: active_ip, interface_name: None, neighbor_state: NeighborState::Reachable },
        ];
        let device = NetworkDevice::new(DeviceId::Ip(active_ip), addresses, None);

        assert_eq!(device.primary_address(), active_ip);
    }

    #[test]
    fn test_network_device_primary_address_falls_back_to_lowest_when_none_active() {
        // No address is currently confirmed live (e.g. two Stale entries,
        // or a durable leases/wg-peers-only address with no neigh vote at
        // all): falls back to today's existing tie-break, lowest IPv4.
        let lower_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let higher_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 51));
        let addresses = vec![
            DeviceAddress { ip: higher_ip, interface_name: None, neighbor_state: NeighborState::Stale },
            DeviceAddress { ip: lower_ip, interface_name: None, neighbor_state: NeighborState::Unknown },
        ];
        let device = NetworkDevice::new(DeviceId::Ip(lower_ip), addresses, None);

        assert_eq!(device.primary_address(), lower_ip);
    }

    #[test]
    fn test_is_newly_observed_true_within_24h() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let address = DeviceAddress { ip, interface_name: None, neighbor_state: NeighborState::Unknown };
        let mut device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);
        device.first_observed = Some(SystemTime::now() - Duration::from_secs(3600));

        assert!(device.is_newly_observed());
    }

    #[test]
    fn test_is_newly_observed_false_over_24h() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let address = DeviceAddress { ip, interface_name: None, neighbor_state: NeighborState::Unknown };
        let mut device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);
        device.first_observed = Some(SystemTime::now() - Duration::from_secs(86401));

        assert!(!device.is_newly_observed());
    }

    #[test]
    fn test_is_newly_observed_false_when_none() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let address = DeviceAddress { ip, interface_name: None, neighbor_state: NeighborState::Unknown };
        let device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);

        assert!(!device.is_newly_observed());
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
        assert_eq!(observation.wireguard_activity, WireGuardActivity::NotApplicable);
    }

    #[test]
    fn test_device_observation_with_wireguard_activity_never_handshaked() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let key = WireGuardPublicKey::new("gN4DvXs=".to_string());

        let observation = DeviceObservation::new(ip).with_wireguard_activity(key.clone(), None);

        assert_eq!(observation.wireguard_activity, WireGuardActivity::Never(key));
    }

    #[test]
    fn test_device_observation_with_wireguard_activity_last_handshake() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let key = WireGuardPublicKey::new("gN4DvXs=".to_string());
        let handshake = SystemTime::now() - Duration::from_secs(120);

        let observation = DeviceObservation::new(ip).with_wireguard_activity(key.clone(), Some(handshake));

        assert_eq!(observation.wireguard_activity, WireGuardActivity::LastHandshake(key, handshake));
    }

    #[test]
    fn test_wireguard_activity_public_key() {
        let key = WireGuardPublicKey::new("gN4DvXs=".to_string());
        assert_eq!(WireGuardActivity::NotApplicable.public_key(), None);
        assert_eq!(WireGuardActivity::Never(key.clone()).public_key(), Some(&key));
        assert_eq!(
            WireGuardActivity::LastHandshake(key.clone(), SystemTime::now()).public_key(),
            Some(&key)
        );
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
    fn test_activity_status_from_wireguard_handshake_over_a_day_is_removed() {
        let handshake = SystemTime::now() - Duration::from_secs(86401);
        assert_eq!(ActivityStatus::from_wireguard_handshake(handshake), ActivityStatus::Removed);
    }

    #[test]
    fn test_activity_status_from_last_seen_over_a_day_is_removed() {
        let last_seen = SystemTime::now() - Duration::from_secs(86401);
        assert_eq!(ActivityStatus::from_last_seen(last_seen), ActivityStatus::Removed);
    }

    #[test]
    fn test_activity_status_from_last_seen_just_under_a_day_is_stale_not_removed() {
        let last_seen = SystemTime::now() - Duration::from_secs(86399);
        assert_eq!(ActivityStatus::from_last_seen(last_seen), ActivityStatus::Stale);
    }

    #[test]
    fn test_network_device_activity_status_prefers_wireguard_handshake_over_stale_last_seen() {
        // Regression test for the bug motivating [[wireguard-handshake-activity]]:
        // a WireGuard peer's neighbor_state is always Unknown, and last_seen is
        // effectively always "now" (reset on every poll's device rebuild), so
        // without this override every peer always read as Active.
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let address = DeviceAddress { ip, interface_name: None, neighbor_state: NeighborState::Unknown };
        let mut device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);
        let key = WireGuardPublicKey::new("gN4DvXs=".to_string());
        device.wireguard_activity =
            WireGuardActivity::LastHandshake(key, SystemTime::now() - Duration::from_secs(7200));

        assert_eq!(device.activity_status(), ActivityStatus::Stale);
    }

    #[test]
    fn test_network_device_activity_status_wireguard_handshake_within_hour_is_active() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let address = DeviceAddress { ip, interface_name: None, neighbor_state: NeighborState::Unknown };
        let mut device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);
        let key = WireGuardPublicKey::new("gN4DvXs=".to_string());
        device.wireguard_activity =
            WireGuardActivity::LastHandshake(key, SystemTime::now() - Duration::from_secs(30));

        assert_eq!(device.activity_status(), ActivityStatus::Active);
    }

    #[test]
    fn test_network_device_activity_status_stale_neighbor_over_a_day_since_last_seen_is_removed() {
        // Regression test: a device the router's neighbor table still carries
        // as Stale/Failed used to read Stale forever, no matter how long ago
        // last_seen actually was — activity_status() only ever consulted
        // last_seen when neighbor_state was Unknown. A device stuck at Stale
        // with a day-old last_seen must now be Removed, matching
        // [[device-recency-and-removal]]'s "Removed, elapsed >= 24h" ceiling,
        // which the decision states applies uniformly, not only to Unknown.
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99));
        let address = DeviceAddress { ip, interface_name: None, neighbor_state: NeighborState::Unknown };
        let mut device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);
        device.neighbor_state = NeighborState::Stale;
        device.last_seen = SystemTime::now() - Duration::from_secs(86401);

        assert_eq!(device.activity_status(), ActivityStatus::Removed);
    }

    #[test]
    fn test_network_device_activity_status_failed_neighbor_over_a_day_since_last_seen_is_removed() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99));
        let address = DeviceAddress { ip, interface_name: None, neighbor_state: NeighborState::Unknown };
        let mut device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);
        device.neighbor_state = NeighborState::Failed;
        device.last_seen = SystemTime::now() - Duration::from_secs(86401);

        assert_eq!(device.activity_status(), ActivityStatus::Removed);
    }

    #[test]
    fn test_network_device_activity_status_stale_neighbor_under_a_day_since_last_seen_is_stale() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99));
        let address = DeviceAddress { ip, interface_name: None, neighbor_state: NeighborState::Unknown };
        let mut device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);
        device.neighbor_state = NeighborState::Stale;
        device.last_seen = SystemTime::now() - Duration::from_secs(3600);

        assert_eq!(device.activity_status(), ActivityStatus::Stale);
    }

    #[test]
    fn test_network_device_activity_status_never_handshaked_is_removed() {
        // Regression test for the bug motivating [[device-recency-and-removal]]:
        // a never-handshaked WireGuard peer used to fall through to the
        // generic neighbor_state/last_seen path (always Unknown/"now" for a
        // WireGuard peer) and read as Active. It must now read Removed
        // unconditionally, without consulting neighbor_state or last_seen.
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 3));
        let address = DeviceAddress { ip, interface_name: None, neighbor_state: NeighborState::Unknown };
        let mut device = NetworkDevice::new(DeviceId::Ip(ip), vec![address], None);
        let key = WireGuardPublicKey::new("gN4DvXs=".to_string());
        device.wireguard_activity = WireGuardActivity::Never(key);

        assert_eq!(device.activity_status(), ActivityStatus::Removed);
    }
}
