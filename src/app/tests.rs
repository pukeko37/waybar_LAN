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
    let address =
        DeviceAddress { ip, interface_name: Some(InterfaceName::new(interface.to_string())), neighbor_state: NeighborState::Unknown };
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
fn test_merge_prefers_reachable_address_over_stale_leftover_sharing_a_mac() {
    // Regression test for a live bug: a router's ARP cache can carry a
    // leftover Stale entry for a device's *previous* DHCP-leased address
    // alongside the Reachable entry for its current one — same MAC, same
    // device, two addresses. Correlation correctly merges them into one
    // device (as above), but the device must display/sort by the
    // currently-reachable address, not whichever IP happens to be
    // numerically lower.
    let stale_ip: IpAddr = "192.168.1.156".parse().unwrap();
    let reachable_ip: IpAddr = "192.168.1.157".parse().unwrap();
    let mac = MacAddress::new("18:C0:4D:A7:B8:B6".to_string()).unwrap();
    let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);

    let router = RouterSnapshot {
        observations: vec![
            TieredObservation {
                tier: RouterSourceTier::NeighborTable,
                observation: DeviceObservation::new(stale_ip)
                    .with_mac(mac.clone())
                    .with_neighbor_state(NeighborState::Stale),
            },
            TieredObservation {
                tier: RouterSourceTier::NeighborTable,
                observation: DeviceObservation::new(reachable_ip)
                    .with_mac(mac)
                    .with_neighbor_state(NeighborState::Reachable),
            },
        ],
        wifi_clients: vec![],
        wan_address: None,
    };

    let (merged, _history) = merge_network_and_router(local, router, &HashMap::new());
    assert_eq!(merged.devices.len(), 1);
    let device = &merged.devices[0];
    assert_eq!(device.addresses.len(), 2);
    assert_eq!(device.primary_address(), reachable_ip);
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

#[test]
fn test_merge_sets_wifi_signal_alongside_on_wifi_for_clients_match() {
    let ip: IpAddr = "192.168.1.77".parse().unwrap();
    let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
    let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);

    let router = RouterSnapshot {
        observations: vec![TieredObservation {
            tier: RouterSourceTier::NeighborTable,
            observation: DeviceObservation::new(ip).with_mac(mac.clone()),
        }],
        wifi_clients: vec![crate::app::WifiClient { mac, signal: Some(crate::domain::SignalStrength::from_snr_db(21)) }],
        wan_address: None,
    };

    let (merged, _history) = merge_network_and_router(local, router, &HashMap::new());
    assert_eq!(merged.devices.len(), 1);
    assert!(merged.devices[0].on_wifi);
    assert_eq!(merged.devices[0].wifi_signal, Some(crate::domain::SignalStrength::from_snr_db(21)));
}

#[test]
fn test_merge_wifi_signal_none_when_no_clients_match() {
    let ip: IpAddr = "192.168.1.78".parse().unwrap();
    let mac = MacAddress::new("11:22:33:44:55:66".to_string()).unwrap();
    let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);

    let router = RouterSnapshot {
        observations: vec![TieredObservation {
            tier: RouterSourceTier::NeighborTable,
            observation: DeviceObservation::new(ip).with_mac(mac),
        }],
        wifi_clients: vec![],
        wan_address: None,
    };

    let (merged, _history) = merge_network_and_router(local, router, &HashMap::new());
    assert_eq!(merged.devices.len(), 1);
    assert!(!merged.devices[0].on_wifi);
    assert_eq!(merged.devices[0].wifi_signal, None);
}

#[test]
fn test_merge_sets_first_observed_to_now_on_first_ever_appearance() {
    let ip: IpAddr = "192.168.1.79".parse().unwrap();
    let mac = MacAddress::new("22:33:44:55:66:77".to_string()).unwrap();
    let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);

    let router = RouterSnapshot {
        observations: vec![TieredObservation {
            tier: RouterSourceTier::NeighborTable,
            observation: DeviceObservation::new(ip).with_mac(mac).with_neighbor_state(NeighborState::Reachable),
        }],
        wifi_clients: vec![],
        wan_address: None,
    };

    let before = std::time::SystemTime::now();
    let (merged, new_history) = merge_network_and_router(local, router, &HashMap::new());

    assert_eq!(merged.devices.len(), 1);
    let device = &merged.devices[0];
    assert!(device.is_newly_observed());
    let first_observed = device.first_observed.expect("non-WireGuard device with a vote should have first_observed set");
    assert!(first_observed >= before);
    assert_eq!(new_history.get(&device.id).unwrap().first_observed, first_observed);
}

#[test]
fn test_merge_carries_forward_first_observed_across_polls() {
    // Regression test for the migration/no-re-flagging rule: a device
    // already known from a previous poll must not look newly observed
    // again just because this poll also voted for it.
    let ip: IpAddr = "192.168.1.80".parse().unwrap();
    let mac = MacAddress::new("33:44:55:66:77:88".to_string()).unwrap();
    let id = DeviceId::Mac(mac.clone());
    let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);

    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(10 * 24 * 60 * 60);
    let mut history = HashMap::new();
    history.insert(id, crate::domain::DeviceHistory { first_observed: long_ago, last_observed: long_ago });

    let router = RouterSnapshot {
        observations: vec![TieredObservation {
            tier: RouterSourceTier::NeighborTable,
            observation: DeviceObservation::new(ip).with_mac(mac).with_neighbor_state(NeighborState::Reachable),
        }],
        wifi_clients: vec![],
        wan_address: None,
    };

    let (merged, new_history) = merge_network_and_router(local, router, &history);

    assert_eq!(merged.devices.len(), 1);
    let device = &merged.devices[0];
    assert_eq!(device.first_observed, Some(long_ago));
    assert!(!device.is_newly_observed());
    // last_observed still refreshes to now (this poll did vote for it) —
    // only first_observed stays pinned.
    assert!(new_history.get(&device.id).unwrap().last_observed > long_ago);
    assert_eq!(new_history.get(&device.id).unwrap().first_observed, long_ago);
}

#[test]
fn test_merge_wireguard_device_never_gets_first_observed() {
    let ip: IpAddr = "10.20.30.9".parse().unwrap();
    let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);

    let router = RouterSnapshot {
        observations: vec![TieredObservation {
            tier: RouterSourceTier::WireGuard,
            observation: DeviceObservation::new(ip)
                .with_wireguard_activity(WireGuardPublicKey::new("pubkey123".to_string()), Some(std::time::SystemTime::now())),
        }],
        wifi_clients: vec![],
        wan_address: None,
    };

    let (merged, new_history) = merge_network_and_router(local, router, &HashMap::new());

    assert_eq!(merged.devices.len(), 1);
    assert_eq!(merged.devices[0].first_observed, None);
    assert!(!merged.devices[0].is_newly_observed());
    assert!(!new_history.contains_key(&merged.devices[0].id));
}

#[test]
fn test_merge_stale_neigh_state_does_not_refresh_last_observed() {
    // Regression test for [[neigh-state-activity-fidelity]]: a router's
    // kernel neighbour-table cache can keep re-reporting a Stale entry
    // (unconfirmed by any actual traffic — see NeighborState::is_active)
    // for a device that's long gone. That must not count as a fresh
    // "seen right now" vote, or the device's 24h Removed ceiling (see
    // [[device-recency-and-removal]]) never fires — exactly the live bug
    // this test guards against.
    let ip: IpAddr = "192.168.1.113".parse().unwrap();
    let mac = MacAddress::new("06:57:28:00:47:7D".to_string()).unwrap();
    let id = DeviceId::Mac(mac.clone());
    let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);

    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(20 * 60 * 60);
    let mut history = HashMap::new();
    history.insert(id.clone(), crate::domain::DeviceHistory { first_observed: long_ago, last_observed: long_ago });

    let router = RouterSnapshot {
        observations: vec![TieredObservation {
            tier: RouterSourceTier::NeighborTable,
            observation: DeviceObservation::new(ip)
                .with_mac(mac)
                .with_neighbor_state(NeighborState::Stale),
        }],
        wifi_clients: vec![],
        wan_address: None,
    };

    let (merged, new_history) = merge_network_and_router(local, router, &history);

    assert_eq!(merged.devices.len(), 1);
    // A Stale re-report must not refresh the clock — it stays exactly
    // where the persisted history already had it.
    assert_eq!(new_history.get(&id).unwrap().last_observed, long_ago);
    assert_eq!(merged.devices[0].last_seen, long_ago);
}

#[test]
fn test_merge_failed_neigh_state_does_not_refresh_last_observed() {
    // Same as above, for Failed — the kernel actively tried and got no
    // answer, stronger evidence of absence than Stale, and must
    // certainly not count as a vote either.
    let ip: IpAddr = "192.168.1.222".parse().unwrap();
    let mac = MacAddress::new("A0:02:DC:B7:C8:AC".to_string()).unwrap();
    let id = DeviceId::Mac(mac.clone());
    let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);

    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(20 * 60 * 60);
    let mut history = HashMap::new();
    history.insert(id.clone(), crate::domain::DeviceHistory { first_observed: long_ago, last_observed: long_ago });

    let router = RouterSnapshot {
        observations: vec![TieredObservation {
            tier: RouterSourceTier::NeighborTable,
            observation: DeviceObservation::new(ip)
                .with_mac(mac)
                .with_neighbor_state(NeighborState::Failed),
        }],
        wifi_clients: vec![],
        wan_address: None,
    };

    let (merged, new_history) = merge_network_and_router(local, router, &history);

    assert_eq!(merged.devices.len(), 1);
    assert_eq!(new_history.get(&id).unwrap().last_observed, long_ago);
    assert_eq!(merged.devices[0].last_seen, long_ago);
}

#[test]
fn test_merge_reachable_neigh_state_still_refreshes_last_observed() {
    // The positive case: a genuinely Reachable neigh entry must still
    // vote, exactly as before this fix — this decision narrows which
    // states count, it doesn't remove the vote entirely.
    let ip: IpAddr = "192.168.1.140".parse().unwrap();
    let mac = MacAddress::new("BA:BC:C7:95:BC:AE".to_string()).unwrap();
    let id = DeviceId::Mac(mac.clone());
    let local = NetworkSnapshot::new(vec![], vec![], None, vec![]);

    let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(20 * 60 * 60);
    let mut history = HashMap::new();
    history.insert(id.clone(), crate::domain::DeviceHistory { first_observed: long_ago, last_observed: long_ago });

    let router = RouterSnapshot {
        observations: vec![TieredObservation {
            tier: RouterSourceTier::NeighborTable,
            observation: DeviceObservation::new(ip)
                .with_mac(mac)
                .with_neighbor_state(NeighborState::Reachable),
        }],
        wifi_clients: vec![],
        wan_address: None,
    };

    let (merged, new_history) = merge_network_and_router(local, router, &history);

    assert_eq!(merged.devices.len(), 1);
    assert!(new_history.get(&id).unwrap().last_observed > long_ago);
    assert!(merged.devices[0].last_seen > long_ago);
}
