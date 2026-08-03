//! Parsers for the router dispatcher commands' output, converting to
//! `DeviceObservation` rather than building domain types inline — same
//! DTO-conversion discipline `infra::network` uses. All five parsers here
//! are tested against real output captured live against the actual router
//! during the `router-integration` decision's verification pass (see the
//! wiki).

use crate::app::{RouterSourceTier, TieredObservation};
use crate::domain::{DeviceObservation, MacAddress, NeighborState, WanAddress, WireGuardPublicKey};
use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// Parses `neigh` (`ip neigh show`, run on the router) into tiered
/// observations. Same line shape as `infra::network::proc_parsers`' local
/// parsing — just a different vantage point.
pub fn parse_neigh(output: &str) -> Vec<TieredObservation> {
    output.lines().filter_map(parse_neigh_line).collect()
}

fn parse_neigh_line(line: &str) -> Option<TieredObservation> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let ip: IpAddr = parts[0].parse().ok()?;

    let mac = parts
        .iter()
        .position(|&s| s == "lladdr")
        .and_then(|idx| parts.get(idx + 1))
        .and_then(|s| MacAddress::new((*s).to_string()).ok());

    let state = parts.last().map(|s| NeighborState::from_label(s));

    let mut observation = DeviceObservation::new(ip);
    if let Some(mac) = mac {
        observation = observation.with_mac(mac);
    }
    if let Some(state) = state {
        observation = observation.with_neighbor_state(state);
    }

    Some(TieredObservation {
        tier: RouterSourceTier::NeighborTable,
        observation,
    })
}

/// Parses `leases` (`cat /tmp/dhcp.leases`, dnsmasq format) into tiered
/// observations. Line format: `<expiry> <mac> <ip> <hostname-or-*> <clientid-or-*>`
/// — router-authoritative, so this is the highest-priority tier.
pub fn parse_leases(output: &str) -> Vec<TieredObservation> {
    output.lines().filter_map(parse_lease_line).collect()
}

fn parse_lease_line(line: &str) -> Option<TieredObservation> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let mac = MacAddress::new(parts[1].to_string()).ok()?;
    let ip: IpAddr = parts[2].parse().ok()?;
    let hostname = (parts[3] != "*").then(|| parts[3].to_string());

    let mut observation = DeviceObservation::new(ip).with_mac(mac);
    if let Some(hostname) = hostname {
        observation = observation.with_hostname(hostname);
    }

    Some(TieredObservation {
        tier: RouterSourceTier::DhcpLease,
        observation,
    })
}

/// Parses `clients` (`iwinfo <radio> assoclist` output, one block per
/// associated station) into the MAC addresses currently on Wi-Fi. Each
/// block starts with an unindented line beginning with the station's MAC;
/// indented `RX:`/`TX:`/`expected throughput:` lines are signal detail,
/// not needed here. Per [[router-integration]], this is a MAC-keyed side
/// lookup — it does not produce `DeviceObservation`s or participate in the
/// merge fold.
pub fn parse_clients(output: &str) -> Vec<MacAddress> {
    output
        .lines()
        .filter(|line| !line.starts_with(char::is_whitespace) && !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|token| MacAddress::new(token.to_string()).ok())
        .collect()
}

/// One peer line from `wg-dump` (`sudo wg show all dump`). The router's own
/// local-identity line (5 fields: interface, private-key, public-key,
/// listen-port, fwmark) is not a peer and is skipped — it is distinguished
/// by field count alone, since this parser never reads a `wg-dump` private
/// key field into any named field to begin with.
#[derive(Debug, Clone)]
struct WgDumpPeer {
    public_key: String,
    allowed_ips: Vec<IpAddr>,
}

fn parse_wg_dump_line(line: &str) -> Option<WgDumpPeer> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 9 {
        return None; // 5 fields = the interface's own identity line, skip
    }

    let public_key = parts[1].to_string();
    let allowed_ips = parts[4]
        .split(',')
        .filter_map(|entry| entry.split('/').next())
        .filter_map(|ip| ip.parse().ok())
        .collect();

    Some(WgDumpPeer {
        public_key,
        allowed_ips,
    })
}

/// One `wireguard_BowersNet`-typed UCI section from `wg-peers`
/// (`ubus call uci get`). Sections with a `private_key` are the router's
/// own local WireGuard identity, not a peer — `private_key` is deserialized
/// only so this struct can detect and drop that section; it is never read
/// beyond that check, per the domain module's hard-exclusion rule.
#[derive(Debug, Deserialize)]
struct UciWireguardSection {
    #[serde(default)]
    description: Option<String>,
    public_key: Option<String>,
    #[serde(default)]
    private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UciGetResponse {
    values: HashMap<String, UciWireguardSection>,
}

/// Public key → peer description ("friendly name"), for genuine peers only.
fn parse_wg_peers(output: &str) -> Result<HashMap<String, String>> {
    let response: UciGetResponse = serde_json::from_str(output)?;

    Ok(response
        .values
        .into_values()
        .filter(|section| section.private_key.is_none())
        .filter_map(|section| Some((section.public_key?, section.description?)))
        .collect())
}

/// Merges `wg-dump` (identity/allowed-IPs) with `wg-peers` (peer name) by
/// public key into tiered observations, one per allowed-IP.
pub fn parse_wireguard(wg_dump_output: &str, wg_peers_output: &str) -> Result<Vec<TieredObservation>> {
    let peer_names = parse_wg_peers(wg_peers_output)?;

    Ok(wg_dump_output
        .lines()
        .filter_map(parse_wg_dump_line)
        .flat_map(|peer| {
            let friendly_name = peer_names.get(&peer.public_key).cloned();
            let public_key = WireGuardPublicKey::new(peer.public_key.clone());
            peer.allowed_ips
                .into_iter()
                .map(move |ip| {
                    let mut observation = DeviceObservation::new(ip)
                        .with_wireguard_public_key(public_key.clone());
                    if let Some(name) = &friendly_name {
                        observation = observation.with_friendly_name(
                            crate::domain::FriendlyName::new(name.clone()),
                        );
                    }
                    TieredObservation {
                        tier: RouterSourceTier::WireGuard,
                        observation,
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect())
}

/// One `ipv4-address` entry from `ubus call network.interface.wan status`.
#[derive(Debug, Deserialize)]
struct UbusIpv4Address {
    address: Ipv4Addr,
}

/// Shape of `ubus call network.interface.wan status`'s JSON output, reduced
/// to the one field this parser reads.
#[derive(Debug, Deserialize)]
struct UbusWanStatus {
    #[serde(rename = "ipv4-address", default)]
    ipv4_address: Vec<UbusIpv4Address>,
}

/// Parses `wan-ip` (`ubus call network.interface.wan status`) into the
/// router's external address, per [[wan-ip-display]]. `None` if the WAN
/// interface is up but reports no IPv4 address (e.g. IPv6-only) — this is
/// not itself an error. IPv6 WAN addresses are out of scope for this pass.
pub fn parse_wan_ip(output: &str) -> Result<Option<WanAddress>> {
    let status: UbusWanStatus = serde_json::from_str(output)?;
    Ok(status
        .ipv4_address
        .first()
        .map(|entry| WanAddress::new(IpAddr::V4(entry.address))))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real output captured 2026-08-02 against the actual router.
    const LEASES_OUTPUT: &str = "\
1785691475 a4:77:33:2d:b5:01 192.168.1.142 Chromecast *
1785690629 de:c9:87:75:31:6e 192.168.1.122 * 01:de:c9:87:75:31:6e";

    #[test]
    fn test_parse_leases_carries_mac_ip_hostname() {
        let observations = parse_leases(LEASES_OUTPUT);
        assert_eq!(observations.len(), 2);
        assert!(observations.iter().all(|o| o.tier == RouterSourceTier::DhcpLease));

        let chromecast = &observations[0].observation;
        assert_eq!(chromecast.ip, "192.168.1.142".parse::<IpAddr>().unwrap());
        assert_eq!(chromecast.mac, Some(MacAddress::new("a4:77:33:2d:b5:01".to_string()).unwrap()));
        assert_eq!(chromecast.hostname, Some("Chromecast".to_string()));
    }

    #[test]
    fn test_parse_leases_treats_star_hostname_as_absent() {
        let observations = parse_leases(LEASES_OUTPUT);
        let unnamed = &observations[1].observation;
        assert_eq!(unnamed.hostname, None);
        assert_eq!(unnamed.mac, Some(MacAddress::new("de:c9:87:75:31:6e".to_string()).unwrap()));
    }

    // Real output captured 2026-08-02 against the actual router.
    const CLIENTS_OUTPUT: &str = "\
AE:1F:90:01:8B:1B  -70 dBm / -91 dBm (SNR 21)  28280 ms ago
    RX: 6.0 MBit/s                               1482166 Pkts.
    TX: 104.0 MBit/s, MCS 13, 20MHz              3728040 Pkts.
    expected throughput: unknown

A4:77:33:2D:B5:01  -80 dBm / -91 dBm (SNR 11)  3460 ms ago
    RX: 21.7 MBit/s, MCS 2, 20MHz                  34051 Pkts.
    TX: 28.9 MBit/s, MCS 3, 20MHz                  39199 Pkts.
    expected throughput: unknown";

    #[test]
    fn test_parse_clients_extracts_only_station_mac_lines() {
        let macs = parse_clients(CLIENTS_OUTPUT);
        assert_eq!(
            macs,
            vec![
                MacAddress::new("AE:1F:90:01:8B:1B".to_string()).unwrap(),
                MacAddress::new("A4:77:33:2D:B5:01".to_string()).unwrap(),
            ]
        );
    }

    const NEIGH_OUTPUT: &str = "\
192.168.1.50 dev eno1 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.1.51 dev eno1 lladdr 11:22:33:44:55:66 STALE
192.168.1.99 dev eno1 FAILED";

    #[test]
    fn test_parse_neigh_keeps_state_only_lines_with_no_mac() {
        // mac is optional on DeviceObservation, so a line with no `lladdr`
        // (just an IP + state) still contributes a valid partial record —
        // it isn't discarded the way infra::network's stricter
        // NetworkDevice-producing parser discards it.
        let observations = parse_neigh(NEIGH_OUTPUT);
        assert_eq!(observations.len(), 3);
        assert!(observations.iter().all(|o| o.tier == RouterSourceTier::NeighborTable));

        let state_only = observations
            .iter()
            .find(|o| o.observation.ip == "192.168.1.99".parse::<IpAddr>().unwrap())
            .unwrap();
        assert_eq!(state_only.observation.mac, None);
        assert_eq!(state_only.observation.neighbor_state, Some(NeighborState::Failed));
    }

    #[test]
    fn test_parse_neigh_carries_mac_and_state() {
        let observations = parse_neigh(NEIGH_OUTPUT);
        let first = &observations[0].observation;
        assert_eq!(first.mac, Some(MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap()));
        assert_eq!(first.neighbor_state, Some(NeighborState::Reachable));
    }

    // Real output captured 2026-08-02 against the actual router (see
    // ssh-setup-notes / router-integration in the wiki). The first line is
    // the router's own local WireGuard identity (5 fields); the rest are
    // peers (9 fields).
    const WG_DUMP_OUTPUT: &str = "BowersNet\tmKajgC03HJL4+KW2k9jy7dQ9hpzeRVg7L0CCy9eqHU8=\tGNG56/JGC+YhaCo3KmuFqYylhG5NBwG+xPTebD6FLUE=\t51823\toff
BowersNet\tgN4DvXs/DP060P0yLzfTYBMqUAh/qHznuPHw1vOfCUg=\t(none)\t(none)\t10.20.30.3/32\t0\t0\t0\toff
BowersNet\t+mP28ziwQ2zZqlBBfYI5xDA3djASAQ66jJqa9osDCxk=\t(none)\t192.168.1.122:57426\t10.20.30.13/32\t1785651044\t109147828\t282043476\t25";

    const WG_PEERS_OUTPUT: &str = r#"{
    "values": {
        "cfg095927": {
            ".anonymous": true,
            ".type": "wireguard_BowersNet",
            ".name": "cfg095927",
            ".index": 8,
            "description": "Jamie phone",
            "public_key": "gN4DvXs/DP060P0yLzfTYBMqUAh/qHznuPHw1vOfCUg=",
            "allowed_ips": ["10.20.30.3/32"]
        },
        "cfg0d5927": {
            ".anonymous": true,
            ".type": "wireguard_BowersNet",
            ".name": "cfg0d5927",
            ".index": 12,
            "description": "Andrew iPhone",
            "public_key": "+mP28ziwQ2zZqlBBfYI5xDA3djASAQ66jJqa9osDCxk=",
            "route_allowed_ips": "1",
            "persistent_keepalive": "25",
            "allowed_ips": ["10.20.30.13/32"]
        },
        "cfg135927": {
            ".anonymous": true,
            ".type": "wireguard_BowersNet",
            ".name": "cfg135927",
            ".index": 18,
            "public_key": "uELOYvCauwqTTz4HJyiipWTwF6vYzPP9vW7SfGsBOAU=",
            "private_key": "OE+V5V9LiNtgWjVRdDICvUMsPviM0GK1igBMiDkCzHc="
        }
    }
}"#;

    #[test]
    fn test_parse_wg_dump_line_skips_own_identity_row() {
        let peer = parse_wg_dump_line("BowersNet\tmKajgC03HJL4+KW2k9jy7dQ9hpzeRVg7L0CCy9eqHU8=\tGNG56/JGC+YhaCo3KmuFqYylhG5NBwG+xPTebD6FLUE=\t51823\toff");
        assert!(peer.is_none());
    }

    #[test]
    fn test_parse_wg_dump_line_parses_peer_row() {
        let peer = parse_wg_dump_line("BowersNet\tgN4DvXs/DP060P0yLzfTYBMqUAh/qHznuPHw1vOfCUg=\t(none)\t(none)\t10.20.30.3/32\t0\t0\t0\toff").unwrap();
        assert_eq!(peer.public_key, "gN4DvXs/DP060P0yLzfTYBMqUAh/qHznuPHw1vOfCUg=");
        assert_eq!(peer.allowed_ips, vec!["10.20.30.3".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_parse_wg_peers_excludes_router_own_identity() {
        let peer_names = parse_wg_peers(WG_PEERS_OUTPUT).unwrap();
        assert_eq!(peer_names.len(), 2);
        assert!(peer_names.contains_key("gN4DvXs/DP060P0yLzfTYBMqUAh/qHznuPHw1vOfCUg="));
        assert!(!peer_names.contains_key("uELOYvCauwqTTz4HJyiipWTwF6vYzPP9vW7SfGsBOAU="));
    }

    #[test]
    fn test_parse_wireguard_merges_dump_and_peer_names() {
        let observations = parse_wireguard(WG_DUMP_OUTPUT, WG_PEERS_OUTPUT).unwrap();
        assert_eq!(observations.len(), 2);
        assert!(observations.iter().all(|o| o.tier == RouterSourceTier::WireGuard));

        let jamie_phone = observations
            .iter()
            .find(|o| o.observation.ip == "10.20.30.3".parse::<IpAddr>().unwrap())
            .unwrap();
        assert_eq!(
            jamie_phone.observation.wireguard_public_key.as_ref().map(|k| k.as_str()),
            Some("gN4DvXs/DP060P0yLzfTYBMqUAh/qHznuPHw1vOfCUg=")
        );
        assert_eq!(
            jamie_phone.observation.friendly_name.as_ref().map(|f| f.as_str()),
            Some("Jamie phone")
        );
    }

    #[test]
    fn test_parse_wireguard_never_exposes_private_key() {
        let observations = parse_wireguard(WG_DUMP_OUTPUT, WG_PEERS_OUTPUT).unwrap();
        // The router's own identity (uELO...) has no allowed_ips in wg-dump
        // peer rows (it's the 5-field own-identity line, already skipped),
        // so it cannot appear here at all — this asserts that absence.
        assert!(!observations.iter().any(|o| {
            o.observation.ip == "10.20.30.99".parse::<IpAddr>().unwrap()
        }));
        assert_eq!(observations.len(), 2);
    }

    const WAN_STATUS_OUTPUT: &str = r#"{
    "up": true,
    "pending": false,
    "available": true,
    "device": "pppoe-wan",
    "ipv4-address": [
        {
            "address": "203.0.113.7",
            "mask": 32
        }
    ]
}"#;

    #[test]
    fn test_parse_wan_ip_extracts_ipv4_address() {
        let wan_address = parse_wan_ip(WAN_STATUS_OUTPUT).unwrap();
        assert_eq!(wan_address, Some(WanAddress::new("203.0.113.7".parse().unwrap())));
    }

    #[test]
    fn test_parse_wan_ip_none_when_no_ipv4_address() {
        let output = r#"{"up": true, "ipv4-address": []}"#;
        let wan_address = parse_wan_ip(output).unwrap();
        assert_eq!(wan_address, None);
    }
}
