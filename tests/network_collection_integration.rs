//! Integration tests against the real network stack.
//!
//! Network-dependent: these hit the live network and open an mDNS daemon,
//! rather than exercising pure logic (see the `rust-style` skill's
//! test-driven-development section on why these live here, not in `src/`).

use waybar_lan::infra::network::mdns_discovery::MdnsDiscovery;
use waybar_lan::infra::network::NetworkCollector;

#[test]
fn test_collect_network_info() {
    let collector = NetworkCollector::new().unwrap();
    let result = collector.collect_network_info();

    // Should succeed even if no devices found
    assert!(result.is_ok());

    let snapshot = result.unwrap();
    // We should have at least loopback interface
    // (though it might not have an IPv4 address)
    println!("Found {} interfaces", snapshot.interfaces.len());
    println!("Found {} devices", snapshot.devices.len());
    if let Some(gw) = snapshot.gateway {
        println!("Gateway: {}", gw);
    }
}

#[test]
fn test_discover_services() {
    let discovery = MdnsDiscovery::new().unwrap();
    let services = discovery.discover_services(std::time::Duration::from_secs(2));
    assert!(services.is_ok());

    // We may or may not find services depending on the network
    let services = services.unwrap();
    println!("Found services on {} IPs", services.len());
}
