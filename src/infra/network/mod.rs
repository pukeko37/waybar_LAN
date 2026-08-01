//! Network data collection module. I/O boundary confined to this module
//! (shelling out to `ip`/`ping`, reading `/proc` and `/etc/resolv.conf`,
//! mDNS, reverse-DNS). Implements `app::NetworkFetcher`.

pub mod collector;
pub mod mdns_discovery;
pub mod models;
pub mod proc_parsers;

pub use collector::*;
