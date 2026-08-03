//! Router adapter: SSH into the LAN's OpenWrt router as a second device
//! source, implementing `app::RouterFetcher`. See the `router-integration`
//! decision and `infra-router-module-rules` in the project wiki.

pub mod models;
pub mod ssh;

use crate::app::{RouterFetcher, RouterSnapshot};

/// Connects to the router as `andrew` (`user@host`, e.g.
/// `andrew@192.168.1.1`) via the SSH dispatcher whitelist.
pub struct SshRouterFetcher {
    host: String,
}

impl SshRouterFetcher {
    pub fn new(host: String) -> Self {
        Self { host }
    }
}

impl RouterFetcher for SshRouterFetcher {
    fn collect(&self) -> Result<RouterSnapshot, anyhow::Error> {
        let leases_output = ssh::run_dispatch_command(&self.host, "leases")?;
        let neigh_output = ssh::run_dispatch_command(&self.host, "neigh")?;
        let wg_dump_output = ssh::run_dispatch_command(&self.host, "wg-dump")?;
        let wg_peers_output = ssh::run_dispatch_command(&self.host, "wg-peers")?;
        let clients_output = ssh::run_dispatch_command(&self.host, "clients")?;
        let wan_ip_output = ssh::run_dispatch_command(&self.host, "wan-ip")?;

        let mut observations = models::parse_leases(&leases_output);
        observations.extend(models::parse_neigh(&neigh_output));
        observations.extend(models::parse_wireguard(&wg_dump_output, &wg_peers_output)?);

        Ok(RouterSnapshot {
            observations,
            wifi_clients: models::parse_clients(&clients_output),
            wan_address: models::parse_wan_ip(&wan_ip_output)?,
        })
    }
}
