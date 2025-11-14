//! LAN monitoring application with domain-driven design and type safety.
//! Monitors devices on the local network and outputs JSON for Waybar.

#![allow(clippy::upper_case_acronyms)] // NAS is standard industry acronym

mod data;
mod display;
mod domain;

use anyhow::Result;
use data::NetworkCollector;
use display::WaybarFormatter;

fn main() -> Result<()> {
    let collector = NetworkCollector::new()?;
    let formatter = WaybarFormatter::new();

    match collector.collect_network_info() {
        Ok(network_data) => {
            let output = formatter.format(&network_data)?;
            println!("{}", serde_json::to_string(&output)?);
        }
        Err(e) => {
            let error_output = WaybarFormatter::create_error_output(e);
            println!("{}", serde_json::to_string(&error_output)?);
        }
    }

    Ok(())
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_error_handling_flow() {
        let error = anyhow::anyhow!("Test error");
        let error_output = WaybarFormatter::create_error_output(error);

        assert!(error_output.text.contains("unavailable"));
        assert!(error_output.tooltip.contains("Test error"));

        // Validate JSON serialization
        let json = serde_json::to_string(&error_output).unwrap();
        assert!(json.contains("text"));
        assert!(json.contains("tooltip"));
    }
}
