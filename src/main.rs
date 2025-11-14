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

    // Exponential backoff: initial attempt, then retry after 1s, 2s, 4s, 8s
    // Total: 5 attempts, up to 15 seconds of delays
    let retry_delays_secs = [1u64, 2, 4, 8];
    let total_attempts = retry_delays_secs.len() + 1;

    let network_data = std::iter::once(None)
        .chain(retry_delays_secs.iter().map(|&delay| Some(delay)))
        .enumerate()
        .find_map(|(attempt, delay_option)| {
            // Sleep before retry attempts (not before initial attempt)
            if let Some(delay_secs) = delay_option {
                std::thread::sleep(std::time::Duration::from_secs(delay_secs));
            }

            match collector.collect_network_info() {
                // Success with devices found - return immediately
                Ok(data) if !data.devices.is_empty() => Some(Ok(data)),

                // Last attempt - return even if no devices
                Ok(data) if attempt == total_attempts - 1 => Some(Ok(data)),

                // No devices yet - continue retrying
                Ok(_) => None,

                // Error - fail immediately without retrying
                Err(e) => Some(Err(e)),
            }
        })
        .unwrap_or_else(|| {
            // Safety: Should never reach here as last attempt always returns Some
            // Include fallback for absolute safety
            collector.collect_network_info()
        });

    match network_data {
        Ok(data) => {
            let output = formatter.format(&data)?;
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
