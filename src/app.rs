//! Application layer: orchestrates domain logic through port traits.
//!
//! Defines the port traits (`NetworkFetcher`, `NetworkFormatter`) that
//! infrastructure adapters implement. No `use crate::infra::` imports here
//! outside `#[cfg(test)]`.

use crate::domain::NetworkSnapshot;

/// Port trait for collecting a network snapshot.
///
/// Uses `anyhow::Error` because system/network collection errors are
/// genuinely open-ended infrastructure concerns.
pub trait NetworkFetcher {
    fn collect(&self) -> Result<NetworkSnapshot, anyhow::Error>;
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
}
