//! Display module for formatting network data as Waybar JSON output.
pub mod waybar;
pub use waybar::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::NetworkData;

    #[test]
    fn test_waybar_output_creation() {
        let network_data = NetworkData::new(vec![], vec![], None, vec![]);
        let output = WaybarFormatter::new().format(&network_data).unwrap();

        // Test that output has required fields
        assert!(!output.text.is_empty());
        assert!(!output.tooltip.is_empty());
    }

    #[test]
    fn test_error_output_formatting() {
        let error_output = WaybarFormatter::create_error_output(anyhow::anyhow!("Network error"));

        assert!(error_output.text.contains("unavailable"));
        assert!(error_output.tooltip.contains("Network error"));
    }
}
