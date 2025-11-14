//! Data collection module for network information.

pub mod collector;
pub mod mdns_discovery;
pub mod models;
pub mod proc_parsers;
pub mod ssdp_discovery;

pub use collector::*;

#[cfg(test)]
mod tests {
    #[test]
    fn test_placeholder() {
        // Placeholder test to ensure module compiles
        assert!(true);
    }
}
