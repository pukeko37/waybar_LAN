//! Domain value objects for network data with type-level safety and validation.

pub mod types;

pub use types::*;

#[cfg(test)]
mod tests {
    #[test]
    fn test_placeholder() {
        // Placeholder test to ensure module compiles
        assert!(true);
    }
}
