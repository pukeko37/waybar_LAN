//! Closed error types for the domain layer.

use std::fmt;

/// Domain error enum representing all possible validation failures.
#[derive(Debug)]
pub enum NetworkError {
    /// A MAC address string had the wrong length after normalisation.
    InvalidMacLength(String),
    /// A MAC address string did not split into six colon-separated octets.
    InvalidMacFormat(String),
    /// A MAC address octet was not valid two-digit hexadecimal.
    InvalidMacOctet(String),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMacLength(mac) => write!(f, "Invalid MAC address length: {}", mac),
            Self::InvalidMacFormat(mac) => write!(f, "Invalid MAC address format: {}", mac),
            Self::InvalidMacOctet(part) => write!(f, "Invalid hex in MAC address octet: {}", part),
        }
    }
}

impl std::error::Error for NetworkError {}
