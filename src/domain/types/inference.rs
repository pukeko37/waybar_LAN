//! Heuristic device-identity inference: a second `impl NetworkDevice` block,
//! separate from the entity/data-model definitions in `device`. This
//! heuristic set is expected to grow — keep the priority-ordered `or_else`
//! chain shape rather than a monolithic match, per [[domain-module-rules]].

use super::device::{DeviceIdentity, DeviceType, Hostname, NetworkDevice};
use super::values::{FriendlyName, ManufacturerName};

impl NetworkDevice {
    /// Build DeviceIdentity from collected information
    /// Uses priority-based inference for device type, manufacturer, and friendly name
    pub fn build_identity(mut self) -> Self {
        self.identity = DeviceIdentity {
            device_type: self.infer_device_type(),
            manufacturer: self.extract_manufacturer(),
            friendly_name: self.extract_friendly_name(),
        };
        self
    }

    /// Infer device type from available information
    fn infer_device_type(&self) -> DeviceType {
        self.infer_from_services()
            .or_else(|| self.infer_from_manufacturer_and_model())
            .or_else(|| self.infer_from_hostname())
            .unwrap_or(DeviceType::Unknown)
    }

    /// Infer device type from mDNS service types
    fn infer_from_services(&self) -> Option<DeviceType> {
        if self.has_service("_printer") || self.has_service("_ipp") {
            return Some(DeviceType::Printer);
        }
        if self.has_service("_googlecast")
            || (self.has_service("_airplay") && self.has_service("_spotify-connect")) {
            return Some(DeviceType::Television);
        }
        if self.has_service("_raop") && !self.has_service("_airplay") {
            return Some(DeviceType::Speaker);
        }
        if self.has_service("_ssh") && self.has_service("_smb") {
            return Some(DeviceType::NAS);
        }
        if self.has_service("_homekit") {
            return Some(DeviceType::SmartHome);
        }
        None
    }

    /// Infer device type from manufacturer and model with service heuristics
    fn infer_from_manufacturer_and_model(&self) -> Option<DeviceType> {
        let manufacturer_from_hostname = if let Hostname::Resolved(hostname) = &self.hostname {
            Some(hostname.to_lowercase())
        } else {
            None
        };

        // Check for TV brands with media services
        let is_tv_brand = |name: &str| {
            name.contains("samsung") || name.contains("lg") || name.contains("sony")
                || name.contains("vizio") || name.contains("tcl") || name.contains("hisense")
        };
        let has_tv_brand = manufacturer_from_hostname.as_ref().map(|m| is_tv_brand(m)).unwrap_or(false);

        if has_tv_brand && (self.has_service("_airplay") || self.has_service("_googlecast")
            || self.has_service("_spotify-connect") || self.has_service("_raop")) {
            return Some(DeviceType::Television);
        }

        // Check for printer brands
        let is_printer_brand = |name: &str| {
            name.contains("brother") || name.contains("hp") || name.contains("canon")
                || name.contains("epson") || name.contains("xerox")
        };
        let has_printer_brand = manufacturer_from_hostname.as_ref().map(|m| is_printer_brand(m)).unwrap_or(false);

        if has_printer_brand {
            return Some(DeviceType::Printer);
        }

        // Check for NAS manufacturers in hostname
        if let Some(hostname) = &manufacturer_from_hostname
            && (hostname.contains("synology") || hostname.contains("qnap"))
        {
            return Some(DeviceType::NAS);
        }

        None
    }

    /// Infer device type from hostname patterns
    fn infer_from_hostname(&self) -> Option<DeviceType> {
        let Hostname::Resolved(hostname) = &self.hostname else { return None };
        let hostname_lower = hostname.to_lowercase();

        if hostname_lower.contains("router") || hostname_lower.contains("gateway") {
            return Some(DeviceType::Router);
        }
        if hostname_lower.contains("nas") {
            return Some(DeviceType::NAS);
        }
        if hostname_lower.contains("printer") {
            return Some(DeviceType::Printer);
        }
        // Check for tablets before phones (since "Galaxy Tab" contains "galaxy")
        if hostname_lower.contains("ipad") || hostname_lower.contains("tablet")
            || hostname_lower.contains("-tab-") || hostname_lower.contains(" tab ")
            || hostname_lower.starts_with("tab") {
            return Some(DeviceType::Tablet);
        }
        if hostname_lower.contains("iphone") || hostname_lower.contains("galaxy")
            || hostname_lower.contains("pixel") {
            return Some(DeviceType::MobileDevice);
        }
        None
    }

    /// Extract manufacturer from available sources
    fn extract_manufacturer(&self) -> Option<ManufacturerName> {
        // Extract from hostname
        if let Hostname::Resolved(hostname) = &self.hostname {
            let hostname_lower = hostname.to_lowercase();
            let known_manufacturers = ["samsung", "lg", "sony", "brother", "hp",
                                      "canon", "epson", "apple", "google", "amazon"];
            for mfr in &known_manufacturers {
                if hostname_lower.contains(mfr) {
                    // Capitalize first letter
                    let capitalized = format!("{}{}",
                        mfr[0..1].to_uppercase(),
                        &mfr[1..]);
                    return Some(ManufacturerName::new(capitalized));
                }
            }
        }

        None
    }

    /// Extract friendly name from available sources
    fn extract_friendly_name(&self) -> Option<FriendlyName> {
        // DNS hostname (if available and descriptive)
        if let Hostname::Resolved(hostname) = &self.hostname
            && !hostname.is_empty() && !hostname.starts_with('_')
        {
            return Some(FriendlyName::new(hostname.clone()));
        }

        None
    }

    /// Check if device has a specific mDNS service (case-insensitive partial match)
    fn has_service(&self, service_type: &str) -> bool {
        self.services.iter().any(|s|
            s.service_type.as_str().to_lowercase().contains(&service_type.to_lowercase())
        )
    }
}
