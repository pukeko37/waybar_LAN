//! Hardcoded vendor/platform lookup, scoped to Andrew's own known devices
//! plus a small set of recognised non-IEEE conventions (currently just
//! QEMU/libvirt's `52:54:00`) — not the full IEEE OUI registry. No live
//! internet lookup. Table entries are added only for devices actually
//! observed on the network, never speculatively. Per
//! [[oui-vendor-lookup-and-composed-identity]].

use super::values::{MacAddress, ManufacturerName};

/// The result of classifying a MAC's 3-octet prefix. Three real outcomes,
/// not a collapsing `Option` — `LocallyAdministered` and `Unregistered`
/// are genuinely different facts (an address that's structurally
/// unresolvable by design, vs. a real registered OUI this table just
/// doesn't have yet) and must stay distinguishable in the type, the same
/// illegal-state shape [[device-recency-and-removal]] already fixed once
/// for WireGuard handshake activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendorClassification {
    /// The prefix matched a table entry — either a real IEEE OUI or a
    /// recognised non-IEEE convention (e.g. QEMU/libvirt).
    Known(ManufacturerName),
    /// No table match, and the address is locally administered (U/L bit
    /// set) — never IEEE-registered by design. A lookup could never
    /// legitimately resolve this regardless of table content.
    LocallyAdministered,
    /// No table match, and the address is universally administered — a
    /// real OUI, just not one this table has catalogued yet.
    Unregistered,
}

/// Short display labels, not the full IEEE-registered legal name — the
/// tooltip is space-constrained and a legal-entity suffix
/// (`Inc.`/`Ltd.`/`Co.,Ltd`) adds nothing a user needs to identify a
/// device on their own LAN. Full legal names and lookup provenance are
/// recorded in [[oui-vendor-lookup-and-composed-identity]], not carried
/// into code. `52:54:00` is the one locally-administered entry here —
/// QEMU/libvirt's own convention for virtual NICs, not an IEEE
/// registration, kept anyway because identifying "this is a VM" is more
/// useful than a vendor name would be.
const VENDOR_TABLE: &[(&str, &str)] = &[
    ("A4:77:33", "Google"),
    ("64:07:F6", "Samsung"),
    ("18:C0:4D", "Gigabyte"),
    ("2C:7C:F2", "Apple"),
    ("A0:02:DC", "Amazon"),
    ("BC:5F:F4", "ASRock"),
    ("52:54:00", "QEMU/KVM"),
];

/// Classifies a MAC by its 3-octet prefix. The table is checked first,
/// regardless of the U/L bit — a hit (IEEE vendor or recognised
/// convention alike) always wins; only a miss falls through to the U/L
/// check. Per [[oui-vendor-lookup-and-composed-identity]].
pub fn classify(mac: &MacAddress) -> VendorClassification {
    let prefix = &mac.as_str()[0..8]; // "AA:BB:CC"
    match VENDOR_TABLE.iter().find(|(table_prefix, _)| *table_prefix == prefix) {
        Some((_, vendor)) => VendorClassification::Known(ManufacturerName::new((*vendor).to_string())),
        None if mac.is_locally_administered() => VendorClassification::LocallyAdministered,
        None => VendorClassification::Unregistered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_known_ieee_vendor() {
        let mac = MacAddress::new("2C:7C:F2:ED:4D:13".to_string()).unwrap();
        assert_eq!(classify(&mac), VendorClassification::Known(ManufacturerName::new("Apple".to_string())));
    }

    #[test]
    fn test_classify_recognised_locally_administered_convention() {
        let mac = MacAddress::new("52:54:00:AE:AF:A7".to_string()).unwrap();
        assert_eq!(classify(&mac), VendorClassification::Known(ManufacturerName::new("QEMU/KVM".to_string())));
    }

    #[test]
    fn test_classify_locally_administered_unrecognised() {
        // A real iPhone private-Wi-Fi address, not in the table.
        let mac = MacAddress::new("DE:C9:87:75:31:6E".to_string()).unwrap();
        assert_eq!(classify(&mac), VendorClassification::LocallyAdministered);
    }

    #[test]
    fn test_classify_universal_unregistered() {
        // A universal address (U/L bit clear) not in the table.
        let mac = MacAddress::new("00:11:22:33:44:55".to_string()).unwrap();
        assert_eq!(classify(&mac), VendorClassification::Unregistered);
    }

    #[test]
    fn test_classify_is_case_insensitive_via_mac_normalization() {
        let mac = MacAddress::new("a4:77:33:2d:b5:01".to_string()).unwrap();
        assert_eq!(classify(&mac), VendorClassification::Known(ManufacturerName::new("Google".to_string())));
    }
}
