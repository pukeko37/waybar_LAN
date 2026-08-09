//! Presentation primitives: colour, emoji, identity composition, timestamp
//! formatting, and the fixed-space indentation scheme. Pure functions only —
//! no `NetworkData`/`NetworkDevice` traversal, that lives in `formatter.rs`.

use crate::domain::{ActivityStatus, DeviceIdentity, DeviceType, SignalStrength};
use std::time::{SystemTime, UNIX_EPOCH};

/// Get Pango markup for coloring text based on activity status
pub(super) fn pango_color(status: ActivityStatus) -> (&'static str, &'static str) {
    match status {
        ActivityStatus::Active => ("<span color='#00FF00'>", "</span>"), // Green
        ActivityStatus::Recent => ("<span color='#FFFF00'>", "</span>"), // Yellow
        ActivityStatus::Idle => ("", ""),                                // White (default)
        ActivityStatus::Stale => ("<span color='#888888'>", "</span>"), // Grey
        // Removed devices are filtered out of the tooltip before rendering
        // (see WaybarFormatter::format) — this arm should be unreachable in
        // practice. Rust's exhaustiveness check still requires it, so it's
        // handled the same as Stale rather than with `unreachable!()`: if
        // the filter and this match ever drift apart, a grey fallback is
        // the safe failure for a UI widget, not a panic.
        ActivityStatus::Removed => ("<span color='#888888'>", "</span>"),
    }
}

/// Wrap text with color markup based on activity status
pub(super) fn colorize(status: ActivityStatus, text: &str) -> String {
    let (start, end) = pango_color(status);
    format!("{}{}{}", start, text, end)
}

/// Fixed indent for a device row under its group heading, per
/// [[wifi-signal-new-device-and-flat-layout]] — supersedes the
/// [[nested-tree-by-access-path]] tree-glyph nesting this replaced.
/// Illustrative width (~3 em-dash-widths, Andrew's stated target); exact
/// character count is a visual-tuning call against the tooltip's actual
/// Pango-rendered font, not derived from character-width arithmetic.
pub(super) const INDENT: &str = "      ";

/// A device row's sub-lines (`Services`, `Gateway`/`WAN`/`DNS`) indent one
/// further `INDENT` step beyond their device row — not an independently
/// tuned second value.
pub(super) fn sub_indent() -> String {
    format!("{INDENT}{INDENT}")
}

/// Splits a Unix day count into (year, month, day), proleptic Gregorian
/// calendar. Howard Hinnant's `civil_from_days` algorithm — a closed-form
/// calculation with no lookup tables — chosen per [[updated-timestamp-footer]]
/// because [[waybar-lan-workspace-rules]] rules out the `time`/`chrono`
/// crates `waybar_weather` uses for its equivalent "Updated:" footer, in
/// favour of `std::time` alone.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
}

/// Formats a `SystemTime` as `YYYY-MM-DD HH:MMZ` (UTC), matching the
/// "Updated:" footer format `waybar_weather`'s `LastUpdated::format_display`
/// produces, per [[updated-timestamp-footer]].
pub(super) fn format_utc_timestamp(time: SystemTime) -> String {
    let total_secs = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = total_secs.div_euclid(86400);
    let secs_of_day = total_secs.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    format!("{:04}-{:02}-{:02} {:02}:{:02}Z", year, month, day, hour, minute)
}

/// Signal-strength glyph for a Wi-Fi device, tiered by SNR (dB), appended at
/// the end of the device line — see [[wifi-signal-icon-at-line-end]], which
/// moved this from a prepended fixed-width column (its original spot under
/// [[wifi-signal-new-device-and-flat-layout]]) after Pango's non-monospace
/// rendering left that column's blank placeholder and block glyphs at
/// visibly different widths, unevenly offsetting Wi-Fi rows from the rest.
/// Plain block characters (`▂▄▆█`), not emoji, deliberately — chosen for
/// [[wifi-signal-new-device-and-flat-layout]] and unaffected by the move.
/// `None` (a non-Wi-Fi device, or a Wi-Fi device whose SNR couldn't be
/// parsed) renders nothing — there's no following column left to keep
/// aligned now that the icon sits at line end.
pub(super) fn signal_suffix(signal: Option<SignalStrength>) -> String {
    match signal {
        None => String::new(),
        Some(s) if s.snr_db() < 10 => " ▂".to_string(),
        Some(s) if s.snr_db() < 20 => " ▄".to_string(),
        Some(s) if s.snr_db() < 30 => " ▆".to_string(),
        Some(_) => " █".to_string(),
    }
}

/// Emoji for a device type
pub(super) fn device_type_emoji(device_type: DeviceType) -> &'static str {
    match device_type {
        DeviceType::Television => "📺",
        DeviceType::Printer => "🖨 ",     // Extra space for alignment
        DeviceType::Router => "🌐",
        DeviceType::Computer => "💻",
        DeviceType::NAS => "🗄",
        DeviceType::MobileDevice => "📞", // Telephone receiver for phones
        DeviceType::Tablet => "📋",       // Clipboard for tablets
        DeviceType::Speaker => "🔊",
        DeviceType::StreamingDevice => "📺",
        DeviceType::SmartHome => "🏠",
        DeviceType::Unknown => "🖥 ",     // Extra space for alignment
    }
}

/// Format device identity with emoji, composing two independent facts
/// rather than choosing one between them: a *classification* label
/// (manufacturer + device type together when both are known, either
/// alone, or the bare `device_type.as_str()` fallback — `"Device"` for
/// `DeviceType::Unknown` — when neither is) and an *instance* label
/// (`friendly_name`, when known; `format_device_entry` already appends
/// `({primary_address})` regardless, so there's no need for a MAC/address
/// fallback here too). Per [[oui-vendor-lookup-and-composed-identity]]:
/// manufacturer and friendly_name answer different questions and
/// shouldn't compete for one slot — once OUI makes manufacturer commonly
/// available even without a hostname, a winner-take-all chain would start
/// hiding known hostnames behind a generic vendor name.
/// Format: `{Emoji} {Classification}` or `{Emoji} {Classification} — {Instance}`
pub(super) fn format_identity(identity: &DeviceIdentity) -> String {
    let emoji = device_type_emoji(identity.device_type);

    let classification = match &identity.manufacturer {
        Some(mfr) if identity.device_type != DeviceType::Unknown => {
            format!("{} {}", mfr.as_str(), identity.device_type.as_str())
        }
        Some(mfr) => mfr.as_str().to_string(),
        None => identity.device_type.as_str().to_string(),
    };

    match &identity.friendly_name {
        Some(name) => format!("{emoji} {classification} — {}", name.as_str()),
        None => format!("{emoji} {classification}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_identity_composes_manufacturer_type_and_instance_name() {
        let identity = DeviceIdentity {
            device_type: DeviceType::Television,
            manufacturer: Some(crate::domain::ManufacturerName::new("Samsung".to_string())),
            friendly_name: Some(crate::domain::FriendlyName::new("living-room-tv".to_string())),
        };
        assert_eq!(format_identity(&identity), "📺 Samsung Television — living-room-tv");
    }

    #[test]
    fn test_format_identity_manufacturer_known_but_no_instance_name() {
        // The 192.168.1.159 case that motivated this: an OUI hit with no
        // hostname must not disappear back to a bare device-type fallback.
        // `device_type` is Unknown here, so the classification is the
        // manufacturer alone, no redundant "Device" suffix.
        let identity = DeviceIdentity {
            device_type: DeviceType::Unknown,
            manufacturer: Some(crate::domain::ManufacturerName::new("Apple".to_string())),
            friendly_name: None,
        };
        assert_eq!(format_identity(&identity), "🖥  Apple");
    }

    #[test]
    fn test_format_identity_instance_name_known_but_no_manufacturer_or_type() {
        // A known hostname must not get hidden behind a generic type/vendor
        // fallback — this was the regression this composition exists to avoid.
        let identity = DeviceIdentity {
            device_type: DeviceType::Unknown,
            manufacturer: None,
            friendly_name: Some(crate::domain::FriendlyName::new("kaukau".to_string())),
        };
        assert_eq!(format_identity(&identity), "🖥  Device — kaukau");
    }

    #[test]
    fn test_format_identity_nothing_known_falls_back_to_bare_device_type() {
        let identity = DeviceIdentity::new();
        assert_eq!(format_identity(&identity), "🖥  Device");
    }

    #[test]
    fn test_format_utc_timestamp_known_epoch() {
        // 2023-01-13 14:30:00 UTC, per waybar_weather's own equivalent test fixture.
        let time = UNIX_EPOCH + std::time::Duration::from_secs(1673620200);
        assert_eq!(format_utc_timestamp(time), "2023-01-13 14:30Z");
    }

    #[test]
    fn test_format_utc_timestamp_epoch_zero() {
        assert_eq!(format_utc_timestamp(UNIX_EPOCH), "1970-01-01 00:00Z");
    }

    #[test]
    fn test_signal_suffix_tiers_by_snr() {
        assert_eq!(signal_suffix(None), "");
        assert_eq!(signal_suffix(Some(SignalStrength::from_snr_db(5))), " ▂");
        assert_eq!(signal_suffix(Some(SignalStrength::from_snr_db(15))), " ▄");
        assert_eq!(signal_suffix(Some(SignalStrength::from_snr_db(25))), " ▆");
        assert_eq!(signal_suffix(Some(SignalStrength::from_snr_db(35))), " █");
    }
}
