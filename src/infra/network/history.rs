//! Persisted per-device recency timestamps, surviving across the app's
//! one-shot polls — see [[device-recency-and-removal]] (`last_observed`)
//! and [[wifi-signal-new-device-and-flat-layout]] (`first_observed`).
//! `main` reads this at the start of a poll and writes it back at the end;
//! `app`'s merge fold takes/returns a plain `HashMap`, never touching the
//! filesystem itself.

use crate::domain::{DeviceHistory, DeviceId};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Entries untouched for this long are dropped on write, so the file
/// doesn't grow unbounded as devices permanently leave the network. Keyed
/// on `last_observed` only — `first_observed` is not a pruning input, just
/// a "how long has this `DeviceId` been known" record.
const PRUNE_AFTER: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Serialized as a flat list, not a JSON object keyed by `DeviceId` —
/// `DeviceId` is an enum, not a string, and `serde_json` object keys must
/// serialize to strings.
#[derive(Serialize)]
struct HistoryEntry {
    id: DeviceId,
    first_observed: SystemTime,
    last_observed: SystemTime,
}

/// Read-side shape, tolerating a missing `first_observed` — files written
/// before [[wifi-signal-new-device-and-flat-layout]] added it. `load`
/// backfills a missing value from that same entry's `last_observed`, never
/// from "now" — upgrading must not flag every already-known device as
/// newly observed.
#[derive(Deserialize)]
struct RawHistoryEntry {
    id: DeviceId,
    #[serde(default)]
    first_observed: Option<SystemTime>,
    last_observed: SystemTime,
}

/// `$XDG_STATE_HOME/waybar-lan/devices.json`, falling back to
/// `~/.local/state/waybar-lan/devices.json` when `XDG_STATE_HOME` is unset.
/// `None` if neither `XDG_STATE_HOME` nor `HOME` is set — callers should
/// treat that the same as any other missing/unavailable history.
pub fn default_path() -> Option<PathBuf> {
    let base = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .ok()?;
    Some(base.join("waybar-lan").join("devices.json"))
}

/// Missing or corrupt file is treated as empty, not an error — this is
/// optional enrichment (same "partial data beats no data" stance
/// [[infra-network-module-rules]] already takes for mDNS failure), not the
/// router env var's mandatory-once-configured contract.
pub fn load(path: &Path) -> HashMap<DeviceId, DeviceHistory> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_json::from_str::<Vec<RawHistoryEntry>>(&contents).ok())
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| {
                    let first_observed = entry.first_observed.unwrap_or(entry.last_observed);
                    (entry.id, DeviceHistory { first_observed, last_observed: entry.last_observed })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Writes atomically (temp file, then rename over the target) and prunes
/// entries older than [`PRUNE_AFTER`] first.
pub fn save(path: &Path, history: &HashMap<DeviceId, DeviceHistory>) -> anyhow::Result<()> {
    let now = SystemTime::now();
    let entries: Vec<HistoryEntry> = history
        .iter()
        .filter(|&(_, h)| {
            now.duration_since(h.last_observed).unwrap_or(Duration::from_secs(0)) < PRUNE_AFTER
        })
        .map(|(id, h)| HistoryEntry { id: id.clone(), first_observed: h.first_observed, last_observed: h.last_observed })
        .collect();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }

    let tmp_path = path.with_extension("json.tmp");
    let mut tmp_file = std::fs::File::create(&tmp_path)
        .with_context(|| format!("Failed to create {}", tmp_path.display()))?;
    let json = serde_json::to_string_pretty(&entries).context("Failed to serialize device history")?;
    tmp_file
        .write_all(json.as_bytes())
        .with_context(|| format!("Failed to write {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to rename {} to {}", tmp_path.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::MacAddress;
    use std::net::{IpAddr, Ipv4Addr};

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("waybar-lan-history-test-{name}-{}.json", std::process::id()))
    }

    #[test]
    fn test_load_missing_file_is_empty() {
        let path = temp_path("missing");
        assert!(load(&path).is_empty());
    }

    #[test]
    fn test_load_corrupt_file_is_empty() {
        let path = temp_path("corrupt");
        std::fs::write(&path, "not json").unwrap();

        assert!(load(&path).is_empty());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_save_then_load_round_trips() {
        let path = temp_path("round-trip");
        let mac = MacAddress::new("AA:BB:CC:DD:EE:FF".to_string()).unwrap();
        let id = DeviceId::Mac(mac);
        let first_observed = SystemTime::now() - Duration::from_secs(3600);
        let last_observed = SystemTime::now();
        let mut history = HashMap::new();
        history.insert(id.clone(), DeviceHistory { first_observed, last_observed });

        save(&path, &history).unwrap();
        let loaded = load(&path);

        assert_eq!(loaded.get(&id), Some(&DeviceHistory { first_observed, last_observed }));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_save_prunes_entries_older_than_30_days() {
        let path = temp_path("prune");
        let stale_ip = DeviceId::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99)));
        let fresh_ip = DeviceId::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        let mut history = HashMap::new();
        let stale_last_observed = SystemTime::now() - Duration::from_secs(31 * 24 * 60 * 60);
        history.insert(
            stale_ip.clone(),
            DeviceHistory { first_observed: stale_last_observed, last_observed: stale_last_observed },
        );
        let fresh_now = SystemTime::now();
        history.insert(fresh_ip.clone(), DeviceHistory { first_observed: fresh_now, last_observed: fresh_now });

        save(&path, &history).unwrap();
        let loaded = load(&path);

        assert!(!loaded.contains_key(&stale_ip));
        assert!(loaded.contains_key(&fresh_ip));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_load_backfills_missing_first_observed_from_last_observed() {
        // Regression test for the migration rule: a devices.json written
        // before first_observed existed must not make every already-known
        // device look newly observed the moment this ships — the missing
        // value backfills from last_observed, never from "now".
        let path = temp_path("migration");
        // Whole seconds, zero nanos — matches the hand-written JSON exactly,
        // so the round-trip comparison below isn't fighting sub-second
        // precision that has nothing to do with what this test is checking.
        let secs = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 10 * 24 * 60 * 60;
        let last_observed = std::time::UNIX_EPOCH + Duration::from_secs(secs);
        let old_format_json = format!(
            r#"[{{"id":{{"Ip":"192.168.1.50"}},"last_observed":{{"secs_since_epoch":{secs},"nanos_since_epoch":0}}}}]"#
        );
        std::fs::write(&path, old_format_json).unwrap();

        let loaded = load(&path);
        let id = DeviceId::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
        let entry = loaded.get(&id).expect("entry should load despite missing first_observed");

        assert_eq!(entry.first_observed, last_observed);
        assert_eq!(entry.last_observed, last_observed);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_default_path_ends_with_waybar_lan_devices_json() {
        if let Some(path) = default_path() {
            assert!(path.ends_with("waybar-lan/devices.json"));
        }
    }
}
