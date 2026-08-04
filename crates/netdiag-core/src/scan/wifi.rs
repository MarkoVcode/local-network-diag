//! Wi-Fi analysis shared by all three platform backends.
//!
//! Each OS gathers the raw network list differently; everything after that —
//! band classification, channel occupancy, the congestion recommendation — is
//! identical and lives here.

use crate::types::{ChannelUsage, WifiInfo, WifiNetwork};
use std::collections::BTreeMap;

pub fn band_for_frequency(mhz: u32) -> &'static str {
    match mhz {
        2400..=2499 => "2.4 GHz",
        4900..=5924 => "5 GHz",
        5925..=7125 => "6 GHz",
        _ => "unknown",
    }
}

/// Falls back to channel numbering where a driver reports no frequency.
pub fn band_for_channel(channel: u32) -> &'static str {
    match channel {
        1..=14 => "2.4 GHz",
        32..=177 => "5 GHz",
        // 6 GHz channels overlap 5 GHz numbering; without a frequency the best
        // that can be said is "unknown" rather than guessing wrong.
        _ => "unknown",
    }
}

/// Converts dBm to the 0-100 quality figure the other platforms report, using
/// the same mapping NetworkManager applies so numbers are comparable across OSes.
pub fn dbm_to_quality(dbm: i32) -> u8 {
    if dbm <= -100 {
        0
    } else if dbm >= -50 {
        100
    } else {
        (2 * (dbm + 100)) as u8
    }
}

/// 2.4 GHz channels overlap: a network on channel 6 is interfered with by
/// anything on 4-8. 5/6 GHz channels do not overlap, so only exact matches count.
fn overlaps(a_channel: u32, a_band: &str, b_channel: u32, b_band: &str) -> bool {
    if a_band != b_band {
        return false;
    }
    if a_band == "2.4 GHz" {
        return a_channel.abs_diff(b_channel) < 5;
    }
    a_channel == b_channel
}

pub fn assemble(interface: Option<String>, mut networks: Vec<WifiNetwork>) -> WifiInfo {
    networks.sort_by(|a, b| b.signal.cmp(&a.signal));

    let current = networks.iter().find(|n| n.active).cloned();

    let mut usage: BTreeMap<(String, u32), u32> = BTreeMap::new();
    for network in &networks {
        if network.band == "unknown" {
            continue;
        }
        *usage
            .entry((network.band.clone(), network.channel))
            .or_insert(0) += 1;
    }

    let channel_usage: Vec<ChannelUsage> = usage
        .into_iter()
        .map(|((band, channel), count)| ChannelUsage {
            is_current: current
                .as_ref()
                .map(|c| c.channel == channel && c.band == band)
                .unwrap_or(false),
            channel,
            band,
            count,
        })
        .collect();

    let recommendation = current.as_ref().map(|current| {
        let same_band: Vec<&WifiNetwork> =
            networks.iter().filter(|n| n.band == current.band).collect();

        // Count every overlapping radio in the band, then discount ourselves.
        //
        // Excluding self by comparing BSSIDs looks natural but breaks on any
        // platform that does not report a BSSID: `None != None` is false, so
        // every network would be treated as self and contention would always
        // read zero.
        let overlapping = same_band
            .iter()
            .filter(|n| overlaps(n.channel, &n.band, current.channel, &current.band))
            .count();
        let contention = overlapping.saturating_sub(1);

        let candidates: Vec<u32> = if current.band == "2.4 GHz" {
            vec![1, 6, 11]
        } else {
            let mut channels: Vec<u32> = same_band.iter().map(|n| n.channel).collect();
            channels.sort_unstable();
            channels.dedup();
            channels
        };

        let best = candidates
            .iter()
            .map(|channel| {
                let load = same_band
                    .iter()
                    .filter(|n| overlaps(n.channel, &n.band, *channel, &current.band))
                    .count();
                (*channel, load)
            })
            .min_by_key(|(_, load)| *load);

        let plural = if contention == 1 { "" } else { "s" };

        match best {
            _ if contention == 0 => format!(
                "Channel {} is clear — no other visible AP overlaps it.",
                current.channel
            ),
            Some((channel, load)) if load < contention => format!(
                "{contention} other AP{plural} overlap channel {}. Channel {channel} looks quieter ({load} overlapping).",
                current.channel
            ),
            _ => format!(
                "{contention} other AP{plural} overlap channel {}, but no visible channel in the {} band is clearly better.",
                current.channel, current.band
            ),
        }
    });

    WifiInfo {
        interface,
        current,
        networks,
        channel_usage,
        recommendation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(ssid: &str, channel: u32, band: &str, signal: u8, active: bool) -> WifiNetwork {
        WifiNetwork {
            ssid: ssid.into(),
            // Unique per SSID: real radios never share a BSSID, and a fixture
            // that duplicated them would hide bugs in the contention count.
            bssid: Some(format!("00:00:00:00:{:02x}:{channel:02x}", ssid.len())),
            active,
            signal,
            channel,
            band: band.into(),
            rate: None,
            security: Some("WPA2".into()),
        }
    }

    #[test]
    fn maps_frequencies_to_bands() {
        assert_eq!(band_for_frequency(2437), "2.4 GHz");
        assert_eq!(band_for_frequency(5745), "5 GHz");
        assert_eq!(band_for_frequency(6135), "6 GHz");
        assert_eq!(band_for_frequency(0), "unknown");
    }

    #[test]
    fn converts_dbm_to_the_same_quality_scale_other_platforms_use() {
        assert_eq!(dbm_to_quality(-30), 100);
        assert_eq!(dbm_to_quality(-75), 50);
        assert_eq!(dbm_to_quality(-100), 0);
        assert_eq!(dbm_to_quality(-120), 0);
    }

    #[test]
    fn counts_channel_occupancy_per_band() {
        let networks = vec![
            network("A", 6, "2.4 GHz", 90, false),
            network("B", 6, "2.4 GHz", 80, false),
            network("C", 149, "5 GHz", 97, true),
        ];
        let info = assemble(Some("wlo1".into()), networks);

        let ch6 = info
            .channel_usage
            .iter()
            .find(|u| u.channel == 6 && u.band == "2.4 GHz")
            .unwrap();
        assert_eq!(ch6.count, 2);
        assert!(!ch6.is_current);

        let ch149 = info
            .channel_usage
            .iter()
            .find(|u| u.channel == 149)
            .unwrap();
        assert!(ch149.is_current, "the connected channel must be marked");
    }

    #[test]
    fn reports_a_clear_channel_when_nothing_overlaps() {
        let networks = vec![network("Mine", 149, "5 GHz", 97, true)];
        let info = assemble(None, networks);
        assert!(info.recommendation.unwrap().contains("clear"));
    }

    #[test]
    fn recommends_a_quieter_24ghz_channel_accounting_for_overlap() {
        // Channel 6 is crowded; 1 and 11 are empty. Overlap means 4-8 all count.
        let mut networks = vec![network("Mine", 6, "2.4 GHz", 90, true)];
        for i in 0..4 {
            networks.push(network(&format!("Other{i}"), 6, "2.4 GHz", 70, false));
        }
        let info = assemble(None, networks);
        let recommendation = info.recommendation.unwrap();
        assert!(
            recommendation.contains("Channel 1") || recommendation.contains("Channel 11"),
            "expected a non-overlapping suggestion, got: {recommendation}"
        );
    }

    #[test]
    fn counts_contention_even_when_the_platform_reports_no_bssid() {
        // Regression: excluding self by BSSID equality meant `None != None` was
        // false for every network, so contention silently read zero on any
        // platform that omits BSSIDs.
        let mut networks = vec![network("Mine", 6, "2.4 GHz", 90, true)];
        for i in 0..3 {
            networks.push(network(&format!("Other{i}"), 6, "2.4 GHz", 70, false));
        }
        for network in networks.iter_mut() {
            network.bssid = None;
        }

        let info = assemble(None, networks);
        let recommendation = info.recommendation.unwrap();
        assert!(
            !recommendation.contains("clear"),
            "three overlapping APs must not report a clear channel: {recommendation}"
        );
        assert!(
            recommendation.contains('3'),
            "expected a count of 3, got: {recommendation}"
        );
    }

    #[test]
    fn treats_2ghz_neighbours_within_five_channels_as_overlapping() {
        assert!(
            overlaps(6, "2.4 GHz", 8, "2.4 GHz"),
            "channel 8 bleeds into 6"
        );
        assert!(
            !overlaps(1, "2.4 GHz", 11, "2.4 GHz"),
            "1 and 11 are non-overlapping"
        );
        assert!(
            !overlaps(36, "5 GHz", 40, "5 GHz"),
            "5 GHz channels do not overlap"
        );
        assert!(
            !overlaps(6, "2.4 GHz", 6, "5 GHz"),
            "different bands never overlap"
        );
    }

    #[test]
    fn ignores_unknown_band_entries_in_the_congestion_chart() {
        let networks = vec![
            network("A", 0, "unknown", 50, false),
            network("B", 6, "2.4 GHz", 60, false),
        ];
        let info = assemble(None, networks);
        assert_eq!(info.channel_usage.len(), 1);
    }
}
