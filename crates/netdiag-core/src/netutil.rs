//! IPv4/CIDR helpers, MAC normalisation and the port profiles.
//!
//! Pure and dependency-free so it can be unit-tested without any network.

use crate::types::PortProfile;
use std::net::Ipv4Addr;

/// Refuse anything wider than a /22. A mistyped prefix would otherwise queue a
/// 65k-host sweep and hammer the network.
pub const MIN_PREFIX: u8 = 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedCidr {
    pub network: Ipv4Addr,
    pub prefix: u8,
    pub first: u32,
    pub last: u32,
}

impl ParsedCidr {
    pub fn host_count(&self) -> u32 {
        self.last.saturating_sub(self.first).saturating_add(1)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let value = u32::from(ip);
        value >= self.first && value <= self.last
    }

    pub fn canonical(&self) -> String {
        format!("{}/{}", self.network, self.prefix)
    }

    pub fn hosts(&self) -> impl Iterator<Item = Ipv4Addr> {
        (self.first..=self.last).map(Ipv4Addr::from)
    }
}

pub fn parse_cidr(input: &str) -> Result<ParsedCidr, String> {
    let trimmed = input.trim();
    let (addr_part, prefix_part) = trimmed
        .split_once('/')
        .ok_or_else(|| format!("Invalid CIDR: {trimmed}"))?;

    let addr: Ipv4Addr = addr_part
        .parse()
        .map_err(|_| format!("Invalid IPv4 address in {trimmed}"))?;
    let prefix: u8 = prefix_part
        .parse()
        .map_err(|_| format!("Invalid CIDR prefix in {trimmed}"))?;

    if prefix > 32 {
        return Err(format!("Invalid CIDR prefix in {trimmed}"));
    }
    if prefix < MIN_PREFIX {
        return Err(format!(
            "Range {trimmed} is too large to scan (minimum prefix /{MIN_PREFIX})"
        ));
    }

    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(addr) & mask;
    let broadcast = network | !mask;

    // /31 and /32 have no network/broadcast addresses to reserve.
    let (first, last) = if prefix >= 31 {
        (network, broadcast)
    } else {
        (network + 1, broadcast - 1)
    };

    Ok(ParsedCidr {
        network: Ipv4Addr::from(network),
        prefix,
        first,
        last,
    })
}

/// Derives the enclosing /24 — turns an off-subnet mDNS/SSDP hint into a scannable range.
pub fn to_slash24(ip: Ipv4Addr) -> String {
    let value = u32::from(ip) & 0xFFFF_FF00;
    format!("{}/24", Ipv4Addr::from(value))
}

/// RFC1918 + CGNAT + link-local. Only private space is ever scanned automatically.
pub fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local() || {
        // 100.64.0.0/10 (CGNAT) is not covered by std's is_private.
        let v = u32::from(ip);
        v >= u32::from(Ipv4Addr::new(100, 64, 0, 0))
            && v <= u32::from(Ipv4Addr::new(100, 127, 255, 255))
    }
}

pub fn normalize_mac(mac: &str) -> String {
    mac.trim().to_ascii_lowercase().replace('-', ":")
}

/// The 0x02 bit of the first octet marks a locally-administered address. Modern
/// phones randomize their MAC per network, so an OUI lookup on one of these
/// would confidently report the wrong vendor.
pub fn is_locally_administered(mac: &str) -> bool {
    first_octet(mac).map(|o| o & 0x02 != 0).unwrap_or(false)
}

pub fn is_multicast_mac(mac: &str) -> bool {
    first_octet(mac).map(|o| o & 0x01 != 0).unwrap_or(false)
}

fn first_octet(mac: &str) -> Option<u8> {
    let normalized = normalize_mac(mac);
    let first = normalized.split(':').next()?;
    u8::from_str_radix(first, 16).ok()
}

/// True for the all-zero and broadcast MACs, which carry no identity.
pub fn is_meaningless_mac(mac: &str) -> bool {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    hex.len() != 12 || hex.chars().all(|c| c == '0') || hex.eq_ignore_ascii_case("ffffffffffff")
}

/* ---------------------------------------------------------------- port tables */

/// Well-known services plus the IoT/media ports a home network actually runs.
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        81 => "http-alt",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        443 => "https",
        445 => "smb",
        515 => "printer",
        548 => "afp",
        554 => "rtsp",
        587 => "smtp-sub",
        631 => "ipp",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1400 => "sonos",
        1433 => "mssql",
        1883 => "mqtt",
        1900 => "ssdp",
        2049 => "nfs",
        2375 => "docker",
        2376 => "docker-tls",
        3000 => "http-dev",
        3306 => "mysql",
        3389 => "rdp",
        5000 => "upnp/airplay",
        5001 => "http-alt",
        5432 => "postgres",
        5555 => "adb",
        5900 => "vnc",
        6053 => "esphome",
        6379 => "redis",
        7000 => "airplay",
        8000 => "http-alt",
        8008 => "chromecast",
        8009 => "chromecast-tls",
        8060 => "roku",
        8080 => "http-proxy",
        8081 => "http-alt",
        8096 => "jellyfin",
        8123 => "home-assistant",
        8443 => "https-alt",
        8883 => "mqtt-tls",
        8888 => "http-alt",
        9000 => "http-alt",
        9090 => "http-alt",
        9100 => "printer-raw",
        9200 => "elasticsearch",
        10000 => "webmin",
        11434 => "ollama",
        27017 => "mongodb",
        32400 => "plex",
        _ => return None,
    })
}

pub const QUICK_PORTS: &[u16] = &[
    21, 22, 23, 53, 80, 139, 443, 445, 554, 631, 3389, 5000, 8080, 8443, 9100,
];

pub const STANDARD_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 110, 139, 143, 443, 445, 515, 548, 554, 587, 631, 993, 1400, 1883,
    1900, 2049, 3000, 3306, 3389, 5000, 5432, 5900, 6053, 7000, 8008, 8009, 8060, 8080, 8096, 8123,
    8443, 8883, 9100, 32400,
];

pub const DEEP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 161, 179, 199, 389,
    427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 902, 990, 993,
    995, 1024, 1025, 1026, 1080, 1110, 1194, 1234, 1400, 1433, 1521, 1723, 1755, 1883, 1900, 2000,
    2049, 2121, 2181, 2222, 2375, 2376, 3000, 3001, 3128, 3260, 3268, 3306, 3389, 3478, 3689, 4000,
    4200, 4444, 4567, 5000, 5001, 5060, 5061, 5100, 5222, 5269, 5353, 5357, 5432, 5555, 5601, 5666,
    5672, 5678, 5800, 5900, 5901, 6000, 6001, 6053, 6379, 6666, 6667, 7000, 7001, 7070, 7100, 7777,
    8000, 8001, 8002, 8008, 8009, 8010, 8060, 8080, 8081, 8085, 8088, 8090, 8096, 8123, 8181, 8200,
    8291, 8443, 8500, 8600, 8765, 8880, 8883, 8888, 9000, 9001, 9080, 9090, 9091, 9100, 9200, 9443,
    9999, 10000, 10001, 11434, 20000, 25565, 27017, 32400, 32469, 44158, 47808, 49152, 49153,
    49154, 51413, 62078,
];

pub fn ports_for_profile(profile: PortProfile) -> &'static [u16] {
    match profile {
        PortProfile::Quick => QUICK_PORTS,
        PortProfile::Standard => STANDARD_PORTS,
        PortProfile::Deep => DEEP_PORTS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_slash_24_and_skips_network_and_broadcast() {
        let cidr = parse_cidr("10.0.3.221/24").unwrap();
        assert_eq!(cidr.canonical(), "10.0.3.0/24");
        assert_eq!(cidr.host_count(), 254);
        assert_eq!(Ipv4Addr::from(cidr.first), Ipv4Addr::new(10, 0, 3, 1));
        assert_eq!(Ipv4Addr::from(cidr.last), Ipv4Addr::new(10, 0, 3, 254));
    }

    #[test]
    fn refuses_ranges_wider_than_the_cap() {
        // A docker bridge /16 would be 65k hosts.
        let err = parse_cidr("172.17.0.1/16").unwrap_err();
        assert!(err.contains("too large"), "unexpected error: {err}");
    }

    #[test]
    fn slash_31_and_32_have_no_reserved_addresses() {
        assert_eq!(parse_cidr("10.0.0.5/32").unwrap().host_count(), 1);
        assert_eq!(parse_cidr("10.0.0.4/31").unwrap().host_count(), 2);
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(parse_cidr("not-a-cidr").is_err());
        assert!(parse_cidr("10.0.0.1").is_err());
        assert!(parse_cidr("10.0.0.1/33").is_err());
        assert!(parse_cidr("999.0.0.1/24").is_err());
    }

    #[test]
    fn detects_randomized_macs() {
        // docker0's MAC from the reference machine has the locally-administered bit.
        assert!(is_locally_administered("f6:10:04:1c:20:08"));
        // A real Ubiquiti OUI does not.
        assert!(!is_locally_administered("e0:63:da:82:1b:35"));
    }

    #[test]
    fn recognises_private_space_including_cgnat() {
        assert!(is_private_ipv4("10.0.3.1".parse().unwrap()));
        assert!(is_private_ipv4("192.168.1.1".parse().unwrap()));
        assert!(is_private_ipv4("172.17.0.1".parse().unwrap()));
        assert!(is_private_ipv4("100.64.0.1".parse().unwrap()));
        assert!(!is_private_ipv4("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn derives_the_enclosing_slash_24() {
        assert_eq!(to_slash24("10.0.107.110".parse().unwrap()), "10.0.107.0/24");
    }

    #[test]
    fn filters_meaningless_macs() {
        assert!(is_meaningless_mac("00:00:00:00:00:00"));
        assert!(is_meaningless_mac("ff:ff:ff:ff:ff:ff"));
        assert!(!is_meaningless_mac("e0:63:da:82:1b:35"));
    }
}
