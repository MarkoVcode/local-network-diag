/** Human-readable names for DNS-SD service types, mirroring the Rust table. */

const LABELS: Record<string, string> = {
  _esphomelib: "ESPHome device",
  "_home-assistant": "Home Assistant",
  _esphomebuilder: "ESPHome Builder",
  _googlecast: "Google Cast",
  _airplay: "AirPlay",
  _raop: "AirPlay audio",
  "_spotify-connect": "Spotify Connect",
  _printer: "Printer",
  _ipp: "Printer (IPP)",
  _ipps: "Printer (IPP/TLS)",
  "_pdl-datastream": "Printer (raw)",
  _scanner: "Scanner",
  _smb: "SMB file share",
  _afpovertcp: "AFP file share",
  _nfs: "NFS share",
  _adisk: "Time Machine target",
  _ssh: "SSH",
  "_sftp-ssh": "SFTP",
  _http: "Web server",
  _https: "Web server (TLS)",
  _workstation: "Workstation",
  "_companion-link": "Apple Companion",
  _remotepairing: "Apple remote pairing",
  _rdlink: "Apple Remote Desktop",
  "_sleep-proxy": "Sleep proxy",
  _hap: "HomeKit accessory",
  _matter: "Matter device",
  _matterc: "Matter commissioning",
  _plexmediasvr: "Plex Media Server",
  _sonos: "Sonos",
  _mqtt: "MQTT broker",
  "_device-info": "Device info",
};

export function labelForServiceType(serviceType: string): string {
  const base = serviceType
    .replace(/\.local\.?$/, "")
    .replace(/\._(tcp|udp)$/, "");
  return LABELS[base] ?? base.replace(/^_/, "");
}

/** Sorts IPv4 strings numerically rather than lexically. */
export function compareIp(a: string, b: string): number {
  const toInt = (ip: string) =>
    ip.split(".").reduce((acc, octet) => acc * 256 + Number(octet), 0);
  const left = toInt(a);
  const right = toInt(b);
  return Number.isFinite(left) && Number.isFinite(right) ? left - right : a.localeCompare(b);
}
