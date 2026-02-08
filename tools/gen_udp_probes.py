#!/usr/bin/env python3
"""
gen_udp_probes.py — Generate rs_scan UDP probe YAML files from nmap-service-probes.

Parses the nmap probe database, extracts UDP probes with their payloads and port
mappings, and writes one YAML file per probe in rs_scan's format.

Port conflict resolution: when multiple probes claim the same port, the probe with
the lowest rarity (most common) wins. This ensures each port sends the most likely
protocol-correct probe.

Usage:
    python3 tools/gen_udp_probes.py [nmap-service-probes path] [output dir]

Defaults:
    nmap-service-probes: /usr/share/nmap/nmap-service-probes
    output dir:          probes/udp/
"""

import re
import sys
import os


def parse_nmap_payload(raw: str) -> bytes:
    """Convert nmap q|...| payload string to raw bytes.

    nmap uses: \\x hex, \\r, \\n, \\t, \\0, \\\\, and literal chars.
    The q|...| delimiters are already stripped before calling this.
    """
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == '\\' and i + 1 < len(raw):
            c = raw[i + 1]
            if c == 'x' and i + 3 < len(raw):
                try:
                    val = int(raw[i+2:i+4], 16)
                    out.append(val)
                    i += 4
                    continue
                except ValueError:
                    pass
            elif c == 'r':
                out.append(0x0d)
                i += 2
                continue
            elif c == 'n':
                out.append(0x0a)
                i += 2
                continue
            elif c == 't':
                out.append(0x09)
                i += 2
                continue
            elif c == '0':
                out.append(0x00)
                i += 2
                continue
            elif c == '\\':
                out.append(0x5c)
                i += 2
                continue
            elif c == '|':
                out.append(ord('|'))
                i += 2
                continue
            # Unknown escape — emit literal backslash + char
            out.append(ord(raw[i]))
            i += 1
        else:
            out.append(ord(raw[i]))
            i += 1
    return bytes(out)


def bytes_to_yaml_hello(data: bytes) -> str:
    """Convert raw bytes to our YAML hello string format.

    Uses \\xNN for non-printable bytes, literal chars for printable ASCII.
    Always uses \\r \\n \\t for those specific bytes.
    """
    out = []
    for b in data:
        if b == 0x0d:
            out.append('\\r')
        elif b == 0x0a:
            out.append('\\n')
        elif b == 0x09:
            out.append('\\t')
        elif b == 0x5c:
            out.append('\\\\')
        elif b == ord('"'):
            out.append('\\"')
        elif 0x20 <= b <= 0x7e:
            out.append(chr(b))
        else:
            out.append(f'\\x{b:02x}')
    return '"' + ''.join(out) + '"'


def parse_ports(port_str: str) -> list[int]:
    """Parse nmap port specification like '53,1967,2967,26198' or '27910-27914'."""
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            lo, hi = part.split('-', 1)
            try:
                lo, hi = int(lo), int(hi)
                # For ranges, only include if reasonable size (< 100 ports)
                if hi - lo < 100:
                    ports.extend(range(lo, hi + 1))
                else:
                    # Large range — just include endpoints and skip
                    ports.append(lo)
            except ValueError:
                continue
        else:
            try:
                ports.append(int(part))
            except ValueError:
                continue
    return ports


def sanitize_name(name: str) -> str:
    """Convert probe name to a safe filename."""
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name).lower()


def parse_nmap_probes(path: str) -> list[dict]:
    """Parse nmap-service-probes file, extracting all UDP probes."""
    probes = []
    current = None

    with open(path, 'r', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')

            # New probe definition
            m = re.match(r'^Probe\s+(TCP|UDP)\s+(\S+)\s+q\|(.*)(?:\|.*)$', line)
            if m:
                if current and current['proto'] == 'UDP':
                    probes.append(current)
                proto, name, payload_raw = m.group(1), m.group(2), m.group(3)
                # Strip trailing | and any flags after it
                if '|' in payload_raw:
                    payload_raw = payload_raw[:payload_raw.rindex('|')]
                current = {
                    'proto': proto,
                    'name': name,
                    'payload_raw': payload_raw,
                    'ports': '',
                    'rarity': 5,  # default
                    'match_count': 0,
                }
                continue

            if current is None:
                continue

            if line.startswith('ports '):
                current['ports'] = line[6:].strip()
            elif line.startswith('rarity '):
                try:
                    current['rarity'] = int(line[7:].strip())
                except ValueError:
                    pass
            elif line.startswith('match ') or line.startswith('softmatch '):
                current['match_count'] += 1

    # Don't forget last probe
    if current and current['proto'] == 'UDP':
        probes.append(current)

    return probes


# Well-known port → protocol overrides.
# nmap's general-purpose probes (RPCCheck rarity=1) claim many ports they don't
# actually represent. This table forces the protocol-correct probe for well-known
# ports regardless of rarity.
PORT_FORCE_PROBE = {
    53:   'DNSVersionBindReq',   # DNS, not RPC
    67:   'DHCP_INFORM',         # DHCP
    69:   'TFTP_GET',            # TFTP, not DNSStatusRequest
    88:   'Kerberos',            # Kerberos, not RPC
    123:  'NTPRequest',          # NTP
    137:  'NBTStat',             # NetBIOS
    161:  'SNMPv1public',        # SNMP
    389:  'LDAPSearchReqUDP',    # LDAP
    443:  'DTLSSessionReq',      # DTLS/QUIC, not OpenVPN
    500:  'IKE_MAIN_MODE',       # IKE/IPSec, not RPC
    623:  'ipmi-rmcp',           # IPMI
    1194: 'OpenVPN',             # OpenVPN
    1434: 'Sqlping',             # MSSQL Browser
    1701: 'L2TP_ICRQ',           # L2TP
    1812: 'RADIUS_ACCESS',       # RADIUS
    1900: 'UPNP_MSEARCH',        # UPnP/SSDP
    2049: 'NFSPROC_NULL',        # NFS, not RPC
    3478: 'STUN_BIND',           # STUN
    5060: 'SIPOptions',          # SIP
    5351: 'NAT_PMP_ADDR',        # NAT-PMP
    5353: 'DNSVersionBindReq',   # mDNS (use DNS probe)
    5683: 'coap-request',        # CoAP
    9987: 'TeamSpeak3',          # TeamSpeak3
    11211: 'memcached',          # Memcached
    27017: 'STEAM',              # Steam (not MongoDB TCP!)
}

# Curated recv_bytes based on protocol type
RECV_BYTES_OVERRIDES = {
    'DNSVersionBindReq': 512,
    'DNSStatusRequest': 512,
    'SNMPv1public': 1024,
    'SNMPv3GetRequest': 1024,
    'NTPRequest': 256,
    'NBTStat': 512,
    'SIPOptions': 2048,
    'Kerberos': 1024,
    'STUN_BIND': 256,
    'DTLSSessionReq': 2048,
    'UPNP_MSEARCH': 2048,
    'ipmi-rmcp': 256,
    'coap-request': 512,
    'DHCP_INFORM': 1024,
    'QUIC': 2048,
    'IKE_MAIN_MODE': 1024,
    'NFSPROC_NULL': 512,
    'RADIUS_ACCESS': 512,
    'TFTP_GET': 512,
    'L2TP_ICRQ': 512,
}


def generate_yaml(probe: dict) -> str:
    """Generate rs_scan YAML probe from parsed nmap probe."""
    payload = parse_nmap_payload(probe['payload_raw'])
    if not payload:
        return ''  # Skip empty-payload probes

    hello = bytes_to_yaml_hello(payload)
    ports = parse_ports(probe['ports'])
    if not ports:
        return ''  # Skip probes with no port assignments

    recv_bytes = RECV_BYTES_OVERRIDES.get(probe['name'], 512)

    lines = [
        f"# Generated from nmap-service-probes (rarity {probe['rarity']}, {probe['match_count']} match rules)",
        f"name: {probe['name'].lower()}",
        f"protocol: udp",
        f"ports: [{', '.join(str(p) for p in sorted(set(ports)))}]",
        f"hello: {hello}",
        f"recv_bytes: {recv_bytes}",
    ]

    return '\n'.join(lines) + '\n'


def main():
    nmap_path = sys.argv[1] if len(sys.argv) > 1 else '/usr/share/nmap/nmap-service-probes'
    out_dir = sys.argv[2] if len(sys.argv) > 2 else 'probes/udp'

    if not os.path.exists(nmap_path):
        print(f"Error: {nmap_path} not found", file=sys.stderr)
        sys.exit(1)

    os.makedirs(out_dir, exist_ok=True)

    probes = parse_nmap_probes(nmap_path)
    print(f"Parsed {len(probes)} UDP probes from {nmap_path}")

    # Index probes by name for forced overrides
    probes_by_name = {p['name']: p for p in probes}

    # Build port → probe mapping
    # Step 1: Apply forced overrides for well-known ports
    port_owner: dict[int, dict] = {}
    for port, probe_name in PORT_FORCE_PROBE.items():
        if probe_name in probes_by_name:
            port_owner[port] = probes_by_name[probe_name]

    # Step 2: Fill remaining ports by rarity (lowest wins), never override forced ports
    forced_ports = set(PORT_FORCE_PROBE.keys())
    for p in probes:
        ports = parse_ports(p['ports'])
        for port in ports:
            if port in forced_ports:
                continue  # never override manual assignments
            if port not in port_owner or p['rarity'] < port_owner[port]['rarity']:
                port_owner[port] = p

    # Track which probes actually own at least one port
    active_probes = set()
    for port, probe in port_owner.items():
        active_probes.add(probe['name'])

    # Generate YAML files
    written = 0
    skipped_empty = 0
    skipped_no_ports = 0

    for probe in probes:
        payload = parse_nmap_payload(probe['payload_raw'])
        if not payload:
            skipped_empty += 1
            continue

        ports = parse_ports(probe['ports'])
        if not ports:
            skipped_no_ports += 1
            continue

        # Only include ports this probe owns (won rarity conflict)
        owned_ports = [p for p in ports if port_owner.get(p, {}).get('name') == probe['name']]
        if not owned_ports:
            print(f"  SKIP {probe['name']:30s} — all ports claimed by lower-rarity probes")
            continue

        # Update the probe's ports to only owned ports for YAML generation
        probe_copy = dict(probe)
        probe_copy['ports'] = ','.join(str(p) for p in owned_ports)

        yaml_content = generate_yaml(probe_copy)
        if not yaml_content:
            continue

        fname = sanitize_name(probe['name']) + '.yaml'
        fpath = os.path.join(out_dir, fname)
        with open(fpath, 'w') as f:
            f.write(yaml_content)
        written += 1
        print(f"  WRITE {fname:40s} ports={probe_copy['ports'][:60]}")

    print(f"\nSummary: {written} probes written, {skipped_empty} empty payload, {skipped_no_ports} no ports")

    # Print port conflict resolution report
    conflicts = {}
    for probe in probes:
        ports = parse_ports(probe['ports'])
        for port in ports:
            if port not in conflicts:
                conflicts[port] = []
            conflicts[port].append((probe['name'], probe['rarity']))

    multi = {p: v for p, v in conflicts.items() if len(v) > 1}
    if multi:
        print(f"\nPort conflicts resolved ({len(multi)} ports with multiple probes):")
        for port in sorted(multi.keys())[:20]:
            entries = multi[port]
            winner = port_owner[port]['name']
            losers = [f"{n}(r{r})" for n, r in entries if n != winner]
            print(f"  :{port:5d} → {winner} (beat {', '.join(losers)})")
        if len(multi) > 20:
            print(f"  ... and {len(multi)-20} more")


if __name__ == '__main__':
    main()
