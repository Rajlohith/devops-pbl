"""Application-protocol identification from payload signatures and well-known ports.

Pure functions over bytes (no Scapy), so every rule is unit-testable. ``detect_tcp`` and
``detect_udp`` return ``(name, metadata)`` or ``None``. Names are at most 16 characters (the
database column width). ``metadata["detected_by"]`` says how the decision was made:

``signature``  the payload itself has the protocol's structure (TLS record, SSH banner,
               QUIC long header, DHCP magic cookie, ...). Strong evidence.
``port``       only the well-known port matched (and the packet carried a payload). Weaker:
               the port is a convention, not proof.

Only packets that carry payload are classified, so bare handshake/ACK packets stay "TCP".
Encrypted streams are identified by their TLS record header: continuation segments of a TLS
stream (no record header) are not guessed from the port, because a port such as 443 or 993
says nothing about whether a given segment is plain text. DNS and HTTP are identified by the
extractor before these rules run; TCP/UDP port 53 is intentionally not mapped here.
"""

from __future__ import annotations

import re

# ----------------------------------------------------------------------------- TLS

_TLS_RECORDS = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}
_TLS_HANDSHAKES = {
    0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
    5: "EndOfEarlyData", 8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange",
    13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
    16: "ClientKeyExchange", 20: "Finished", 24: "KeyUpdate",
}
_TLS_VERSIONS = {0: "SSL 3.0", 1: "TLS 1.0", 2: "TLS 1.1", 3: "TLS 1.2", 4: "TLS 1.3"}
_MAX_TLS_RECORD = 16384 + 2048


def _server_name(data: bytes) -> str | None:
    """SNI from a ClientHello record (bounds-checked; None if absent or malformed)."""
    try:
        pos = 5 + 4 + 2 + 32  # record header, handshake header, version, random
        pos += 1 + data[pos]  # session id
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")  # cipher suites
        pos += 1 + data[pos]  # compression methods
        end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = min(end, len(data))
        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0 and ext_len >= 5 and data[pos + 2] == 0:  # host_name
                name_len = int.from_bytes(data[pos + 3:pos + 5], "big")
                raw = data[pos + 5:pos + 5 + name_len]
                if len(raw) == name_len and name_len:
                    text = raw.decode("ascii")
                    return text if text.isprintable() else None
                return None
            pos += ext_len
    except (IndexError, UnicodeDecodeError):
        return None
    return None


def parse_tls(data: bytes) -> dict | None:
    """Metadata if ``data`` begins with a structurally valid TLS/SSL record, else None."""
    if len(data) < 6 or data[0] not in _TLS_RECORDS or data[1] != 3 or data[2] > 4:
        return None
    length = int.from_bytes(data[3:5], "big")
    if length == 0 or length > _MAX_TLS_RECORD:
        return None
    kind = data[0]
    meta = {"record": _TLS_RECORDS[kind], "record_version": _TLS_VERSIONS[data[2]]}
    if kind == 22:
        if data[5] not in _TLS_HANDSHAKES:
            return None
        meta["handshake"] = _TLS_HANDSHAKES[data[5]]
        if data[5] == 1:
            sni = _server_name(data)
            if sni:
                meta["sni"] = sni[:253]
    elif kind == 20:
        if length != 1 or data[5] != 1:
            return None
    elif kind == 21:
        if not ((length == 2 and data[5] in (1, 2)) or length >= 16):
            return None
    return meta


# ---------------------------------------------------------------------------- text rules

_FTP = re.compile(rb"^(?:\d{3}[ -]|(?:USER|PASS|QUIT|SYST|PWD|CWD|TYPE|PASV|PORT|LIST|RETR|STOR|FEAT|AUTH)\b)", re.I)
_SMTP = re.compile(rb"^(?:\d{3}[ -]|(?:EHLO|HELO|MAIL FROM|RCPT TO|DATA|QUIT|STARTTLS|AUTH|RSET|VRFY)\b)", re.I)
_POP3 = re.compile(rb"^(?:\+OK|-ERR|(?:USER|PASS|STAT|LIST|RETR|DELE|QUIT|CAPA|UIDL|TOP|APOP|STLS)\b)", re.I)
_IMAP = re.compile(
    rb"^(?:\* (?:OK|BYE|PREAUTH|CAPABILITY|LIST|FLAGS|\d+ )|[A-Za-z0-9.]{1,10} "
    rb"(?:LOGIN|CAPABILITY|SELECT|EXAMINE|FETCH|LIST|LSUB|NOOP|LOGOUT|STARTTLS|AUTHENTICATE|UID|STATUS|IDLE)\b)",
    re.I,
)
_IRC = re.compile(rb"^(?::[^ ]+ )?(?:NICK|USER|PRIVMSG|JOIN|PING|PONG|NOTICE|CAP|PASS)\b|^:[^ ]+ \d{3} ")
_RTSP = re.compile(rb"^(?:RTSP/1\.0|(?:OPTIONS|DESCRIBE|SETUP|PLAY|TEARDOWN|PAUSE|ANNOUNCE) rtsp://)")
_SIP = re.compile(rb"^(?:SIP/2\.0|(?:INVITE|REGISTER|OPTIONS|ACK|BYE|CANCEL|SUBSCRIBE|NOTIFY|MESSAGE) (?:sip|tel)s?:)")
_SSDP = re.compile(rb"^(?:M-SEARCH \*|NOTIFY \*|HTTP/1\.1 200)")


def _sig(name: str, **extra) -> tuple[str, dict]:
    return name, {"detected_by": "signature", **extra}


def _port(name: str) -> tuple[str, dict]:
    return name, {"detected_by": "port"}


# Plain-text services: a payload on the well-known port that also looks like the protocol.
_TCP_TEXT_RULES = (
    (frozenset({21}), _FTP, "FTP"),
    (frozenset({25, 587, 2525}), _SMTP, "SMTP"),
    (frozenset({110}), _POP3, "POP3"),
    (frozenset({143}), _IMAP, "IMAP"),
    (frozenset({6667, 6697}), _IRC, "IRC"),
    (frozenset({554}), _RTSP, "RTSP"),
    (frozenset({5060}), _SIP, "SIP"),
)

# Services identified by port alone when a payload is present (binary or free-form protocols).
_TCP_PORTS = {
    23: "Telnet", 88: "Kerberos", 139: "NetBIOS", 179: "BGP", 389: "LDAP", 445: "SMB",
    502: "Modbus", 514: "Syslog", 873: "Rsync", 1433: "MSSQL", 1883: "MQTT", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    9418: "Git", 11211: "Memcached", 27017: "MongoDB", 20000: "DNP3",
}


def detect_tcp(sport: int, dport: int, data: bytes) -> tuple[str, dict] | None:
    if not data:
        return None
    tls = parse_tls(data)
    if tls is not None:
        return _sig("TLS", **tls)
    if data.startswith(b"SSH-"):
        return _sig("SSH", banner=data.split(b"\r\n", 1)[0][:80].decode("latin-1"))
    if data.startswith(b"PRI * HTTP/2.0"):
        return _sig("HTTP/2")
    if data.startswith(b"RFB 00"):
        return _sig("VNC")
    if data[:16] == b"\xff" * 16:
        return _sig("BGP")
    netbios = data[4:] if len(data) > 8 and data[0] == 0 else data
    if netbios[:4] in (b"\xffSMB", b"\xfeSMB", b"\xfdSMB"):
        return _sig("SMB", dialect="SMB1" if netbios[0] == 0xFF else "SMB2/3")
    if data.startswith(b"@RSYNCD:"):
        return _sig("Rsync")
    ports = {sport, dport}
    for rule_ports, pattern, name in _TCP_TEXT_RULES:
        if ports & rule_ports and pattern.match(data):
            return _sig(name) if name in ("SIP", "RTSP") else _port(name)
    if 3389 in ports and data[:2] == b"\x03\x00":
        return _sig("RDP")
    if 6379 in ports and data[:1] in (b"*", b"+", b"-", b":", b"$"):
        return _sig("Redis")
    for port in (dport, sport):
        name = _TCP_PORTS.get(port)
        if name:
            return _port(name)
    return None


# ----------------------------------------------------------------------------- UDP

_QUIC_VERSIONS = {0x00000001, 0x6B3343CF, 0x00000000}
_DHCP_COOKIE = b"\x63\x82\x53\x63"
_UDP_PORTS = {
    69: "TFTP", 88: "Kerberos", 137: "NBNS", 138: "NBDS", 161: "SNMP", 162: "SNMP",
    389: "CLDAP", 500: "ISAKMP", 514: "Syslog", 520: "RIP", 521: "RIPng", 1194: "OpenVPN",
    1701: "L2TP", 1812: "RADIUS", 1813: "RADIUS", 2055: "NetFlow", 2123: "GTP", 2152: "GTP",
    3702: "WS-Discovery", 4789: "VXLAN", 5353: "mDNS", 5355: "LLMNR", 6343: "sFlow",
    47808: "BACnet",
}


def detect_udp(sport: int, dport: int, data: bytes) -> tuple[str, dict] | None:
    if not data:
        return None
    ports = {sport, dport}
    n = len(data)

    if n >= 20 and data[4:8] == b"\x21\x12\xa4\x42":
        return _sig("STUN")
    if n >= 240 and ports & {67, 68} and data[236:240] == _DHCP_COOKIE:
        return _sig("DHCP", op="request" if data[0] == 1 else "reply")
    if ports & {546, 547} and 1 <= data[0] <= 13:
        return _port("DHCPv6")
    if 123 in ports and n >= 48 and 1 <= (data[0] & 7) <= 7:
        return _sig("NTP", mode=data[0] & 7, version=(data[0] >> 3) & 7)
    if ports & {161, 162} and data[0] == 0x30:
        return _sig("SNMP")
    if 69 in ports and data[0] == 0 and 1 <= data[1] <= 6 and dport == 69:
        return _sig("TFTP")
    if 1900 in ports and _SSDP.match(data):
        return _sig("SSDP")
    if 514 in ports and data[:1] == b"<":
        return _sig("Syslog")
    if 520 in ports and n >= 4 and data[0] in (1, 2) and data[1] in (1, 2):
        return _sig("RIP")
    if 5060 in ports and _SIP.match(data):
        return _sig("SIP")
    if ports & {1812, 1813, 1645, 1646} and 1 <= data[0] <= 13:
        return _sig("RADIUS")
    if 4789 in ports and data[0] == 0x08:
        return _sig("VXLAN")
    if 51820 in ports and n >= 32 and data[0] in (1, 2, 3, 4) and data[1:4] == b"\x00\x00\x00":
        return _sig("WireGuard")
    if 4500 in ports:
        return _sig("ISAKMP") if data[:4] == b"\x00\x00\x00\x00" else _sig("ESP-in-UDP")

    # QUIC: long header (form + fixed bits) with a known version, or any short packet on 443.
    if n >= 7 and data[0] & 0xC0 == 0xC0:
        version = int.from_bytes(data[1:5], "big")
        if version in _QUIC_VERSIONS or (version >> 8) == 0xFF0000 or version & 0x0A0A0A0A == 0x0A0A0A0A:
            return _sig("QUIC", version=f"0x{version:08x}")
    if 443 in ports:
        return _port("QUIC")

    for port in (dport, sport):
        name = _UDP_PORTS.get(port)
        if name:
            return _port(name)
    return None


# ------------------------------------------------------------------ non-IP (Ethernet)

L2_ETHERTYPES = {
    0x8035: "RARP", 0x8809: "LACP", 0x8847: "MPLS", 0x8848: "MPLS", 0x8863: "PPPoE",
    0x8864: "PPPoE", 0x888E: "EAPOL", 0x88CC: "LLDP", 0x88F7: "PTP", 0x8906: "FCoE",
}
