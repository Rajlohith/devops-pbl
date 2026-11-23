"""Rules of the application-protocol detector (pure Python; runs without Scapy)."""

import struct
import unittest

from app.services.protocol_detector import detect_tcp, detect_udp, parse_tls


def client_hello(sni=b"example.org"):
    name = struct.pack(">BH", 0, len(sni)) + sni
    sni_list = struct.pack(">H", len(name)) + name
    extensions = struct.pack(">HH", 0, len(sni_list)) + sni_list
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack(">H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def name(result):
    return result[0] if result else None


class TcpTests(unittest.TestCase):
    def test_tls_client_hello_with_sni(self):
        r = detect_tcp(50000, 443, client_hello())
        self.assertEqual(name(r), "TLS")
        self.assertEqual(r[1]["handshake"], "ClientHello")
        self.assertEqual(r[1]["sni"], "example.org")
        self.assertEqual(r[1]["detected_by"], "signature")

    def test_tls_on_any_port_and_application_data(self):
        self.assertEqual(name(detect_tcp(1234, 8443, b"\x17\x03\x03\x00\x20" + b"\x00" * 32)), "TLS")
        self.assertEqual(name(detect_tcp(1234, 993, b"\x16\x03\x03\x00\x30\x02" + b"\x00" * 40)), "TLS")

    def test_tls_lookalike_junk_is_rejected(self):
        # the pre-existing extractor test relies on this staying unidentified
        self.assertIsNone(parse_tls(b"\x16\x03\x01 binary"))
        self.assertIsNone(detect_tcp(40000, 80, b"\x16\x03\x01 binary"))
        self.assertIsNone(parse_tls(b"\x16\x03\x09\x00\x10\x01"))      # impossible version
        self.assertIsNone(parse_tls(b"\x17\x03\x03\x00\x00\x01"))      # zero-length record
        self.assertIsNone(parse_tls(b"\x16\x03"))                      # too short

    def test_truncated_client_hello_does_not_crash(self):
        hello = client_hello()
        for cut in range(6, len(hello)):
            parse_tls(hello[:cut])  # must never raise
        self.assertNotIn("sni", parse_tls(hello[:60]))

    def test_binary_signatures(self):
        self.assertEqual(name(detect_tcp(1, 22, b"SSH-2.0-OpenSSH_9.6\r\n")), "SSH")
        self.assertEqual(detect_tcp(1, 22, b"SSH-2.0-OpenSSH_9.6\r\n")[1]["banner"], "SSH-2.0-OpenSSH_9.6")
        self.assertEqual(name(detect_tcp(1, 9999, b"SSH-2.0-x")), "SSH")
        self.assertEqual(name(detect_tcp(1, 7, b"\xff" * 16 + b"\x00\x13\x04")), "BGP")
        self.assertEqual(name(detect_tcp(1, 445, b"\x00\x00\x00\x40\xfeSMB" + b"\x00" * 60)), "SMB")
        self.assertEqual(name(detect_tcp(1, 7, b"\xffSMB" + b"\x00" * 20)), "SMB")
        self.assertEqual(name(detect_tcp(1, 3389, b"\x03\x00\x00\x13\x0e\xe0")), "RDP")
        self.assertEqual(name(detect_tcp(1, 6379, b"*2\r\n$3\r\nGET\r\n")), "Redis")
        self.assertEqual(name(detect_tcp(1, 7, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")), "HTTP/2")

    def test_text_protocols_need_port_and_pattern(self):
        self.assertEqual(name(detect_tcp(1, 21, b"220 FTP ready\r\n")), "FTP")
        self.assertEqual(detect_tcp(1, 21, b"220 FTP ready\r\n")[1]["detected_by"], "port")
        self.assertEqual(name(detect_tcp(1, 25, b"EHLO mail.example\r\n")), "SMTP")
        self.assertEqual(name(detect_tcp(587, 1, b"250-STARTTLS\r\n")), "SMTP")
        self.assertEqual(name(detect_tcp(110, 1, b"+OK POP3 ready\r\n")), "POP3")
        self.assertEqual(name(detect_tcp(143, 1, b"* OK IMAP4rev1\r\n")), "IMAP")
        self.assertEqual(name(detect_tcp(1, 143, b"a001 LOGIN user pass\r\n")), "IMAP")
        self.assertEqual(name(detect_tcp(1, 554, b"DESCRIBE rtsp://cam/stream RTSP/1.0\r\n")), "RTSP")
        # a binary continuation segment on port 21 is not guessed
        self.assertIsNone(detect_tcp(1, 21, b"\x01\x02\x03\x04"))

    def test_port_only_services(self):
        for port, expected in ((23, "Telnet"), (3306, "MySQL"), (5432, "PostgreSQL"),
                               (27017, "MongoDB"), (1883, "MQTT"), (389, "LDAP"), (502, "Modbus")):
            self.assertEqual(name(detect_tcp(50000, port, b"\x01\x02\x03")), expected, port)
        self.assertEqual(name(detect_tcp(3306, 50000, b"\x01\x02")), "MySQL")  # server side

    def test_no_payload_and_unrelated_traffic_stay_unidentified(self):
        self.assertIsNone(detect_tcp(40000, 22, b""))          # bare ACK/SYN on the SSH port
        self.assertIsNone(detect_tcp(40000, 80, b"xxxxxxxx"))  # HTTP is the extractor's job
        self.assertIsNone(detect_tcp(40000, 443, b"hi"))       # 443 is never guessed from the port
        self.assertIsNone(detect_tcp(40000, 53, b"\x00\x63not a dns message"))  # DNS is the extractor's job
        self.assertIsNone(detect_tcp(40000, 40001, b"random"))


class UdpTests(unittest.TestCase):
    def test_quic(self):
        long_header = b"\xc3" + (1).to_bytes(4, "big") + b"\x08" + b"\x00" * 30
        self.assertEqual(detect_udp(50000, 443, long_header), ("QUIC", {"detected_by": "signature", "version": "0x00000001"}))
        self.assertEqual(name(detect_udp(50000, 4433, long_header)), "QUIC")
        self.assertEqual(detect_udp(50000, 443, b"\x41" + b"\x00" * 20)[1]["detected_by"], "port")  # short header

    def test_dhcp_requires_the_magic_cookie(self):
        packet = b"\x01" + b"\x00" * 235 + b"\x63\x82\x53\x63" + b"\x35\x01\x01\xff"
        self.assertEqual(name(detect_udp(68, 67, packet)), "DHCP")
        self.assertIsNone(detect_udp(68, 67, b"\x01" + b"\x00" * 239))

    def test_ntp_snmp_syslog_tftp(self):
        self.assertEqual(name(detect_udp(40000, 123, b"\x1b" + b"\x00" * 47)), "NTP")
        self.assertIsNone(detect_udp(40000, 123, b"\x1b" + b"\x00" * 10))
        self.assertEqual(name(detect_udp(40000, 161, b"\x30\x26\x02\x01\x01")), "SNMP")
        self.assertEqual(name(detect_udp(40000, 514, b"<34>Oct 11 su: x")), "Syslog")
        self.assertEqual(name(detect_udp(40000, 69, b"\x00\x01file\x00octet\x00")), "TFTP")

    def test_discovery_and_vpn_protocols(self):
        self.assertEqual(name(detect_udp(40000, 1900, b"M-SEARCH * HTTP/1.1\r\n")), "SSDP")
        self.assertEqual(name(detect_udp(40000, 5355, b"\x00\x01\x00\x00")), "LLMNR")
        self.assertEqual(name(detect_udp(40000, 137, b"\x00\x01\x01\x10")), "NBNS")
        self.assertEqual(name(detect_udp(40000, 5060, b"INVITE sip:a@b SIP/2.0\r\n")), "SIP")
        self.assertEqual(name(detect_udp(40000, 500, b"\x00" * 28)), "ISAKMP")
        stun = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"\x00" * 12
        self.assertEqual(name(detect_udp(40000, 3478, stun)), "STUN")
        wg = b"\x01\x00\x00\x00" + b"\x00" * 144
        self.assertEqual(name(detect_udp(40000, 51820, wg)), "WireGuard")

    def test_dns_port_and_empty_payloads_are_left_alone(self):
        self.assertIsNone(detect_udp(40000, 53, b"\x12\x34 not dns"))
        self.assertIsNone(detect_udp(40000, 161, b""))
        self.assertIsNone(detect_udp(40000, 22, b"hello"))   # UDP to a TCP-only port
        self.assertIsNone(detect_udp(40000, 40001, b"abc"))


class NameWidthTests(unittest.TestCase):
    def test_every_label_fits_the_database_column(self):
        from app.services import protocol_detector as pd

        names = set(pd._TCP_PORTS.values()) | set(pd._UDP_PORTS.values()) | set(pd.L2_ETHERTYPES.values())
        names |= {n for _, _, n in pd._TCP_TEXT_RULES}
        names |= {"TLS", "SSH", "HTTP/2", "BGP", "SMB", "QUIC", "DHCP", "DHCPv6", "NTP", "STUN",
                  "WireGuard", "ESP-in-UDP", "WS-Discovery", "PostgreSQL"}
        self.assertTrue(all(len(n) <= 16 for n in names), [n for n in names if len(n) > 16])


if __name__ == "__main__":
    unittest.main()
