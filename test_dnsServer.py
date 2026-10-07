import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dnslib import A, DNSRecord, QTYPE, RCODE, RR

from dnsServer import FilteringResolver, SQLiteBlocklist, normalize_domain


class DNSBlockerTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "blocklist.db"
        self.blocklist = SQLiteBlocklist(str(self.database_path))
        connection = sqlite3.connect(self.database_path)
        try:
            connection.executemany(
                "INSERT INTO blocked_domains(domain) VALUES (?)",
                [("ads.example",), ("malware.test",)],
            )
            connection.commit()
        finally:
            connection.close()
        self.resolver = FilteringResolver(
            self.blocklist,
            "192.0.2.1",
            53,
            1.0,
        )

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_normalize_domain(self):
        self.assertEqual(normalize_domain(" Ads.Example. "), "ads.example")
        self.assertEqual(normalize_domain("."), ".")

    def test_blocked_domain_and_subdomain_return_nxdomain(self):
        request = DNSRecord.question("track.ads.example", "A")

        response = self.resolver.resolve(request, None)

        self.assertEqual(response.header.rcode, RCODE.NXDOMAIN)
        self.assertEqual(len(response.rr), 0)

    def test_allowed_domain_is_forwarded_and_answer_returned(self):
        request = DNSRecord.question("example.org", "A")
        upstream = request.reply()
        upstream.add_answer(
            RR("example.org", QTYPE.A, rdata=A("203.0.113.10"), ttl=60)
        )

        with patch.object(DNSRecord, "send", return_value=upstream.pack()) as send:
            response = self.resolver.resolve(request, None)

        self.assertEqual(response.header.rcode, RCODE.NOERROR)
        self.assertEqual(str(response.rr[0].rdata), "203.0.113.10")
        send.assert_called_once_with(
            "192.0.2.1",
            53,
            tcp=False,
            timeout=1.0,
        )

    def test_upstream_failure_returns_servfail(self):
        request = DNSRecord.question("example.org", "A")

        with self.assertLogs("dns-blocker", level="ERROR"):
            with patch.object(DNSRecord, "send", side_effect=OSError("offline")):
                response = self.resolver.resolve(request, None)

        self.assertEqual(response.header.rcode, RCODE.SERVFAIL)

    def test_invalid_upstream_response_returns_servfail(self):
        request = DNSRecord.question("example.org", "A")

        with self.assertLogs("dns-blocker", level="ERROR"):
            with patch.object(DNSRecord, "send", return_value=b"invalid"):
                response = self.resolver.resolve(request, None)

        self.assertEqual(response.header.rcode, RCODE.SERVFAIL)

    def test_truncated_udp_response_is_retried_over_tcp(self):
        request = DNSRecord.question("example.org", "A")
        truncated = request.reply()
        truncated.header.tc = 1
        complete = request.reply()
        complete.add_answer(
            RR("example.org", QTYPE.A, rdata=A("203.0.113.10"), ttl=60)
        )
        handler = type("Handler", (), {"protocol": "udp"})()

        with patch.object(
            DNSRecord,
            "send",
            side_effect=[truncated.pack(), complete.pack()],
        ) as send:
            response = self.resolver.resolve(request, handler)

        self.assertEqual(str(response.rr[0].rdata), "203.0.113.10")
        self.assertEqual(send.call_count, 2)
        self.assertFalse(send.call_args_list[0].kwargs["tcp"])
        self.assertTrue(send.call_args_list[1].kwargs["tcp"])


if __name__ == "__main__":
    unittest.main()
