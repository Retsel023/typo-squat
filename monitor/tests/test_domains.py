import unittest

from typo_monitor.domains import normalize_domain, normalize_records, parse_domains


class DomainTests(unittest.TestCase):
    def test_text_lists_normalize_idna_case_comments_and_duplicates(self):
        self.assertEqual(
            parse_domains("# list\n EXAMPLE.com. # root\n\nBÜCHER.de\nexample.com\n"),
            ["example.com", "xn--bcher-kva.de"],
        )

    def test_unsafe_or_non_domain_input_is_rejected(self):
        for value in ("https://example.com", "example.com:443", "example.com;id",
                      "*.example.com", "localhost", "127.0.0.1", "::1", "example..com",
                      "example.com..", "exam ple.com", " example.com", "-bad.example",
                      "bad-.example", "example.123", "a" * 64 + ".com", "example.com/", "a@b.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)

    def test_bad_input_identifies_line(self):
        with self.assertRaisesRegex(ValueError, "Line 3"):
            parse_domains("# comment\nexample.com\nhttps://example.com")

    def test_rrsets_ignore_order_ttl_duplicates_and_dns_case(self):
        first = [["MX", "10 Mail.EXAMPLE.com."], ["A", "192.0.2.1"],
                 ["AAAA", "2001:0db8:0:0:0:0:0:1"], ["CNAME", "BÜCHER.de."]]
        second = [{"type": "cname", "value": "xn--bcher-kva.de", "ttl": 100},
                  {"type": "AAAA", "value": "2001:db8::1", "ttl": 1},
                  ["A", "192.0.2.1", 100], ["MX", "10 mail.example.com"], ["A", "192.0.2.1"]]
        self.assertEqual(normalize_records(first), normalize_records(second))

    def test_txt_values_are_case_sensitive(self):
        self.assertNotEqual(normalize_records([["TXT", "ABC"]]), normalize_records([["TXT", "abc"]]))

    def test_invalid_ip_or_wrong_address_family_rejected(self):
        for record in (["A", "not-an-ip"], ["AAAA", "192.0.2.1"], ["A", "2001:db8::1"]):
            with self.subTest(record=record), self.assertRaises(ValueError):
                normalize_records([record])


if __name__ == "__main__":
    unittest.main()
