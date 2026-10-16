"""Parking heuristics are tested with DNS fixtures; no external queries run."""

from copy import deepcopy
import threading
import unittest
from unittest.mock import patch

import dns.resolver
import dns.rrset

from typo_monitor.parking import ParkingClassifier


POSITIVE = {"status": "resolved", "records": [["A", "192.0.2.10"]]}


class NSAnswer(list):
    def __init__(self, domain, *targets):
        self.rrset = dns.rrset.from_text(domain, 60, "IN", "NS", *targets)
        super().__init__(self.rrset)


class ParkingTests(unittest.TestCase):
    def enrich(self, observations, answer, *, classifier=None):
        calls = []

        class Resolver:
            def resolve(self, domain, kind, **kwargs):
                calls.append((domain, kind))
                if isinstance(answer, BaseException):
                    raise answer
                return answer

        with patch("typo_monitor.parking.dns.resolver.Resolver", Resolver):
            result = (classifier or ParkingClassifier()).enrich(observations)
        return result, calls

    def test_documented_parking_nameservers_match_case_and_trailing_dot(self):
        for provider, targets in (
            ("Afternic", ("NS1.AFTERNIC.COM.", "ns2.afternic.com.")),
            ("Sedo", ("ns1.sedoparking.com", "ns2.sedoparking.com")),
            ("GoDaddy CashParking", ("ns01.cashparking.com", "ns02.cashparking.com")),
            ("ParkingCrew", ("ns1.parkingcrew.net", "ns2.parkingcrew.net")),
        ):
            with self.subTest(provider=provider):
                result, calls = self.enrich({"example.com": deepcopy(POSITIVE)}, NSAnswer("example.com", *targets))
                parking = result["example.com"]["parking"]
                self.assertEqual(parking["status"], "likely_parked")
                self.assertEqual(parking["provider"], provider)
                self.assertEqual(len(parking["evidence"]), 2)
                self.assertEqual(calls, [("example.com", "NS")])

    def test_generic_godaddy_dns_cdn_and_ip_are_not_parking_indicators(self):
        observation = {"status": "resolved", "records": [
            ["A", "192.0.2.10"], ["CNAME", "customer.cloudflare.net"],
        ]}
        for targets in (("ns01.domaincontrol.com", "ns02.domaincontrol.com"),
                        ("ns1.cashparking.com", "ns2.cashparking.com"),
                        ("ns1.cloudfront.net", "ns2.cloudfront.net")):
            with self.subTest(targets=targets):
                result, _ = self.enrich({"example.com": observation}, NSAnswer("example.com", *targets))
                self.assertEqual(result["example.com"]["parking"]["status"], "not_detected")
                self.assertIsNone(result["example.com"]["parking"]["provider"])

    def test_spoofed_nameserver_suffixes_do_not_match(self):
        for target in ("ns1.afternic.com.attacker.example", "ns1.sedoparking.com.evil.example",
                       "ns01.cashparking.com.evil.example", "evil-ns1.afternic.com"):
            with self.subTest(target=target):
                result, _ = self.enrich({"example.com": POSITIVE}, NSAnswer("example.com", target))
                self.assertEqual(result["example.com"]["parking"]["status"], "not_detected")

    def test_direct_documented_parking_cname_needs_no_additional_query(self):
        observations = {"www.example.com": {"status": "resolved", "records": [
            ["A", "192.0.2.10"], ["CNAME", "Account-123.ParkingCrew.NET."],
        ]}}
        with patch("typo_monitor.parking.dns.resolver.Resolver") as resolver:
            result = ParkingClassifier().enrich(observations)
            resolver.assert_not_called()
        self.assertEqual(result["www.example.com"]["parking"], {
            "status": "likely_parked", "provider": "ParkingCrew",
            "evidence": ["CNAME www.example.com -> account-123.parkingcrew.net"],
        })

    def test_cname_suffix_boundaries_and_foreign_owners_do_not_match(self):
        for record in (
            ["CNAME", "account.parkingcrew.net.attacker.example"],
            ["CNAME", "account.notparkingcrew.net"],
            ["CNAME", "nested.account.parkingcrew.net"],
            ["CNAME", "parkingcrew.net"],
            ["CNAME", "ns1.parkingcrew.net"],
            {"type": "CNAME", "value": "account.parkingcrew.net", "owner": "other.example.com"},
        ):
            with self.subTest(record=record):
                result, _ = self.enrich({"www.example.com": {"status": "resolved", "records": [record]}},
                                        dns.resolver.NoAnswer())
                self.assertEqual(result["www.example.com"]["parking"]["status"], "not_detected")

    def test_mixed_parking_and_live_cname_evidence_is_not_hidden(self):
        observations = {"www.example.com": {"status": "resolved", "records": [
            ["CNAME", "account.parkingcrew.net"], ["CNAME", "live.example.net"],
        ]}}
        with patch("typo_monitor.parking.dns.resolver.Resolver") as resolver:
            result = ParkingClassifier().enrich(observations)
            resolver.assert_not_called()
        parking = result["www.example.com"]["parking"]
        self.assertEqual(parking["status"], "unknown")
        self.assertIsNone(parking["provider"])
        self.assertIn("Mixed CNAME", parking["evidence"][-1])

    def test_parent_zone_and_alias_target_nameservers_are_not_child_evidence(self):
        for owner in ("example.com", "alias.example.net"):
            with self.subTest(owner=owner):
                result, calls = self.enrich({"live.example.com": POSITIVE},
                                            NSAnswer(owner, "ns1.afternic.com", "ns2.afternic.com"))
                self.assertEqual(result["live.example.com"]["parking"]["status"], "not_detected")
                self.assertEqual(calls, [("live.example.com", "NS")])

    def test_mixed_parking_and_unrelated_nameservers_are_uncertain(self):
        for targets in (("ns1.afternic.com", "ns1.example.net"),
                        ("ns1.afternic.com", "ns1.sedoparking.com")):
            with self.subTest(targets=targets):
                result, _ = self.enrich({"example.com": POSITIVE}, NSAnswer("example.com", *targets))
                parking = result["example.com"]["parking"]
                self.assertEqual(parking["status"], "unknown")
                self.assertIsNone(parking["provider"])
                self.assertIn("Mixed nameserver", parking["evidence"][-1])

    def test_dns_enrichment_failure_preserves_successful_observation(self):
        for error in (dns.resolver.LifetimeTimeout(), dns.resolver.NoNameservers(), dns.resolver.NXDOMAIN()):
            with self.subTest(error=type(error).__name__):
                original = {"example.com": deepcopy(POSITIVE)}
                before = deepcopy(original)
                result, _ = self.enrich(original, error)
                self.assertEqual(original, before)
                self.assertEqual(result["example.com"]["status"], "resolved")
                self.assertEqual(result["example.com"]["records"], POSITIVE["records"])
                self.assertEqual(result["example.com"]["parking"]["status"], "unknown")
                self.assertTrue(result["example.com"]["parking"]["evidence"])

    def test_nonresolved_observations_do_not_trigger_queries_or_retain_old_hint(self):
        original = {status + ".example": {"status": status, "records": [],
                    "parking": {"status": "likely_parked", "provider": "Sedo", "evidence": ["old"]}}
                    for status in ("unknown", "nxdomain", "noanswer")}
        with patch("typo_monitor.parking.dns.resolver.Resolver") as resolver:
            result = ParkingClassifier().enrich(original)
            resolver.assert_not_called()
        self.assertTrue(all(row["parking"]["status"] == "unknown" for row in result.values()))
        self.assertTrue(all(row["parking"]["provider"] is None for row in result.values()))

    def test_exact_domain_cached_only_within_current_enrichment_call(self):
        classifier = ParkingClassifier()
        calls = []
        answers = [NSAnswer("example.com", "ns1.afternic.com", "ns2.afternic.com"),
                   NSAnswer("example.com", "ns1.example.net", "ns2.example.net")]

        class Resolver:
            def resolve(self, domain, kind, **kwargs):
                calls.append((domain, kind))
                return answers.pop(0)

        with patch("typo_monitor.parking.dns.resolver.Resolver", Resolver):
            first = classifier.enrich({"Example.COM.": POSITIVE, "example.com": POSITIVE})
            second = classifier.enrich({"example.com": first["example.com"]})
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(row["parking"]["status"] == "likely_parked" for row in first.values()))
        self.assertEqual(second["example.com"]["parking"]["status"], "not_detected")

    def test_cancellation_before_enrichment_makes_no_queries(self):
        classifier = ParkingClassifier()
        classifier.cancel_event = threading.Event()
        classifier.cancel_event.set()
        with patch("typo_monitor.parking.dns.resolver.Resolver") as resolver:
            with self.assertRaisesRegex(RuntimeError, "canceled"):
                classifier.enrich({"example.com": POSITIVE})
            resolver.assert_not_called()

    def test_cancellation_during_lookup_does_not_return_success(self):
        classifier = ParkingClassifier()
        classifier.cancel_event = threading.Event()

        class Resolver:
            def resolve(self, *args, **kwargs):
                classifier.cancel_event.set()
                return NSAnswer("example.com", "ns1.afternic.com", "ns2.afternic.com")

        with patch("typo_monitor.parking.dns.resolver.Resolver", Resolver):
            with self.assertRaisesRegex(RuntimeError, "canceled"):
                classifier.enrich({"example.com": POSITIVE})

    def test_configured_recursive_servers_and_lookup_deadline_are_used(self):
        created = []

        class Resolver:
            def __init__(self):
                created.append(self)

            def resolve(self, domain, kind, **kwargs):
                self.query = (domain, kind, kwargs)
                raise dns.resolver.NoAnswer()

        classifier = ParkingClassifier(nameservers=["192.0.2.53"], lifetime=1.5, workers=2)
        with patch("typo_monitor.parking.dns.resolver.Resolver", Resolver):
            classifier.enrich({"example.com": POSITIVE})
        self.assertEqual(created[0].nameservers, ["192.0.2.53"])
        self.assertEqual(created[0].query, ("example.com", "NS", {
            "lifetime": 1.5, "search": False, "raise_on_no_answer": True,
        }))


if __name__ == "__main__":
    unittest.main()
