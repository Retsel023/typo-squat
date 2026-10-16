import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import dns.resolver
import dns.rrset

from typo_monitor.adapters import AilGenerator, DnsResolver, Subfinder


class Answer(list):
    def __init__(self, name, kind, *values, aliases=()):
        super().__init__(dns.rrset.from_text(name, 60, "IN", kind, *values))
        self.response = SimpleNamespace(answer=list(aliases))


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers

    def resolve(self, domain, kind, **kwargs):
        value = self.answers[kind]
        if isinstance(value, Exception):
            raise value
        return value


class DnsTests(unittest.TestCase):
    def observe(self, answers):
        resolver = DnsResolver(resolver_factory=lambda: FakeResolver(answers))
        return resolver.observe("example.com")

    def test_alias_records_stay_attached_to_query_owner(self):
        alias = dns.rrset.from_text("example.com.", 30, "IN", "CNAME", "Target.Example.net.")
        result = self.observe({"A": Answer("target.example.net", "A", "192.0.2.1", aliases=[alias]),
                               "AAAA": dns.resolver.NoAnswer(),
                               "CNAME": Answer("example.com", "CNAME", "Target.Example.net.")})
        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["records"], [("A", "192.0.2.1"), ("CNAME", "target.example.net")])

    def test_partial_positive_with_timeout_cannot_replace_complete_rrset(self):
        result = self.observe({"A": Answer("example.com", "A", "192.0.2.1"),
                               "AAAA": dns.resolver.LifetimeTimeout(), "CNAME": dns.resolver.NoAnswer()})
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["records"], [])
        self.assertEqual(result["partial_records"], [("A", "192.0.2.1")])

    def test_explicit_negative_is_different_from_resolver_failure(self):
        for exception, expected in ((dns.resolver.NXDOMAIN, "nxdomain"),
                                    (dns.resolver.NoAnswer, "noanswer"),
                                    (dns.resolver.NoNameservers, "unknown")):
            with self.subTest(exception=exception):
                self.assertEqual(self.observe({kind: exception() for kind in ("A", "AAAA", "CNAME")})["status"], expected)

    def test_contradictory_existence_answers_are_unknown(self):
        self.assertEqual(self.observe({"A": dns.resolver.NXDOMAIN(), "AAAA": dns.resolver.NoAnswer(),
                                       "CNAME": dns.resolver.NoAnswer()})["status"], "unknown")

    def test_positive_ipv6_prevents_a_only_false_negative(self):
        self.assertEqual(self.observe({"A": dns.resolver.NoAnswer(), "AAAA": Answer("example.com", "AAAA", "2001:db8::1"),
                                       "CNAME": dns.resolver.NoAnswer()})["status"], "resolved")


class ToolTests(unittest.TestCase):
    def test_generation_cache_profile_changes_with_output_inputs_not_timeouts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = ["tldextract/.tld_set_snapshot", "ail_typo_squatting/etc/common-misspellings.json",
                     "ail_typo_squatting/etc/homophones.txt", "ail_typo_squatting/etc/tlds-alpha-by-domain.txt"]
            for name in paths:
                resource = root / name
                resource.parent.mkdir(parents=True, exist_ok=True)
                resource.write_text("fixture", encoding="utf-8")
            packages = {"ail-typo-squatting": SimpleNamespace(version="fixture-ail", locate_file=lambda name: root / name),
                        "tldextract": SimpleNamespace(version="fixture-psl", locate_file=lambda name: root / name)}
            with (patch("typo_monitor.adapters.distribution", side_effect=lambda name: packages[name]),
                  patch("typo_monitor.adapters.version", return_value="fixture-inflect") as dependency_version):
                baseline = AilGenerator(timeout=1).cache_signature()
                self.assertEqual(AilGenerator(timeout=999).cache_signature(), baseline)
                for name in paths:
                    resource = root / name
                    resource.write_text("changed fixture", encoding="utf-8")
                    self.assertNotEqual(AilGenerator().cache_signature(), baseline, name)
                    resource.write_text("fixture", encoding="utf-8")
                packages["ail-typo-squatting"].version = "updated-ail"
                self.assertNotEqual(AilGenerator().cache_signature(), baseline)
                packages["ail-typo-squatting"].version = "fixture-ail"
                packages["tldextract"].version = "updated-psl"
                self.assertNotEqual(AilGenerator().cache_signature(), baseline)
                packages["tldextract"].version = "fixture-psl"
                dependency_version.return_value = "updated-inflect"
                self.assertNotEqual(AilGenerator().cache_signature(), baseline)

    def test_missing_generation_profile_resource_cannot_reuse_an_old_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            package = SimpleNamespace(version="fixture", locate_file=lambda name: Path(directory) / name)
            with patch("typo_monitor.adapters.distribution", return_value=package):
                with self.assertRaises(FileNotFoundError):
                    AilGenerator().cache_signature()

    def test_subfinder_keeps_partial_in_scope_results_and_records_failure(self):
        def run(args, **kwargs):
            self.assertEqual(args, ["test-subfinder", "-d", "example.com", "-silent"])
            self.assertNotIn("shell", kwargs)
            kwargs["stdout"].write("Portal.Example.com.\nexample.com.attacker.net\nhttps://bad.com\n")
            return SimpleNamespace(returncode=1)
        with tempfile.TemporaryDirectory() as directory, patch("typo_monitor.adapters.subprocess.run", run):
            found, status = Subfinder("test-subfinder").discover(["example.com"], Path(directory))
        self.assertEqual(found, ["portal.example.com"])
        self.assertEqual(status["status"], "partial")

    def test_ail_filters_invalid_transformations_without_weakening_user_validation(self):
        def run(args, **kwargs):
            output = Path(args[-1])
            (output / "example.com.txt").write_text("EXAMPLE.COM.\nexamp1e.com\nexample-com\n", encoding="utf-8")
            return SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as directory, patch("typo_monitor.adapters.subprocess.run", run):
            candidates, status = AilGenerator().generate(["example.com"], Path(directory))
        self.assertEqual(candidates, ["examp1e.com", "example.com"])
        self.assertEqual(status["invalid_generated_names"], 1)

    def test_generation_error_does_not_look_like_empty_success(self):
        with tempfile.TemporaryDirectory() as directory, patch("typo_monitor.adapters.subprocess.run", return_value=SimpleNamespace(returncode=2)):
            with self.assertRaisesRegex(RuntimeError, "generation failed"):
                AilGenerator().generate(["example.com"], Path(directory))

    def test_generated_candidate_retains_all_source_seeds(self):
        def run(args, **kwargs):
            output = Path(args[-1])
            (output / "example.com.txt").write_text("example.com\nshared-typo.com\n", encoding="utf-8")
            (output / "portal.example.com.txt").write_text("portal.example.com\nshared-typo.com\nportal.examp1e.com\n", encoding="utf-8")
            return SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as directory, patch("typo_monitor.adapters.subprocess.run", run):
            generator = AilGenerator()
            generated, _ = generator.generate(["example.com", "portal.example.com"], Path(directory))
        self.assertIn("shared-typo.com", generated)
        self.assertEqual(generator.provenance["shared-typo.com"], ["example.com", "portal.example.com"])
        self.assertEqual(generator.provenance["portal.examp1e.com"], ["portal.example.com"])


if __name__ == "__main__":
    unittest.main()
