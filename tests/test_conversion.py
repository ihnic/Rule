"""Acceptance tests for the rule semantics consumed by each client.

Run with: python3 -m unittest discover -s tests -v
Network access and the platform-specific Mihomo executable are replaced locally.
"""

from contextlib import redirect_stdout
import io
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
import main as converter  # noqa: E402


class ConversionTests(unittest.TestCase):
    def setUp(self):
        original_directory = Path.cwd()
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.addCleanup(os.chdir, original_directory)
        os.chdir(temporary_directory.name)
        for directory in (
            "surge", "mosdns", "mihomo/domain", "mihomo/ip", "mihomo/classical"
        ):
            Path(directory).mkdir(parents=True, exist_ok=True)

        # A successful compiler must produce an artifact, just as Mihomo does.
        compiler_patch = patch.object(
            converter.subprocess, "run", side_effect=self.successful_compile
        )
        self.compiler = compiler_patch.start()
        self.addCleanup(compiler_patch.stop)
        force_update_patch = patch.object(converter, "FORCE_REWRITE", False)
        force_update_patch.start()
        self.addCleanup(force_update_patch.stop)
        network_patch = patch.object(
            converter.requests, "get",
            side_effect=AssertionError("Acceptance tests must not access the network"),
        )
        network_patch.start()
        self.addCleanup(network_patch.stop)

    @staticmethod
    def successful_compile(arguments, **kwargs):
        Path(arguments[-1]).write_bytes(b"test-mrs-artifact\n")
        return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="")

    @staticmethod
    def lines(path):
        return [
            line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    def convert(self, content, loader=None):
        data = converter.parse_rules(content, geosite_loader=loader)
        converter.write_outputs("anthropic", data)

    @staticmethod
    def write_custom(content):
        path = Path("custom/anthropic.txt")
        path.parent.mkdir(exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    @staticmethod
    def published_files():
        paths = [Path("versions.json")]
        for directory in ("surge", "mosdns", "mihomo"):
            paths.extend(Path(directory).rglob("*"))
        return {path: path.read_bytes() for path in paths if path.is_file()}

    @staticmethod
    def run_main():
        with redirect_stdout(io.StringIO()):
            return converter.main(["anthropic"])

    @staticmethod
    def version():
        return json.loads(Path("versions.json").read_text(encoding="utf-8"))["anthropic"]

    def test_exact_domains_and_suffixes_keep_distinct_matching_semantics(self):
        self.convert("DOMAIN,api.example.com\nDOMAIN-SUFFIX,example.net\n")
        self.assertEqual(
            set(self.lines("surge/anthropic.list")),
            {"DOMAIN,api.example.com", "DOMAIN-SUFFIX,example.net"},
        )
        self.assertEqual(
            set(self.lines("mosdns/anthropic.txt")),
            {"full:api.example.com", "domain:example.net"},
        )
        self.assertEqual(
            set(self.lines("mihomo/domain/anthropic_domain.list")),
            {"api.example.com", "+.example.net"},
        )

    def test_surge_preserves_ipv6_type_asn_and_resolution_options(self):
        self.convert(
            "IP-CIDR,160.79.104.0/21,no-resolve\n"
            "IP-CIDR6,2607:6bc0::/32,no-resolve\n"
            "IP-ASN,399358,no-resolve\n"
            "IP-CIDR,192.0.2.0/24\n"
        )
        self.assertEqual(
            set(self.lines("surge/anthropic.list")),
            {
                "IP-CIDR,160.79.104.0/21,no-resolve",
                "IP-CIDR6,2607:6bc0::/32,no-resolve",
                "IP-ASN,399358,no-resolve",
                "IP-CIDR,192.0.2.0/24",
            },
        )

    def test_mosdns_keeps_keywords_without_ip_or_process_rules(self):
        self.convert(
            "DOMAIN-SUFFIX,anthropic.com\n"
            "DOMAIN-KEYWORD,datadog\n"
            "keyword:sentry\n"
            "keyword:sift\n"
            "IP-CIDR,160.79.104.0/21,no-resolve\n"
            "IP-CIDR6,2607:6bc0::/32,no-resolve\n"
            "IP-ASN,399358,no-resolve\n"
            "PROCESS-NAME,Claude\n"
        )
        self.assertEqual(
            set(self.lines("mosdns/anthropic.txt")),
            {"domain:anthropic.com", "keyword:datadog", "keyword:sentry", "keyword:sift"},
        )

    def test_mihomo_separates_domains_networks_and_classical_rules(self):
        self.convert(
            "DOMAIN,anthropic.auth0.com\n"
            "DOMAIN-SUFFIX,anthropic.com\n"
            "keyword:datadog\nkeyword:sentry\nkeyword:sift\n"
            "IP-CIDR,160.79.104.0/21,no-resolve\n"
            "IP-CIDR6,2607:6bc0::/32,no-resolve\n"
            "IP-ASN,399358,no-resolve\n"
            "PROCESS-NAME,Claude\n"
        )
        self.assertEqual(
            set(self.lines("mihomo/domain/anthropic_domain.list")),
            {"anthropic.auth0.com", "+.anthropic.com"},
        )
        self.assertEqual(
            set(self.lines("mihomo/ip/anthropic_ip.list")),
            {"160.79.104.0/21", "2607:6bc0::/32"},
        )
        self.assertEqual(
            set(self.lines("mihomo/classical/anthropic.list")),
            {
                "DOMAIN-KEYWORD,datadog", "DOMAIN-KEYWORD,sentry", "DOMAIN-KEYWORD,sift",
                "IP-ASN,399358,no-resolve", "PROCESS-NAME,Claude",
            },
        )
        self.assertTrue(Path("mihomo/domain/anthropic_domain.mrs").read_bytes())
        self.assertTrue(Path("mihomo/ip/anthropic_ip.mrs").read_bytes())

    def test_keyword_with_a_dot_is_not_mistaken_for_an_exact_domain(self):
        self.convert("keyword:sentry.io\n")
        self.assertEqual(self.lines("surge/anthropic.list"), ["DOMAIN-KEYWORD,sentry.io"])
        self.assertEqual(self.lines("mosdns/anthropic.txt"), ["keyword:sentry.io"])
        self.assertEqual(
            self.lines("mihomo/classical/anthropic.list"), ["DOMAIN-KEYWORD,sentry.io"]
        )
        self.assertFalse(Path("mihomo/domain/anthropic_domain.list").exists())

    def test_keyword_trailing_dot_does_not_expand_to_an_unbounded_substring(self):
        self.convert("DOMAIN-KEYWORD,TeSt.\n")
        rule = self.lines("mosdns/anthropic.txt")[0]
        self.assertTrue(rule.startswith("regexp:"))
        expression = rule.split(":", 1)[1]
        for host in ("test.example", "foo.test.com"):
            self.assertIsNotNone(re.search(expression, host))
        for host in ("testcase.example", "contest123.example"):
            self.assertIsNone(re.search(expression, host))
        self.assertEqual(self.lines("surge/anthropic.list"), ["DOMAIN-KEYWORD,TeSt."])

    def test_unsupported_modifiers_cannot_change_rule_meaning_silently(self):
        for rule in (
            "DOMAIN,example.com,extended-matching",
            "IP-CIDR,192.0.2.0/24,src",
            "DOMAIN-KEYWORD,a b",
            "IP-CIDR6,192.0.2.0/24",
        ):
            with self.subTest(rule=rule):
                with self.assertRaises(ValueError):
                    converter.parse_rules(rule)

    def test_existing_builtin_policy_is_removed_without_losing_no_resolve(self):
        self.convert("IP-CIDR,223.5.5.5/32,DIRECT,no-resolve\n")
        self.assertEqual(
            self.lines("surge/anthropic.list"), ["IP-CIDR,223.5.5.5/32,no-resolve"]
        )

    def test_empty_or_comment_only_remote_response_is_not_a_rule_update(self):
        for body in ("", " \n", "# temporarily empty\npayload:\n"):
            with self.subTest(body=body):
                response = Mock(text=body)
                with patch.object(converter.requests, "get", return_value=response):
                    with self.assertRaises(ValueError):
                        converter.fetch_text("https://example.com/rules.list")

    def test_geosite_groups_merge_with_custom_rules_without_duplicates(self):
        sources = {
            "anthropic": (
                "DOMAIN-SUFFIX,anthropic.com\n"
                "DOMAIN,console.claude.ai\n"
                "DOMAIN-KEYWORD,claude-test\n"
            ),
            "category-ntp": (
                "DOMAIN-SUFFIX,pool.ntp.org\n"
                "DOMAIN,time.nist.gov\n"
                "DOMAIN-SUFFIX,anthropic.com\n"
            ),
        }
        loader = Mock(side_effect=sources.__getitem__)
        self.convert(
            "geosite:anthropic\ngeosite:category-ntp\ngeosite:anthropic\n"
            "DOMAIN-SUFFIX,anthropic.com\nkeyword:claude-test\n",
            loader,
        )
        self.assertEqual(
            {call.args[0] for call in loader.call_args_list},
            {"anthropic", "category-ntp"},
        )
        expected = {
            "surge/anthropic.list": {
                "DOMAIN-SUFFIX,anthropic.com", "DOMAIN,console.claude.ai",
                "DOMAIN-SUFFIX,pool.ntp.org", "DOMAIN,time.nist.gov",
                "DOMAIN-KEYWORD,claude-test",
            },
            "mosdns/anthropic.txt": {
                "domain:anthropic.com", "full:console.claude.ai",
                "domain:pool.ntp.org", "full:time.nist.gov", "keyword:claude-test",
            },
            "mihomo/domain/anthropic_domain.list": {
                "+.anthropic.com", "console.claude.ai", "+.pool.ntp.org", "time.nist.gov",
            },
            "mihomo/classical/anthropic.list": {"DOMAIN-KEYWORD,claude-test"},
        }
        for path, expected_rules in expected.items():
            with self.subTest(path=path):
                rules = self.lines(path)
                self.assertEqual(set(rules), expected_rules)
                self.assertEqual(len(rules), len(expected_rules))

    def test_mixed_domain_notation_preserves_exact_and_suffix_rules(self):
        self.convert(
            "full:api.example.com\ndomain:example.net\n"
            "+.example.org\nstatic.example.edu\n"
        )
        self.assertEqual(
            set(self.lines("surge/anthropic.list")),
            {
                "DOMAIN,api.example.com", "DOMAIN-SUFFIX,example.net",
                "DOMAIN-SUFFIX,example.org", "DOMAIN,static.example.edu",
            },
        )

    def test_geosite_attribute_partitions_preserve_suffix_overlap_and_match_order(self):
        sources = {
            "category-ntp": (
                "DOMAIN,ntp.aliyun.com\nDOMAIN,time.google.com\n"
                "DOMAIN-SUFFIX,pool.ntp.org\nDOMAIN-SUFFIX,cn.pool.ntp.org\n"
                "DOMAIN,shared.example.com\nDOMAIN-SUFFIX,shared.example.com\n"
            ),
            "category-ntp@cn": (
                "full:NTP.ALIYUN.COM.\ndomain:cn.pool.ntp.org\n"
                "full:shared.example.com\n"
            ),
        }
        loader = Mock(side_effect=sources.__getitem__)
        for suffix, attribute in (("cn", "cn"), ("!cn", "!cn")):
            data = converter.parse_rules(f"geosite:category-ntp@{attribute}\n", loader)
            converter.write_outputs(f"category-ntp-{suffix}", data)

        positive = self.lines("surge/category-ntp-cn.list")
        negative = self.lines("surge/category-ntp-!cn.list")
        self.assertEqual(set(positive), {
            "DOMAIN,ntp.aliyun.com", "DOMAIN-SUFFIX,cn.pool.ntp.org",
            "DOMAIN,shared.example.com",
        })
        self.assertEqual(set(negative), {
            "DOMAIN,time.google.com", "DOMAIN-SUFFIX,pool.ntp.org",
            "DOMAIN-SUFFIX,shared.example.com",
        })
        self.assertEqual(set(self.lines("mosdns/category-ntp-!cn.txt")), {
            "full:time.google.com", "domain:pool.ntp.org", "domain:shared.example.com",
        })
        self.assertEqual(set(self.lines("mihomo/domain/category-ntp-!cn_domain.list")), {
            "time.google.com", "+.pool.ntp.org", "+.shared.example.com",
        })
        self.assertEqual({call.args[0] for call in loader.call_args_list}, set(sources))

        def matches(rules, host):
            for rule in rules:
                kind, domain = rule.split(",")
                if host == domain or (kind == "DOMAIN-SUFFIX" and host.endswith("." + domain)):
                    return True
            return False

        for host, expected in (
            ("ntp.aliyun.com", "cn"), ("0.cn.pool.ntp.org", "cn"),
            ("0.jp.pool.ntp.org", "!cn"), ("time.google.com", "!cn"),
        ):
            with self.subTest(host=host):
                selected = next(name for name, rules in (("cn", positive), ("!cn", negative))
                                if matches(rules, host))
                self.assertEqual(selected, expected)
        self.assertTrue(matches(negative, "0.cn.pool.ntp.org"))

    def test_negative_geosite_keeps_distinct_network_resolution_options(self):
        sources = {
            "example": (
                "IP-CIDR,192.0.2.0/24,no-resolve\nIP-CIDR,192.0.2.0/24\n"
                "IP-CIDR6,2001:db8::/32,no-resolve\nIP-CIDR6,2001:db8::/32\n"
                "IP-ASN,64512,no-resolve\nIP-ASN,64512\n"
                "keyword:keep\nkeyword:remove\n"
            ),
            "example@cn": (
                "IP-CIDR,192.0.2.5/24\nIP-CIDR6,2001:db8::1/32,no-resolve\n"
                "IP-ASN,64512\nkeyword:remove\n"
            ),
        }
        self.convert("geosite:example@!cn\n", sources.__getitem__)
        self.assertEqual(set(self.lines("surge/anthropic.list")), {
            "IP-CIDR,192.0.2.0/24,no-resolve", "IP-CIDR6,2001:db8::/32",
            "IP-ASN,64512,no-resolve", "DOMAIN-KEYWORD,keep",
        })
        self.assertEqual(set(self.lines("mihomo/ip/anthropic_ip.list")), {
            "192.0.2.0/24", "2001:db8::/32",
        })
        self.assertEqual(self.lines("mosdns/anthropic.txt"), ["keyword:keep"])

    def test_invalid_geosite_attribute_filters_fail_before_fetching(self):
        for label in ("category-ntp@!", "category-ntp@", "category-ntp@@cn",
                      "category-ntp@cn@!jp", "category-ntp@!!cn", "@!cn"):
            with self.subTest(label=label):
                loader = Mock()
                with self.assertRaisesRegex(ValueError, "无效的 geosite 标签"):
                    converter.parse_rules(f"geosite:{label}\n", loader)
                loader.assert_not_called()

    def test_negative_geosite_detects_cycles_in_either_dependency(self):
        for recursive_dependency in ("category-ntp", "category-ntp@cn"):
            with self.subTest(dependency=recursive_dependency):
                sources = {
                    "category-ntp": "DOMAIN,time.google.com\nDOMAIN,ntp.aliyun.com\n",
                    "category-ntp@cn": "DOMAIN,ntp.aliyun.com\n",
                }
                sources[recursive_dependency] = "geosite:category-ntp@!cn\n"
                with self.assertRaisesRegex(ValueError, "循环 geosite 引用"):
                    converter.parse_rules("geosite:category-ntp@!cn\n", sources.__getitem__)

    def test_unknown_geosite_does_not_silently_publish_an_incomplete_group(self):
        loader = Mock(side_effect=ValueError("Geosite group was not found"))
        with self.assertRaises(ValueError):
            self.convert("DOMAIN-SUFFIX,anthropic.com\ngeosite:missing-group\n", loader)
        self.assertFalse(Path("surge/anthropic.list").exists())
        self.assertFalse(Path("mosdns/anthropic.txt").exists())

    def test_invalid_rule_is_reported_instead_of_silently_dropped(self):
        for rule in ("keyword:", "geosite:", "DOMAIN-SUFFIX,", "NOT-A-RULE,example.com"):
            with self.subTest(rule=rule):
                with self.assertRaises(ValueError):
                    converter.parse_rules(rule, geosite_loader=Mock())

    def test_repository_anthropic_source_covers_all_three_requested_keywords(self):
        source = (PROJECT_ROOT / "custom/anthropic.txt").read_text(encoding="utf-8")
        loader = lambda tag: {
            "anthropic": "DOMAIN-SUFFIX,anthropic.com\n",
            "category-ntp": "DOMAIN-SUFFIX,pool.ntp.org\n",
        }[tag]
        self.convert(source, loader)
        for keyword in ("datadog", "sentry", "sift"):
            with self.subTest(keyword=keyword):
                self.assertIn(f"DOMAIN-KEYWORD,{keyword}", self.lines("surge/anthropic.list"))
                self.assertIn(
                    f"DOMAIN-KEYWORD,{keyword}", self.lines("mihomo/classical/anthropic.list")
                )
                self.assertIn(f"keyword:{keyword}", self.lines("mosdns/anthropic.txt"))

    def test_removing_keywords_removes_the_old_classical_file(self):
        self.convert("DOMAIN-SUFFIX,anthropic.com\nkeyword:datadog\n")
        self.assertTrue(Path("mihomo/classical/anthropic.list").exists())
        self.convert("DOMAIN-SUFFIX,anthropic.com\n")
        self.assertFalse(Path("mihomo/classical/anthropic.list").exists())
        self.assertEqual(self.lines("mosdns/anthropic.txt"), ["domain:anthropic.com"])

    def test_failed_mrs_compile_preserves_the_previously_published_group(self):
        self.convert("DOMAIN,previous.example.com\nIP-CIDR,192.0.2.0/24,no-resolve\n")
        previous_files = {
            path: path.read_bytes() for path in Path(".").rglob("*") if path.is_file()
        }
        compilation_attempts = 0

        def failed_compile(arguments, **kwargs):
            nonlocal compilation_attempts
            compilation_attempts += 1
            if compilation_attempts == 1:
                return self.successful_compile(arguments, **kwargs)
            Path(arguments[-1]).write_bytes(b"incomplete-artifact")
            raise subprocess.CalledProcessError(1, arguments, stderr="invalid rules")

        self.compiler.side_effect = failed_compile
        with self.assertRaises((RuntimeError, subprocess.CalledProcessError)):
            self.convert(
                "DOMAIN,new.example.com\nIP-CIDR,198.51.100.0/24,no-resolve\nkeyword:sentry\n"
            )
        self.assertEqual(compilation_attempts, 2)
        published_files = {
            path: path.read_bytes() for path in Path(".").rglob("*") if path.is_file()
        }
        self.assertEqual(published_files, previous_files)

    def test_compiler_exit_zero_without_an_artifact_is_not_success(self):
        self.compiler.side_effect = lambda arguments, **kwargs: subprocess.CompletedProcess(
            arguments, 0, stdout="", stderr=""
        )
        with self.assertRaises((RuntimeError, FileNotFoundError)):
            self.convert("DOMAIN,anthropic.auth0.com\n")
        self.assertFalse(Path("surge/anthropic.list").exists())
        self.assertFalse(Path("mihomo/domain/anthropic_domain.mrs").exists())

    def test_publication_failure_rolls_back_every_previous_artifact(self):
        self.convert("DOMAIN,previous.example.com\nkeyword:old\n")
        previous = {path: path.read_bytes() for path in Path('.').rglob('*') if path.is_file()}
        original_replace = os.replace
        injected = False

        def fail_once(source, destination):
            nonlocal injected
            if (not injected and str(destination) == 'mosdns/anthropic.txt'
                    and 'previous' not in Path(source).parts):
                injected = True
                raise OSError("simulated publication error")
            return original_replace(source, destination)

        with patch.object(converter.os, 'replace', side_effect=fail_once):
            with self.assertRaises(OSError):
                self.convert("DOMAIN,new.example.com\nkeyword:new\n")
        self.assertTrue(injected)
        self.assertEqual(
            {path: path.read_bytes() for path in Path('.').rglob('*') if path.is_file()}, previous
        )

    def test_upstream_geosite_changes_refresh_an_unchanged_custom_file(self):
        source = self.write_custom("geosite:anthropic\nkeyword:sentry\n")
        original_source = source.read_bytes()
        with patch.object(
            converter, "load_geosite", return_value="DOMAIN-SUFFIX,anthropic.com\n"
        ) as loader:
            self.assertEqual(self.run_main(), 0)
            original_version = self.version()
            self.compiler.reset_mock()
            self.assertEqual(self.run_main(), 0)
            self.compiler.assert_not_called()

            loader.return_value += "DOMAIN,added.example.com\n"
            self.assertEqual(self.run_main(), 0)
            self.assertIn("DOMAIN,added.example.com", self.lines("surge/anthropic.list"))
            self.assertIn("full:added.example.com", self.lines("mosdns/anthropic.txt"))
            self.assertNotEqual(self.version(), original_version)
            self.assertGreater(self.compiler.call_count, 0)
            self.assertEqual(source.read_bytes(), original_source)
            self.assertEqual(loader.call_count, 3)

    def test_negative_geosite_refreshes_when_only_positive_attribute_changes(self):
        source = self.write_custom("geosite:category-ntp@!cn\n")
        original_source = source.read_bytes()
        sources = {
            "category-ntp": (
                "DOMAIN,ntp.aliyun.com\nDOMAIN,time.google.com\nDOMAIN,new-cn.example.com\n"
            ),
            "category-ntp@cn": "DOMAIN,ntp.aliyun.com\n",
        }
        with patch.object(converter, "load_geosite", side_effect=sources.__getitem__) as loader:
            self.assertEqual(self.run_main(), 0)
            self.assertIn("DOMAIN,new-cn.example.com", self.lines("surge/anthropic.list"))
            original_version = self.version()
            self.compiler.reset_mock()
            self.assertEqual(self.run_main(), 0)
            self.compiler.assert_not_called()

            sources["category-ntp@cn"] += "DOMAIN,new-cn.example.com\n"
            self.assertEqual(self.run_main(), 0)
            self.assertEqual(self.lines("surge/anthropic.list"), ["DOMAIN,time.google.com"])
            self.assertEqual(self.lines("mosdns/anthropic.txt"), ["full:time.google.com"])
            self.assertEqual(self.lines("mihomo/domain/anthropic_domain.list"), ["time.google.com"])
            self.assertNotEqual(self.version(), original_version)
            self.assertGreater(self.compiler.call_count, 0)
            self.assertEqual(source.read_bytes(), original_source)
            self.assertEqual([call.args[0] for call in loader.call_args_list],
                             ["category-ntp", "category-ntp@cn"] * 3)

    def test_missing_positive_attribute_preserves_negative_outputs_and_version(self):
        self.write_custom("geosite:category-ntp@!cn\n")
        sources = {
            "category-ntp": "DOMAIN,time.google.com\nDOMAIN,ntp.aliyun.com\n",
            "category-ntp@cn": "DOMAIN,ntp.aliyun.com\n",
        }
        with patch.object(converter, "load_geosite", side_effect=sources.__getitem__) as loader:
            self.assertEqual(self.run_main(), 0)
            published = self.published_files()
            sources["category-ntp"] += "DOMAIN,new.example.com\n"

            def missing_attribute(label):
                if label == "category-ntp@cn":
                    raise converter.requests.HTTPError("404: attribute export missing")
                return sources[label]

            loader.side_effect = missing_attribute
            self.assertEqual(self.run_main(), 1)
            self.assertEqual(self.published_files(), published)

    def test_ntp_partitions_share_dependencies_but_refetch_on_every_run(self):
        Path("custom").mkdir()
        for name, label in (
            ("category-ntp", "category-ntp"),
            ("category-ntp-cn", "category-ntp@cn"),
            ("category-ntp-!cn", "category-ntp@!cn"),
        ):
            Path(f"custom/{name}.txt").write_text(f"geosite:{label}\n", encoding="utf-8")
        sources = {
            "category-ntp": "DOMAIN,time.google.com\nDOMAIN,ntp.aliyun.com\n",
            "category-ntp@cn": "DOMAIN,ntp.aliyun.com\n",
        }
        with patch.object(converter, "load_geosite", side_effect=sources.__getitem__) as loader:
            for run in range(2):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(converter.main(), 0)
                calls = [call.args[0] for call in loader.call_args_list]
                self.assertEqual(calls.count("category-ntp"), run + 1)
                self.assertEqual(calls.count("category-ntp@cn"), run + 1)
                self.assertEqual(len(calls), (run + 1) * 2)
        self.assertEqual(set(self.lines("surge/category-ntp.list")), {
            "DOMAIN,time.google.com", "DOMAIN,ntp.aliyun.com",
        })
        self.assertEqual(self.lines("surge/category-ntp-cn.list"), ["DOMAIN,ntp.aliyun.com"])
        self.assertEqual(self.lines("surge/category-ntp-!cn.list"), ["DOMAIN,time.google.com"])

    def test_same_name_remote_and_custom_sources_are_merged(self):
        self.write_custom("DOMAIN-SUFFIX,anthropic.com\nkeyword:sentry\n")
        remote_url = "https://rules.example.invalid/anthropic.list"
        Path("rules.txt").write_text(remote_url + "\n", encoding="utf-8")
        with patch.object(
            converter, "fetch_text",
            return_value="DOMAIN-SUFFIX,anthropic.com\nDOMAIN,remote.example.com\n",
        ):
            self.assertEqual(self.run_main(), 0)
        expected = {
            "DOMAIN-SUFFIX,anthropic.com", "DOMAIN-KEYWORD,sentry", "DOMAIN,remote.example.com"
        }
        rules = self.lines("surge/anthropic.list")
        self.assertEqual(set(rules), expected)
        self.assertEqual(len(rules), len(expected))
        self.assertEqual(
            set(self.lines("mosdns/anthropic.txt")),
            {"domain:anthropic.com", "keyword:sentry", "full:remote.example.com"},
        )

    def test_fetch_failure_keeps_outputs_and_version_from_the_successful_run(self):
        self.write_custom("keyword:sentry\n")
        Path("rules.txt").write_text(
            "https://rules.example.invalid/anthropic.list\n", encoding="utf-8"
        )
        with patch.object(
            converter, "fetch_text", return_value="DOMAIN-SUFFIX,anthropic.com\n"
        ) as fetch:
            self.assertEqual(self.run_main(), 0)
            published = self.published_files()
            fetch.side_effect = converter.requests.ConnectionError("upstream unavailable")
            self.assertEqual(self.run_main(), 1)
            self.assertEqual(self.published_files(), published)

    def test_unknown_rule_makes_main_fail_without_recording_a_successful_version(self):
        self.write_custom("NOT-A-RULE,anthropic.com\n")
        Path("versions.json").write_text('{"unrelated": "keep-this-version"}\n', encoding="utf-8")
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(
            json.loads(Path("versions.json").read_text(encoding="utf-8")),
            {"unrelated": "keep-this-version"},
        )
        self.assertFalse(Path("surge/anthropic.list").exists())
        self.assertFalse(Path("mosdns/anthropic.txt").exists())

    def test_converter_changes_rebuild_outputs_even_when_rules_are_unchanged(self):
        self.write_custom("DOMAIN-SUFFIX,anthropic.com\n")
        converter_version = Path("converter-version.py")
        converter_version.write_text("# converter version one\n", encoding="utf-8")
        with patch.object(converter, "__file__", str(converter_version)):
            self.assertEqual(self.run_main(), 0)
            original_version = self.version()
            self.compiler.reset_mock()
            self.assertEqual(self.run_main(), 0)
            self.compiler.assert_not_called()

            converter_version.write_text("# converter version two\n", encoding="utf-8")
            self.assertEqual(self.run_main(), 0)
            self.assertNotEqual(self.version(), original_version)
            self.assertGreater(self.compiler.call_count, 0)

    def test_compiler_upgrade_invalidates_cached_artifacts(self):
        self.write_custom("DOMAIN-SUFFIX,anthropic.com\n")
        compiler = Path('test-mihomo')
        compiler.write_bytes(b'compiler version one')
        with patch.object(converter, 'MIHOMO_BIN', str(compiler)):
            self.assertEqual(self.run_main(), 0)
            original_version = self.version()
            self.compiler.reset_mock()
            self.assertEqual(self.run_main(), 0)
            self.compiler.assert_not_called()

            compiler.write_bytes(b'compiler version two')
            self.assertEqual(self.run_main(), 0)
            self.assertNotEqual(self.version(), original_version)
            self.assertGreater(self.compiler.call_count, 0)

    def test_full_run_removes_deleted_sources_but_only_run_keeps_other_groups(self):
        source = self.write_custom("DOMAIN-SUFFIX,anthropic.com\nkeyword:sentry\n")
        self.assertEqual(self.run_main(), 0)
        source.unlink()
        Path('custom/other.txt').write_text('DOMAIN,other.example.com\n', encoding='utf-8')
        with redirect_stdout(io.StringIO()):
            self.assertEqual(converter.main(['other']), 0)
        self.assertTrue(Path('surge/anthropic.list').exists())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(converter.main(), 0)
        for path in converter.output_paths('anthropic'):
            self.assertFalse(Path(path).exists(), path)
        self.assertNotIn('anthropic', json.loads(Path('versions.json').read_text()))
        self.assertTrue(Path('surge/other.list').exists())

    def test_main_does_not_advance_the_version_when_mrs_compilation_fails(self):
        self.write_custom("DOMAIN-SUFFIX,anthropic.com\n")
        self.assertEqual(self.run_main(), 0)
        published = self.published_files()
        self.write_custom("DOMAIN-SUFFIX,anthropic.com\nDOMAIN,new.example.com\n")
        self.compiler.side_effect = subprocess.CalledProcessError(
            1, "test-mihomo", stderr="compilation failed"
        )
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.published_files(), published)


if __name__ == "__main__":
    unittest.main()
