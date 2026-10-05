import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("baseline_builder", ROOT / "deploy/baseline/build-package.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class BaselinePackageToolsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.definitions = ROOT / "deploy/baseline/starter-definitions.json"

    def tearDown(self):
        self.temp.cleanup()

    def test_both_platform_candidates_match_checked_in_packages_and_compiled_commands(self):
        registry = json.loads((ROOT / "agent/internal/baseline/commands.json").read_text())
        for platform in ["linux", "windows"]:
            document = BUILDER.build(self.definitions, platform)
            self.assertEqual(document, json.loads((ROOT / f"deploy/baseline/packages/{platform}-baseline.json").read_text()))
            self.assertTrue(all(item["check"]["cmd"] in registry[platform] for item in document["items"]))
            self.assertFalse(any("fix_spec" in item for item in document["items"]))
            self.assertEqual(hashlib.sha256(self.definitions.read_bytes()).hexdigest(), document["source"]["sha256"])

    def test_review_accounts_for_every_legacy_rule_without_silent_coverage(self):
        definitions = ROOT / "deploy/baseline/reviewed-linux-definitions.json"
        review = json.loads(definitions.read_text())["review"]["rules"]
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/reviewed/linux-baseline.json").read_text()))
        rules = {f"BL-LINUX-{index:04}" for index in range(1, 61)}
        self.assertEqual(rules, {row["ruleId"] for row in review})
        self.assertEqual(60, len(review))
        self.assertEqual(8, len(document["items"]))
        self.assertEqual(52, len(document["unsupported"]))
        self.assertEqual(rules, {row["ruleId"] for row in document["items"] + document["unsupported"]})
        self.assertTrue(all(row["reason"] for row in document["unsupported"]))
        self.assertTrue(all("check" not in row for row in review if row["status"] == "unsupported"))
        registry = json.loads((ROOT / "agent/internal/baseline/commands.json").read_text())
        self.assertTrue(all(row["check"]["cmd"] in registry["linux"] for row in document["items"]))
        self.assertTrue(all("fix_spec" not in row for row in document["items"]))

    def test_ssh_candidate_has_explicit_context_and_does_not_expand_generic_coverage(self):
        definitions = ROOT / "deploy/baseline/ssh-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/ssh/linux-baseline.json").read_text()))
        self.assertEqual({"BL-LINUX-0007", "BL-LINUX-0008"}, {row["ruleId"] for row in document["items"]})
        self.assertEqual(2, len(document["unsupported"]))
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        self.assertEqual(41, sum(row["status"] == "unsupported" for row in review))
        for row in document["items"]:
            self.assertEqual("sshd_effective", row["check"]["type"])
            self.assertEqual({"user", "host", "address", "local_address", "local_port"}, set(row["check"]["connection"]))
            self.assertNotIn("cmd", row["check"])
            self.assertNotIn("fix_spec", row)
            mapping = next(r for r in review if r["ruleId"] == row["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(row["check"], mapping["check"])

    def test_identity_candidate_keeps_local_file_and_uid_scope_in_reviewed_definitions(self):
        definitions = ROOT / "deploy/baseline/identity-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/identity/linux-baseline.json").read_text()))
        self.assertEqual({f"BL-LINUX-{i:04}" for i in [9,11,12,13,14,15,16]}, {item["ruleId"] for item in document["items"]})
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(),document["source"]["sha256"])
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        for item in document["items"]:
            mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
            self.assertEqual("product_candidate",mapping["status"])
            self.assertEqual(item["check"],mapping["check"])
            self.assertNotIn("fix_spec",item)
        shell = next(item["check"] for item in document["items"] if item["ruleId"] == "BL-LINUX-0015")
        self.assertEqual((1,999),(shell["uid_min"],shell["uid_max"]))
        self.assertEqual(8,sum(row["status"] == "mapped" for row in review))

    def test_pam_candidate_binds_passwd_service_and_explicit_quality_reference(self):
        definitions = ROOT / "deploy/baseline/pam-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/pam/linux-baseline.json").read_text()))
        self.assertEqual({"BL-LINUX-0002", "BL-LINUX-0006"}, {item["ruleId"] for item in document["items"]})
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        for item in document["items"]:
            self.assertEqual("pam_password", item["check"]["type"])
            self.assertEqual("/etc/pam.d/passwd", item["check"]["target"])
            mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(item["check"], mapping["check"])
            self.assertNotIn("fix_spec", item)
        quality = next(item["check"] for item in document["items"] if item["check"]["option"] == "quality")
        self.assertIn("enforce_for_root=1", quality["expected"])
        self.assertIn("use_authtok=1", quality["expected"])

    def mapping(self, xml):
        raw = xml.encode(); upstream = self.root / "xccdf.xml"; upstream.write_bytes(raw)
        definition = json.loads(self.definitions.read_text())
        platform = definition["platforms"]["linux"]
        platform["upstreamSha256"] = hashlib.sha256(raw).hexdigest()
        platform["items"] = platform["items"][:1]; platform["items"][0]["ruleId"] = "rule_supported"
        mapping = self.root / "definitions.json"; mapping.write_text(json.dumps(definition))
        return mapping, upstream

    def test_unmapped_xccdf_rules_remain_explicitly_unsupported(self):
        mapping, xml = self.mapping('<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><Rule id="rule_supported"/><Rule id="rule_unsupported"/></Benchmark>')
        document = BUILDER.build(mapping, "linux", xml)
        self.assertEqual("rule_unsupported", document["unsupported"][0]["ruleId"])
        self.assertEqual(1, len(document["items"]))
        self.assertEqual(hashlib.sha256(xml.read_bytes()).hexdigest(), document["source"]["sha256"])

    def test_changed_upstream_is_rejected_before_conversion(self):
        mapping, xml = self.mapping('<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><Rule id="rule_supported"/></Benchmark>')
        xml.write_text("Changed upstream")
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            BUILDER.build(mapping, "linux", xml)

    def test_missing_or_duplicate_upstream_rule_ids_are_rejected(self):
        for content in ['<Rule id="other"/>', '<Rule id="rule_supported"/><Rule id="rule_supported"/>']:
            mapping, xml = self.mapping(f'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">{content}</Benchmark>')
            with self.assertRaises(ValueError):
                BUILDER.build(mapping, "linux", xml)

    def test_entities_are_rejected_without_reading_external_files(self):
        mapping, xml = self.mapping('<!DOCTYPE Benchmark [<!ENTITY x SYSTEM "file:///etc/passwd">]><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><Rule id="rule_supported"/></Benchmark>')
        with self.assertRaisesRegex(ValueError, "DTD"):
            BUILDER.build(mapping, "linux", xml)

    def test_pinned_mapping_requires_upstream_file(self):
        mapping, _ = self.mapping('<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><Rule id="rule_supported"/></Benchmark>')
        with self.assertRaisesRegex(ValueError, "require --xccdf"):
            BUILDER.build(mapping, "linux")

    def test_duplicate_json_fields_are_rejected(self):
        definition = self.root / "bad.json"; definition.write_text('{"platforms":{},"platforms":{}}')
        with self.assertRaisesRegex(ValueError, "Duplicate field"):
            BUILDER.build(definition, "linux")
