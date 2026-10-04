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
