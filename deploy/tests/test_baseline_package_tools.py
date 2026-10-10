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
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))
        for row in document["items"]:
            self.assertEqual("sshd_effective", row["check"]["type"])
            self.assertEqual({"user", "host", "address", "local_address", "local_port"}, set(row["check"]["connection"]))
            self.assertNotIn("cmd", row["check"])
            self.assertNotIn("fix_spec", row)
            mapping = next(r for r in review if r["ruleId"] == row["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(row["check"], mapping["check"])

    def test_systemd_maintenance_binds_loaded_units_and_independent_clock_indicator(self):
        document = BUILDER.build(ROOT / "deploy/baseline/systemd-maintenance-definitions.json", "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/systemd-maintenance/linux-baseline.json").read_text()))
        self.assertEqual({"BL-LINUX-0046", "BL-LINUX-0055"}, {item["ruleId"] for item in document["items"]})
        self.assertLessEqual(len(document["product"]), 128)
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        for item in document["items"]:
            self.assertEqual("systemd_maintenance", item["check"]["type"])
            self.assertLessEqual(len(item["remediation"]), 1000)
            self.assertEqual("local-system", item["check"]["target"])
            self.assertIn("command=systemd-", item["check"]["expected"])
            mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(item["check"], mapping["check"])
            self.assertNotIn("fix_spec", item)
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))

    def test_ipv4_host_batch_requires_role_and_complete_interface_references(self):
        document = BUILDER.build(ROOT / "deploy/baseline/ipv4-host-definitions.json", "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/ipv4-host/linux-baseline.json").read_text()))
        self.assertEqual({"BL-LINUX-0036", "BL-LINUX-0038"}, {item["ruleId"] for item in document["items"]})
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        for item in document["items"]:
            self.assertEqual("linux_ipv4_host", item["check"]["type"])
            self.assertEqual("/proc/sys/net/ipv4", item["check"]["target"])
            self.assertIn("role=non-router-symmetric", item["check"]["expected"])
            self.assertIn("/etc/alinksec/ipv4-host-role", item["remediation"])
            mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(item["check"], mapping["check"])
            self.assertNotIn("fix_spec", item)
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))
        self.assertEqual(8, sum(row["status"] == "mapped" for row in review))

    def test_bash_batch_keeps_five_full_references_and_both_startup_contexts(self):
        document = BUILDER.build(ROOT / "deploy/baseline/bash-policy-definitions.json", "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/bash-policy/linux-baseline.json").read_text()))
        self.assertEqual({f"BL-LINUX-{n:04}" for n in [10,17,26,44,45]}, {item["ruleId"] for item in document["items"]})
        self.assertEqual(["login_timeout","login_umask","history_time","history_capacity","nonlogin_umask"], [item["check"]["option"] for item in document["items"]])
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        for item in document["items"]:
            self.assertEqual("bash_global_policy", item["check"]["type"])
            self.assertEqual("/etc", item["check"]["target"])
            mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(item["check"], mapping["check"])
            self.assertNotIn("fix_spec", item)
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))
        self.assertEqual(8, sum(row["status"] == "mapped" for row in review))

    def test_shadow_defaults_batches_only_ordinary_new_account_declarations(self):
        definitions = ROOT / "deploy/baseline/shadow-defaults-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/shadow-defaults/linux-baseline.json").read_text()))
        self.assertEqual({"BL-LINUX-0003", "BL-LINUX-0004"}, {item["ruleId"] for item in document["items"]})
        self.assertEqual([], document["unsupported"])
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        for item in document["items"]:
            self.assertEqual("shadow_account_defaults", item["check"]["type"])
            self.assertEqual("/etc/login.defs", item["check"]["target"])
            self.assertEqual("eq", item["check"]["operator"])
            self.assertIn("max_days", item["check"]["expected"])
            mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(item["check"], mapping["check"])
            self.assertNotIn("fix_spec", item)
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))
        self.assertEqual(8, sum(row["status"] == "mapped" for row in review))

    def test_ssh_notice_batch_pins_reviewed_banner_bytes_and_both_connection_snapshots(self):
        definitions = ROOT / "deploy/baseline/ssh-notice-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/ssh-notice/linux-baseline.json").read_text()))
        self.assertEqual({"BL-LINUX-0020", "BL-LINUX-0043"}, {item["ruleId"] for item in document["items"]})
        self.assertEqual([], document["unsupported"])
        digest = hashlib.sha256((ROOT / "deploy/baseline/ssh-banner-reference.txt").read_bytes()).hexdigest()
        self.assertEqual("file=/etc/issue.net,sha256=" + digest, document["items"][1]["check"]["expected"])
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        for item in document["items"]:
            self.assertEqual("sshd_notice", item["check"]["type"])
            self.assertEqual("/etc/ssh/sshd_config", item["check"]["target"])
            self.assertEqual(document["items"][0]["check"]["connection"], item["check"]["connection"])
            mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(item["check"], mapping["check"])
            self.assertNotIn("fix_spec", item)
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))
        self.assertEqual(8, sum(row["status"] == "mapped" for row in review))

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

    def test_pam_auth_candidate_binds_login_and_three_stage_lockout_reference(self):
        definitions = ROOT / "deploy/baseline/pam-auth-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/pam-auth/linux-baseline.json").read_text()))
        self.assertEqual(["BL-LINUX-0005"], [item["ruleId"] for item in document["items"]])
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        item = document["items"][0]
        self.assertEqual("pam_auth", item["check"]["type"])
        self.assertEqual("/etc/pam.d/login", item["check"]["target"])
        self.assertIn("root_unlock_time=900..86400", item["check"]["expected"])
        self.assertNotIn("fix_spec", item)
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
        self.assertEqual("product_candidate", mapping["status"])
        self.assertEqual(item["check"], mapping["check"])

    def test_log_metadata_candidate_preserves_fixed_scope_and_mapping(self):
        definitions = ROOT / "deploy/baseline/log-metadata-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/log-metadata/linux-baseline.json").read_text()))
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        self.assertEqual({"BL-LINUX-0023", "BL-LINUX-0027", "BL-LINUX-0028"}, {item["ruleId"] for item in document["items"]})
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        for item in document["items"]:
            self.assertEqual("linux_log_metadata", item["check"]["type"])
            self.assertEqual("subset", item["check"]["operator"])
            self.assertNotIn("fix_spec", item)
            mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(item["check"], mapping["check"])

    def test_pam_limits_batches_three_rules_without_expanding_generic_coverage(self):
        definitions = ROOT / "deploy/baseline/pam-limits-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/pam-limits/linux-baseline.json").read_text()))
        self.assertEqual({"BL-LINUX-0039", "BL-LINUX-0056", "BL-LINUX-0057"}, {row["ruleId"] for row in document["items"]})
        self.assertEqual({"core", "nofile", "nproc"}, {row["check"]["option"] for row in document["items"]})
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        for item in document["items"]:
            self.assertEqual("pam_limits", item["check"]["type"])
            self.assertEqual("/etc/pam.d/login", item["check"]["target"])
            self.assertIn("default_and_explicit_root_soft=", item["check"]["expected"])
            self.assertIn(",hard=", item["check"]["expected"])
            self.assertNotIn("fix_spec", item)
            mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(item["check"], mapping["check"])
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))

    def test_ctrl_alt_del_candidate_binds_both_loaded_trigger_paths(self):
        definitions = ROOT / "deploy/baseline/ctrl-alt-del-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/ctrl-alt-del/linux-baseline.json").read_text()))
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        self.assertEqual(["BL-LINUX-0060"], [item["ruleId"] for item in document["items"]])
        item = document["items"][0]
        self.assertEqual("systemd_ctrl_alt_del", item["check"]["type"])
        self.assertEqual("ctrl-alt-del.target", item["check"]["target"])
        self.assertEqual("masked/inactive/dead,burst_action=none", item["check"]["expected"])
        self.assertNotIn("fix_spec", item)
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
        self.assertEqual("product_candidate", mapping["status"])
        self.assertEqual(item["check"], mapping["check"])
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))

    def test_systemd_candidate_preserves_exact_units_without_generic_coverage_expansion(self):
        definitions = ROOT / "deploy/baseline/systemd-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/systemd/linux-baseline.json").read_text()))
        self.assertEqual({"BL-LINUX-0022", "BL-LINUX-0024"}, {item["ruleId"] for item in document["items"]})
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        for item in document["items"]:
            self.assertEqual("systemd_service", item["check"]["type"])
            self.assertIn(item["check"]["target"], {"auditd.service", "rsyslog.service"})
            self.assertEqual("loaded/active/running", item["check"]["expected"])
            self.assertNotIn("fix_spec", item)
            mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(item["check"], mapping["check"])

    def test_audit_candidate_preserves_kernel_and_loaded_rule_reference(self):
        definitions = ROOT / "deploy/baseline/audit-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/audit/linux-baseline.json").read_text()))
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        self.assertEqual({"BL-LINUX-0021", "BL-LINUX-0025"}, {item["ruleId"] for item in document["items"]})
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        for item in document["items"]:
            self.assertEqual("linux_audit", item["check"]["type"])
            self.assertEqual("kernel", item["check"]["target"])
            self.assertNotIn("cmd", item["check"])
            self.assertNotIn("fix_spec", item)
            mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(item["check"], mapping["check"])
        self.assertEqual(8, sum(row["status"] == "mapped" for row in review))

    def test_cron_candidate_binds_all_system_table_metadata_without_log_claims(self):
        definitions = ROOT / "deploy/baseline/cron-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/cron/linux-baseline.json").read_text()))
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        self.assertEqual(["BL-LINUX-0019"], [item["ruleId"] for item in document["items"]])
        self.assertEqual({"BL-LINUX-0048", "BL-LINUX-0054"}, {row["ruleId"] for row in document["unsupported"]})
        item = document["items"][0]
        self.assertEqual("debian_cron_metadata", item["check"]["type"])
        self.assertEqual("system-tables", item["check"]["target"])
        self.assertIn("all_entries<=0644", item["check"]["expected"])
        self.assertNotIn("fix_spec", item)
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
        self.assertEqual("product_candidate", mapping["status"])
        self.assertEqual(item["check"], mapping["check"])
        self.assertEqual(42, sum(row["status"] == "product_candidate" for row in review))

    def test_rsyslog_cron_candidate_binds_fixed_routing_reference_and_mapping(self):
        definitions = ROOT / "deploy/baseline/rsyslog-cron-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/rsyslog-cron/linux-baseline.json").read_text()))
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        self.assertEqual(["BL-LINUX-0048"], [item["ruleId"] for item in document["items"]])
        item = document["items"][0]
        self.assertEqual("rsyslog_cron_routing", item["check"]["type"])
        self.assertEqual("/etc/rsyslog.conf", item["check"]["target"])
        self.assertEqual("imuxsock=on,cron.emerg..debug=/var/log/cron.log", item["check"]["expected"])
        self.assertNotIn("fix_spec", item)
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
        self.assertEqual("product_candidate", mapping["status"])
        self.assertEqual(item["check"], mapping["check"])
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))

    def test_apt_install_candidate_binds_default_disk_reference_and_mapping(self):
        definitions = ROOT / "deploy/baseline/apt-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/apt/linux-baseline.json").read_text()))
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        self.assertEqual(["BL-LINUX-0052"], [item["ruleId"] for item in document["items"]])
        item = document["items"][0]
        self.assertEqual("apt_install_policy", item["check"]["type"])
        self.assertEqual("/etc/apt", item["check"]["target"])
        self.assertEqual("apt/apt-get:AllowUnauthenticated=false,Force-Yes=false", item["check"]["expected"])
        self.assertNotIn("fix_spec", item)
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
        self.assertEqual("product_candidate", mapping["status"])
        self.assertEqual(item["check"], mapping["check"])
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))

    def test_apt_sources_candidate_binds_complete_declaration_reference_and_mapping(self):
        definitions = ROOT / "deploy/baseline/apt-sources-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/apt-sources/linux-baseline.json").read_text()))
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        self.assertEqual(["BL-LINUX-0053"], [item["ruleId"] for item in document["items"]])
        item = document["items"][0]
        self.assertEqual("apt_sources_policy", item["check"]["type"])
        self.assertEqual("/etc/apt", item["check"]["target"])
        self.assertEqual("apt/apt-get:AllowInsecureRepositories=false,AllowWeakRepositories=false,AllowDowngradeToInsecureRepositories=false;sources:Trusted!=yes,allow-insecure=false,allow-weak=false,allow-downgrade-to-insecure=false,Signed-By=explicit-keyring-files", item["check"]["expected"])
        self.assertNotIn("fix_spec", item)
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
        self.assertEqual("product_candidate", mapping["status"])
        self.assertEqual(item["check"], mapping["check"])
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))

    def test_sudoers_candidate_binds_explicit_declarations_and_mapping(self):
        definitions = ROOT / "deploy/baseline/sudoers-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/sudoers/linux-baseline.json").read_text()))
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        self.assertEqual({"BL-LINUX-0018", "BL-LINUX-0029"}, {item["ruleId"] for item in document["items"]})
        self.assertEqual({"authentication", "allowed_logging"}, {item["check"]["option"] for item in document["items"]})
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        for item in document["items"]:
            self.assertEqual("sudoers_policy", item["check"]["type"])
            self.assertEqual("/etc/sudoers", item["check"]["target"])
            self.assertNotIn("fix_spec", item)
            self.assertNotIn("cmd", item["check"])
            mapping = next(row for row in review if row["ruleId"] == item["ruleId"])
            self.assertEqual("product_candidate", mapping["status"])
            self.assertEqual(item["check"], mapping["check"])
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))

    def test_auditd_candidate_keeps_disk_declarations_separate_from_legacy_coverage(self):
        definitions = ROOT / "deploy/baseline/auditd-definitions.json"
        document = BUILDER.build(definitions, "linux")
        self.assertEqual(document, json.loads((ROOT / "deploy/baseline/packages/auditd/linux-baseline.json").read_text()))
        self.assertEqual(hashlib.sha256(definitions.read_bytes()).hexdigest(), document["source"]["sha256"])
        self.assertEqual({"local_logging", "keep_logs", "log_file_metadata"}, {item["check"]["option"] for item in document["items"]})
        self.assertEqual(2, len(document["unsupported"]))
        for item in document["items"]:
            self.assertEqual("auditd_config", item["check"]["type"])
            self.assertEqual("/etc/audit/auditd.conf", item["check"]["target"])
            self.assertNotIn("cmd", item["check"])
            self.assertNotIn("fix_spec", item)
        review = json.loads((ROOT / "deploy/baseline/reviewed-linux-definitions.json").read_text())["review"]["rules"]
        self.assertEqual(10, sum(row["status"] == "unsupported" for row in review))
        self.assertEqual(8, sum(row["status"] == "mapped" for row in review))

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
