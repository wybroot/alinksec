#!/usr/bin/env python3
"""Recheck external acceptance from raw receipts, real exports and exact JUnit cases."""
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

PUBLISHERS = {
    "ubuntu-usn": "https://ubuntu.com/security/notices/USN-6727-1.json",
    "debian-tracker": "https://security-tracker.debian.org/tracker/data/json",
    "redhat-csaf": "https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_0001.json",
    "msrc-cvrf": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2024-Apr",
}


def verify(root, reports, head):
    run = json.loads((root / "run.json").read_text())
    assert run["head"] == head and run["testExitCode"] == 0 and run["remainingOwnedContainers"] == 0
    assert run["containerState"]["OOMKilled"] is False
    assert run["image"] == "quay.io/victoriametrics/victoria-metrics:v1.102.0" and run["imageDigests"]
    publisher_cases = ET.parse(reports / "TEST-com.alinksec.bootstrap.VendorAdvisoryLiveIntegrationTest.xml").getroot()
    metrics_cases = ET.parse(reports / "TEST-com.alinksec.bootstrap.ExternalMetricsIntegrationTest.xml").getroot()
    for suite, count in [(publisher_cases, 4), (metrics_cases, 2)]:
        assert int(suite.attrib["tests"]) == count
        assert all(int(suite.attrib.get(key, 0)) == 0 for key in ["failures", "errors", "skipped"])
        assert len(suite.findall("testcase")) == count
        assert all(len(case) == 0 or not any(case.find(kind) is not None for kind in ["skipped", "failure", "error"]) for case in suite.findall("testcase"))
    assert all(case.attrib["name"].startswith("actualPublisherSyncCommitsRawBytesAndServesProtectedApis") for case in publisher_cases.findall("testcase"))
    assert {case.attrib["name"] for case in metrics_cases.findall("testcase")} == {
        "realVictoriaMetricsRetainsSampleMillisecondsLabelsAndQueryResults", "recentSamplesAreQueryableWithoutTheDefaultThirtySecondOffset"}
    accepted = []
    for kind, url in PUBLISHERS.items():
        receipt = json.loads((root / "publishers" / (kind + ".json")).read_text())
        raw = (root / "publishers" / (kind + ".raw")).read_bytes()
        assert receipt["format"] == kind and receipt["url"] == url and receipt["rawFile"] == kind + ".raw"
        assert 0 < len(raw) == receipt["bytes"] <= 32 << 20
        assert hashlib.sha256(raw).hexdigest() == receipt["sha256"] and receipt["cveCount"] > 0
        ids = receipt["cveIds"]
        assert ids == sorted(set(ids)) and len(ids) == receipt["cveCount"]
        assert all(re.fullmatch(r"CVE-\d{4}-\d{4,19}", value) for value in ids)
        assert hashlib.sha256("\n".join(ids).encode()).hexdigest() == receipt["cveSetSHA256"]
        assert receipt["originKind"] == "official_https" and receipt["database"] == "isolated_sqlite"
        assert receipt["protectedRawApiVerified"] and receipt["declarationApiVerified"]
        assert receipt["publisherSignatureVerified"] is False and receipt["liveHostApplicabilityVerified"] is False
        if kind != "ubuntu-usn":
            assert receipt["exactVersionRules"] == 0
        accepted.append({k: receipt[k] for k in ["format", "sha256", "bytes", "cveCount", "cveSetSHA256"]})
    metrics = json.loads((root / "metrics/result.json").read_text())
    assert metrics["accepted"] and metrics["sampleCount"] == 2 and metrics["millisecondPrecisionVerified"] and metrics["escapedLabelsVerified"]
    assert metrics["productionForwarder"] and metrics["productionQueryClient"]
    assert metrics["nativeAgentTransportVerified"] is False and metrics["realHostLongSoakVerified"] is False
    assert metrics["latencyAcceptance"] is False and metrics["sampleAgeSeconds"] == 60
    samples = {}
    for line in (root / "metrics/export.ndjson").read_text().splitlines():
        row = json.loads(line)
        assert row["metric"]["__name__"] == "alinksec_external_probe"
        assert row["metric"]["hostname"] == '隔离主机\\"\nVictoriaMetrics' and row["metric"]["mount"] == 'C:\\监测\\"\n目录'
        for timestamp, value in zip(row["timestamps"], row["values"], strict=True):
            assert timestamp not in samples
            samples[timestamp] = value
    first, second = metrics["timestamps"]
    assert samples == {first: 12.5, second: 25.75} and first % 1000 == 123 and second - first == 1111
    instant = json.loads((root / "metrics/query.json").read_text())["data"]
    assert instant["status"] == "success" and len(instant["data"]["result"]) == 1
    assert float(instant["data"]["result"][0]["value"][1]) == 25.75
    interval = json.loads((root / "metrics/query-range.json").read_text())["data"]
    assert interval["status"] == "success" and interval["data"]["result"]
    recent = json.loads((root / "metrics-recent/result.json").read_text())
    assert recent["accepted"] and recent["queryLatencyOffset"] == "1ms" and 0 <= recent["elapsedMillis"] < 10000
    assert recent["realHostLongSoakVerified"] is False and recent["oneSecondSlaAccepted"] is False
    observations = json.loads((root / "metrics-recent/observations.json").read_text())
    assert observations and observations[-1]["elapsedMillis"] == recent["elapsedMillis"]
    assert all(0 <= a["elapsedMillis"] <= b["elapsedMillis"] for a, b in zip(observations, observations[1:]))
    assert all(o["response"]["status"] == "success" for o in observations)
    last = observations[-1]["response"]
    assert last["status"] == "success" and len(last["data"]["result"]) == 1
    assert float(last["data"]["result"][0]["value"][1]) == 42.125
    raw_recent = [json.loads(line) for line in (root / "metrics-recent/export.ndjson").read_text().splitlines()]
    assert len(raw_recent) == 1 and raw_recent[0]["metric"]["agent_id"] == recent["agentId"]
    assert raw_recent[0]["metric"]["__name__"] == "alinksec_recent_probe"
    assert raw_recent[0]["timestamps"] == [recent["timestamp"]] and raw_recent[0]["values"] == [42.125]
    recent_range = json.loads((root / "metrics-recent/query-range.json").read_text())
    assert recent_range["status"] == "success" and len(recent_range["data"]["result"]) == 1
    series = recent_range["data"]["result"][0]
    assert series["metric"]["agent_id"] == recent["agentId"]
    assert series["values"] and all(float(point[1]) == 42.125 for point in series["values"])
    result = {"accepted": True, "head": head, "run": run["run"], "publishers": accepted, "realDisposableVictoriaMetrics": True,
              "recentVisibilityMillis": recent["elapsedMillis"], "oneSecondSlaAccepted": False,
              "realPrivateServicesAccepted": False, "realWindowsPatchAccepted": False, "realHostLongSoakAccepted": False}
    (root / "accepted.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return result


if __name__ == "__main__":
    print(json.dumps(verify(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]), ensure_ascii=False))
