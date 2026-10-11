#!/usr/bin/env python3
"""Compare the Java implementation with all native RPM/DPKG pairs on isolated CI runners."""
import itertools
import json
import os
from pathlib import Path
import subprocess

repo = Path(__file__).resolve().parents[2]
assert os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
corpus = json.loads((repo / "deploy/tests/package-version-corpus.json").read_text())
records = []
for left, right in itertools.product(corpus["dpkg"], repeat=2):
    order = None
    for relation, sign in (("lt", -1), ("eq", 0), ("gt", 1)):
        result = subprocess.run(["/usr/bin/dpkg", "--compare-versions", left, relation, right], capture_output=True, timeout=5)
        assert result.returncode in (0, 1) and not result.stderr, "DPKG corpus must be valid without warnings"
        if result.returncode == 0:
            order = sign
            break
    assert order is not None
    records.append(f"dpkg\t{left}\t{right}\t{order}\n")
rpm = subprocess.run([
    "docker", "run", "--rm", "-i", "--network=none", "--memory=96m", "--memory-swap=128m", "--cpus=1", "--pids-limit=32",
    "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
    "--mount", f"type=bind,src={repo},dst=/workspace,readonly",
    "alinksec-dnf-native-validation:latest", "/usr/bin/python3", "-I", "/workspace/deploy/tests/package-version-rpm-oracle.py",
], input=json.dumps(corpus["rpm"]), text=True, capture_output=True, timeout=45, check=True)
assert not rpm.stderr and len(rpm.stdout.splitlines()) == len(corpus["rpm"]) ** 2
records.append(rpm.stdout)
evidence = "".join(records)
(repo / ".tmp/package-version-native.tsv").write_text(evidence)
subprocess.run([
    "java", "-Xmx64m", "-XX:ActiveProcessorCount=1", "-cp",
    "server/alinksec-service/target/classes:server/alinksec-service/target/test-classes",
    "com.alinksec.service.scan.PackageVersionOracle",
], cwd=repo, input=evidence, text=True, timeout=30, check=True)
