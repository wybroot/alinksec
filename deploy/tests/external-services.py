#!/usr/bin/env python3
"""Run opt-in public publisher/real metrics acceptance with one owned disposable service."""
import argparse
import datetime
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.request
import uuid

IMAGE = "quay.io/victoriametrics/victoria-metrics:v1.102.0"  # Official registry; standard deployment version.


def command(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=30, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("test_command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.test_command
    if argv[:1] == ["--"]:
        argv = argv[1:]
    if not argv:
        parser.error("Provide the Maven test command after --")
    root = args.output.resolve()
    # A fresh directory prevents a failed attempt from inheriting old successful receipts.
    root.mkdir(parents=True, exist_ok=False)
    name = "alinksec-external-" + uuid.uuid4().hex[:16]
    head = command("git", "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
    record = {"head": head, "run": os.environ.get("GITHUB_RUN_ID", "local"),
              "startedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "image": IMAGE, "testExitCode": None, "remainingOwnedContainers": None}
    def interrupted(_number, _frame):
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        command("docker", "image", "inspect", IMAGE, stdout=subprocess.DEVNULL)
        image = json.loads(command("docker", "image", "inspect", IMAGE, capture_output=True, text=True).stdout)[0]
        assert image["RepoDigests"], "Require a pulled official image digest"
        record.update(imageId=image["Id"], imageDigests=image["RepoDigests"])
        command("docker", "run", "-d", "--name", name, "--label", "alinksec.external.acceptance=" + name,
                "--user", "65532:65532", "--memory=192m", "--memory-swap=256m", "--cpus=1", "--pids-limit=64",
                "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--read-only",
                "--tmpfs", "/data:rw,size=96m,uid=65532,gid=65532", "--tmpfs", "/tmp:rw,size=16m,uid=65532,gid=65532",
                "-p", "127.0.0.1::8428", IMAGE, "-storageDataPath=/data", "-memory.allowedBytes=33554432",
                "-retentionPeriod=1d", "-httpListenAddr=:8428", stdout=subprocess.DEVNULL)
        port = command("docker", "port", name, "8428/tcp", capture_output=True, text=True).stdout.strip()
        assert port.startswith("127.0.0.1:") and port.count(":") == 1
        base = "http://" + port
        deadline = time.monotonic() + 30
        while True:
            try:
                with urllib.request.urlopen(base + "/health", timeout=2) as response:
                    if response.status == 200:
                        break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
            time.sleep(.2)
        env = dict(os.environ, ALINKSEC_EXTERNAL_EVIDENCE=str(root), ALINKSEC_EXTERNAL_VM_URL=base)
        record["testExitCode"] = subprocess.run(argv, env=env, timeout=900).returncode
    finally:
        inspect = subprocess.run(["docker", "inspect", name], capture_output=True, text=True, timeout=15)
        if inspect.returncode == 0:
            owned = json.loads(inspect.stdout)[0]
            assert owned["Config"]["Labels"].get("alinksec.external.acceptance") == name
            logs = subprocess.run(["docker", "logs", "--tail", "100", name], capture_output=True, timeout=15)
            (root / "victoriametrics.log").write_bytes((logs.stdout + logs.stderr)[-65536:])
            record["containerState"] = {k: owned["State"][k] for k in ["Status", "OOMKilled", "ExitCode"]}
            command("docker", "rm", "-f", name, stdout=subprocess.DEVNULL)
        remaining = command("docker", "ps", "-aq", "--filter", "label=alinksec.external.acceptance=" + name,
                            capture_output=True, text=True).stdout.strip()
        record["remainingOwnedContainers"] = len(remaining.splitlines())
        record["finishedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (root / "run.json").write_text(json.dumps(record, indent=2) + "\n")
    assert record["remainingOwnedContainers"] == 0
    assert record["testExitCode"] == 0, "External acceptance test command failed"


if __name__ == "__main__":
    main()
