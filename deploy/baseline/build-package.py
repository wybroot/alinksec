#!/usr/bin/env python3
"""Build Linux/Windows candidates from reviewed declarative definitions; never execute a check."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

LIMIT = 32 * 1024 * 1024
XCCDF = {"http://checklists.nist.gov/xccdf/1.2", "http://checklists.nist.gov/xccdf/1.1"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate field: {key}")
        result[key] = value
    return result


def build(definitions_path, platform, xccdf_path=None):
    with Path(definitions_path).open("rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Definitions exceed 2 MiB")
    definitions = json.loads(raw, object_pairs_hook=unique_object)
    document = copy.deepcopy(definitions["platforms"][platform])
    document["schemaVersion"] = 1
    source = copy.deepcopy(definitions["source"])
    source_raw = raw
    if xccdf_path:
        with Path(xccdf_path).open("rb") as stream:
            source_raw = stream.read(LIMIT + 1)
        if len(source_raw) > LIMIT:
            raise ValueError("XCCDF exceeds 32 MiB")
        expected = document.pop("upstreamSha256", None)
        if not expected or hashlib.sha256(source_raw).hexdigest() != expected:
            raise ValueError("Pinned upstream SHA256 mismatch")
        # UTF-8 only and no DTD/entities; upstream content is parsed as data, never evaluated.
        text = source_raw.decode("utf-8-sig")
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper() or "\x00" in text:
            raise ValueError("DTD, entities and non-UTF-8 XML are unsupported")
        root = ET.fromstring(text)
        if root.tag not in {f"{{{namespace}}}Benchmark" for namespace in XCCDF}:
            raise ValueError("Use one standalone XCCDF Benchmark for the selected product")
        namespace = root.tag.split("}")[0] + "}"
        rules = [rule.attrib["id"] for rule in root.iter(namespace + "Rule")]
        if len(rules) != len(set(rules)) or len(rules) > 2000:
            raise ValueError("Duplicate or excessive upstream rules")
        mapped = [item["ruleId"] for item in document["items"]]
        if len(mapped) != len(set(mapped)) or not set(mapped) <= set(rules):
            raise ValueError("Reviewed mappings contain duplicate or missing upstream rule IDs")
        reasons = {item["ruleId"]: item["reason"] for item in document.get("unsupported", [])}
        document["unsupported"] = [{"ruleId": rule, "reason": reasons.get(rule, "No reviewed mapping to a supported Agent check")}
                                   for rule in rules if rule not in mapped]
    elif "upstreamSha256" in document:
        raise ValueError("Pinned upstream definitions require --xccdf")
    source["sha256"] = hashlib.sha256(source_raw).hexdigest()
    document["source"] = source
    if not document.get("items"):
        raise ValueError("A candidate must contain at least one reviewed check")
    if len(document["items"]) > 500 or len(document["items"]) + len(document.get("unsupported", [])) > 2000:
        raise ValueError("Candidate exceeds platform rule limits")
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--definitions", type=Path, default=Path(__file__).with_name("starter-definitions.json"))
    parser.add_argument("--platform", choices=["linux", "windows", "all"], default="all")
    parser.add_argument("--xccdf", type=Path, help="Pinned standalone upstream XCCDF; uses reviewed mappings only")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.xccdf and args.platform == "all":
        parser.error("Select one product platform when mapping an upstream XCCDF")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for platform in ["linux", "windows"] if args.platform == "all" else [args.platform]:
        document = build(args.definitions, platform, args.xccdf)
        destination = args.output_dir / f"{platform}-baseline.json"
        destination.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Candidate only: {destination}; {len(document['items'])} checks, {len(document['unsupported'])} unsupported")


if __name__ == "__main__":
    main()
