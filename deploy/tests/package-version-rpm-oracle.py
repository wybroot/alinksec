#!/usr/bin/env python3
"""Read-only native RPM ordering; no database queries or package installation."""
import itertools
import json
import sys
import rpm

versions = json.load(sys.stdin)
assert isinstance(versions, list) and 0 < len(versions) <= 64
assert all(isinstance(v, str) and 0 < len(v) <= 255 and "\t" not in v and "\n" not in v for v in versions)

def label(value):
    epoch, colon, body = value.partition(":")
    if not colon:
        epoch, body = "0", value
    version, dash, release = body.rpartition("-")
    if not dash:
        version, release = body, None
    return epoch, version, release

for left, right in itertools.product(versions, repeat=2):
    comparison = rpm.labelCompare(label(left), label(right))
    print("rpm", left, right, (comparison > 0) - (comparison < 0), sep="\t")
