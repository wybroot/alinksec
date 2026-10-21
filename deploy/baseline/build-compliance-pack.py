#!/usr/bin/env python3
"""Reproduce the reviewed MLPS 2.0 host packs and compiled coverage catalog."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'deploy/baseline/compliance'
RESOURCE = ROOT / 'server/alinksec-service/src/main/resources/baseline/compliance-catalog.json'


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate field: {key}')
        result[key] = value
    return result


def build():
    raw = [(SOURCE / name).read_bytes() for name in ['catalog.json', 'definitions.json']]
    catalog, recipe = [json.loads(data, object_pairs_hook=unique) for data in raw]
    digest = hashlib.sha256(b'\0'.join(raw)).hexdigest()
    outputs = {RESOURCE: raw[0]}
    for profile in catalog['catalogs']:
        for platform, os_type in [('linux', 1), ('windows', 2)]:
            controls = {c['id']: c['requiredChecks'][platform] for c in profile['controls']}
            codes = {item['code'] for item in recipe[platform]}
            referenced = {code for values in controls.values() for code in values}
            if codes != referenced:
                raise ValueError(f'Unmapped or missing evidence checks: {platform} {profile["id"]}')
            level = profile['level']
            document = dict(schemaVersion=2, code=f'ALINKSEC-MLPS2-L{level}-{platform.upper()}',
                            name=f'等保 2.0 {level}级安全计算环境 · {platform.title()}',
                            standard=profile['standard'], product='Ubuntu 24.04 LTS' if os_type == 1 else 'Windows 10/11、Server 2019/2022/2025',
                            osType=os_type, osVersionPattern=recipe[platform+'Pattern'], version=recipe['version'],
                            source=dict(name='AlinkSec reviewed MLPS host evidence definitions', version=recipe['version'],
                                        url='https://github.com/wybroot/alinksec/tree/main/deploy/baseline/compliance', sha256=digest),
                            items=recipe[platform], unsupported=[],
                            compliance=dict(catalogId=profile['id'], catalogSha256=hashlib.sha256(json.dumps(profile, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest(), controlChecks=controls))
            outputs[ROOT / f'deploy/baseline/packages/compliance/level{level}/{platform}-baseline.json'] = (json.dumps(document, ensure_ascii=False, indent=2)+'\n').encode()
    return outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Fail if checked-in outputs differ')
    args = parser.parse_args()
    for path, content in build().items():
        if args.check:
            if not path.exists() or path.read_bytes() != content:
                raise SystemExit(f'Stale generated artifact: {path.relative_to(ROOT)}')
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        print(path.relative_to(ROOT))


if __name__ == '__main__':
    main()
