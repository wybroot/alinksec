#!/usr/bin/env python3
"""Check actual REST derivation preserves this fixture's standard semantics."""
import io
import json
import sys
import xml.etree.ElementTree as E
import zipfile

content = sys.stdin.buffer.read((2 << 20) + 1)
assert 0 < len(content) <= 2 << 20
with zipfile.ZipFile(io.BytesIO(content)) as archive:
    manifest = json.loads(archive.read('alinksec-scap.json'))
    document = E.fromstring(archive.read(manifest['benchmarkFile']))
ns = '{http://checklists.nist.gov/xccdf/1.2}'
benchmark = next(document.iter(ns + 'Benchmark'))
assert benchmark.attrib.get('resolved') in ['true', '1']
assert all('extends' not in e.attrib for e in benchmark.iter())
profile = next(e for e in benchmark.findall(ns + 'Profile') if e.attrib['id'] == manifest['profileId'])
selection = {e.attrib['idref']: e.attrib['selected'] for e in profile.findall(ns + 'select')}
assert selection == {'xccdf_org.alinksec_rule_' + name: selected for name, selected in [
    ('external', 'true'), ('failure', 'true'), ('compound', 'true'),
    ('unselected', 'false'), ('platform', 'true'),
]}, ('standard resolver changed inherited rule selections', selection)
assert any(e.attrib.get('idref') == 'xccdf_org.alinksec_value_expected' and e.text == 'observed-native'
           for e in profile.findall(ns + 'set-value'))
assert len(list(benchmark.iter(ns + 'Rule'))) == 9
print('PASS actual REST derivation preserves inherited selections and external variable')
