#!/usr/bin/env python3
"""Valid SCAP for disposable REST lifecycle tests, including nine result rows.

REST report rows are protocol fixtures. Actual native interpretation is checked
independently by the three platform jobs using scap-fixture.py unchanged.
"""
import importlib.util
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as E
import zipfile
sys.dont_write_bytecode=True

spec=importlib.util.spec_from_file_location('fixture',Path(__file__).with_name('scap-fixture.py'))
fixture=importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
archive=fixture.create(Path(sys.argv[1]))
with zipfile.ZipFile(archive) as z:
    files={name:z.read(name) for name in z.namelist()}
manifest=json.loads(files['alinksec-scap.json'])
manifest.update(code='ALINKSEC-SCAP-REST-FIXTURE',name='离线标准核查内容',osType=1,osVersionPattern='ubuntu.*')
xml=files['native-ds.xml'].decode('utf-8')
document=E.fromstring(xml)
ns='{http://checklists.nist.gov/xccdf/1.2}'
rule=document.find('.//'+ns+'Rule')
# Retain original namespace serialization used by official native content.
sample=xml[xml.index('<xccdf:Rule '):xml.index('</xccdf:Rule>')+len('</xccdf:Rule>')]
extra=''.join(sample.replace(rule.attrib['id'],fixture.PREFIX+name).replace('<xccdf:title>external</xccdf:title>','<xccdf:title>'+name+'</xccdf:title>') for name in ['unknown','notchecked','informational','fixed'])
xml=xml.replace('</xccdf:Benchmark>',extra+'</xccdf:Benchmark>')
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
    z.writestr('alinksec-scap.json',json.dumps(manifest))
    z.writestr('native-ds.xml',xml)
print(archive)
