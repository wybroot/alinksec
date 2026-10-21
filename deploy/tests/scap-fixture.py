#!/usr/bin/env python3
"""Create small SCAP content which reads only a disposable native test file.

The profile changes an external OVAL variable, inherits rule selection and
unselects one rule. OVAL exercises a real text probe, a local concat variable,
AND criteria, negation and extend_definition on Linux and Windows.
"""
from pathlib import Path
from xml.sax.saxutils import escape
import json
import platform
import sys
import zipfile

BENCHMARK = 'xccdf_org.alinksec_benchmark_native'
PROFILE = 'xccdf_org.alinksec_profile_native'
PREFIX = 'xccdf_org.alinksec_rule_'

def create(root):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    observed = root/'observed.txt'
    observed.write_text('observed-native\n', encoding='utf-8')
    rules = ''
    for name, definition in [('external',1), ('failure',2), ('compound',3), ('unselected',1), ('platform',1)]:
        export = '<check-export export-name="oval:org.alinksec:var:1" value-id="xccdf_org.alinksec_value_expected"/>' if definition in [1,3] else ''
        applicability = '<platform idref="cpe:/a:alinksec:absent_fixture:1"/>' if name=='platform' else ''
        rules += f'''<Rule id="{PREFIX}{name}" selected="false" severity="medium" weight="1.0">
          <title>{name}</title><description>Disposable native interpreter evidence</description>
          {applicability}
          <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">{export}
            <check-content-ref href="checks.xml" name="oval:org.alinksec:def:{definition}"/>
          </check></Rule>'''
    definitions = ''
    for n in [1,2,3]:
        criteria = (f'<criteria><criterion test_ref="oval:org.alinksec:tst:{n}" comment="Read disposable fixture"/></criteria>' if n != 3 else '''<criteria operator="AND">
          <extend_definition definition_ref="oval:org.alinksec:def:1" comment="External variable passes"/>
          <extend_definition definition_ref="oval:org.alinksec:def:2" negate="true" comment="Failed definition negated"/>
          <criterion test_ref="oval:org.alinksec:tst:3" comment="Local concat variable"/>
          </criteria>''')
        definitions += f'''<definition id="oval:org.alinksec:def:{n}" version="1" class="compliance">
          <metadata><title>Native fixture {n}</title><description>Read-only disposable file test</description></metadata>
          {criteria}</definition>'''
    tests = ''.join(f'''<ind:textfilecontent54_test id="oval:org.alinksec:tst:{n}" version="1" check="all" check_existence="at_least_one_exists" comment="Native file observation">
       <ind:object object_ref="oval:org.alinksec:obj:1"/><ind:state state_ref="oval:org.alinksec:ste:{n}"/>
       </ind:textfilecontent54_test>''' for n in [1,2,3])
    family = 'windows' if platform.system()=='Windows' else 'unix'
    other_family = 'unix' if family=='windows' else 'windows'
    cpe_definitions = ''.join(f'''<definition id="oval:org.alinksec.cpe:def:{n}" version="1" class="inventory"><metadata><title>Fixture applicability {n}</title><description>Native OS family applicability</description></metadata><criteria><criterion test_ref="oval:org.alinksec.cpe:tst:{n}" comment="Native OS family"/></criteria></definition>''' for n in [1,2])
    cpe_tests = ''.join(f'''<ind:family_test id="oval:org.alinksec.cpe:tst:{n}" version="1" check="all" comment="Native OS family"><ind:object object_ref="oval:org.alinksec.cpe:obj:1"/><ind:state state_ref="oval:org.alinksec.cpe:ste:{n}"/></ind:family_test>''' for n in [1,2])
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
    <ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2"
      xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:cat="urn:oasis:names:tc:entity:xmlns:xml:catalog"
      xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
      xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
      xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
      xmlns:cpe="http://cpe.mitre.org/dictionary/2.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://scap.nist.gov/schema/scap/source/1.2 http://scap.nist.gov/schema/scap/1.3/scap-source-data-stream_1.3.xsd http://checklists.nist.gov/xccdf/1.2 http://scap.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5 https://github.com/OVALProject/Language/tree/5.11.2/schemas/oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#independent https://github.com/OVALProject/Language/tree/5.11.2/schemas/independent-definitions-schema.xsd http://cpe.mitre.org/dictionary/2.0 http://scap.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd"
      id="scap_org.alinksec_collection_native" schematron-version="1.3">
      <ds:data-stream id="scap_org.alinksec_datastream_native" use-case="CONFIGURATION" scap-version="1.3" timestamp="2026-10-21T00:00:00Z">
        <ds:dictionaries><ds:component-ref id="scap_org.alinksec_cref_dictionary" xlink:href="#scap_org.alinksec_comp_dictionary"><cat:catalog><cat:uri name="cpe.xml" uri="#scap_org.alinksec_cref_cpe"/></cat:catalog></ds:component-ref></ds:dictionaries>
        <ds:checklists><ds:component-ref id="scap_org.alinksec_cref_benchmark" xlink:href="#scap_org.alinksec_comp_benchmark">
          <cat:catalog><cat:uri name="checks.xml" uri="#scap_org.alinksec_cref_checks"/></cat:catalog>
        </ds:component-ref></ds:checklists>
        <ds:checks><ds:component-ref id="scap_org.alinksec_cref_checks" xlink:href="#scap_org.alinksec_comp_checks"/><ds:component-ref id="scap_org.alinksec_cref_cpe" xlink:href="#scap_org.alinksec_comp_cpe"/></ds:checks>
      </ds:data-stream>
      <ds:component id="scap_org.alinksec_comp_benchmark" timestamp="2026-10-21T00:00:00Z">
       <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="{BENCHMARK}" xml:lang="en">
        <status date="2026-10-21">draft</status><title>ALinkSec native interpreter fixture</title>
        <description>Observe a disposable file only; no remediation or scripts</description><platform idref="cpe:/a:alinksec:native_fixture:1"/><version>1</version>
        <Profile id="xccdf_org.alinksec_profile_base"><title>Base selection</title>
          {''.join(f'<select idref="{PREFIX}{name}" selected="true"/>' for name in ['external','failure','compound','unselected','platform'])}
        </Profile>
        <Profile id="{PROFILE}" extends="xccdf_org.alinksec_profile_base"><title>Inherited selection and external variable</title>
          <select idref="{PREFIX}unselected" selected="false"/>
          <set-value idref="xccdf_org.alinksec_value_expected">observed-native</set-value>
        </Profile>
        <Value id="xccdf_org.alinksec_value_expected" type="string"><title>Expected disposable file value</title><value>wrong-default</value></Value>
        {rules}
       </Benchmark>
      </ds:component>
      <ds:component id="scap_org.alinksec_comp_dictionary" timestamp="2026-10-21T00:00:00Z"><cpe:cpe-list>
        <cpe:cpe-item name="cpe:/a:alinksec:native_fixture:1"><cpe:title xml:lang="en">Native fixture applicability</cpe:title><cpe:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5" href="cpe.xml">oval:org.alinksec.cpe:def:1</cpe:check></cpe:cpe-item>
        <cpe:cpe-item name="cpe:/a:alinksec:absent_fixture:1"><cpe:title xml:lang="en">Deliberately inapplicable fixture</cpe:title><cpe:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5" href="cpe.xml">oval:org.alinksec.cpe:def:2</cpe:check></cpe:cpe-item>
      </cpe:cpe-list></ds:component>
      <ds:component id="scap_org.alinksec_comp_cpe" timestamp="2026-10-21T00:00:00Z">
       <oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
        <generator><oval:product_name>ALinkSec fixture</oval:product_name><oval:schema_version>5.11.2</oval:schema_version><oval:timestamp>2026-10-21T00:00:00Z</oval:timestamp></generator>
        <definitions>{cpe_definitions}</definitions><tests>{cpe_tests}</tests>
        <objects><ind:family_object id="oval:org.alinksec.cpe:obj:1" version="1"/></objects>
        <states><ind:family_state id="oval:org.alinksec.cpe:ste:1" version="1"><ind:family>{family}</ind:family></ind:family_state><ind:family_state id="oval:org.alinksec.cpe:ste:2" version="1"><ind:family>{other_family}</ind:family></ind:family_state></states>
       </oval_definitions>
      </ds:component>
      <ds:component id="scap_org.alinksec_comp_checks" timestamp="2026-10-21T00:00:00Z">
       <oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
          xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
          xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
        <generator><oval:product_name>ALinkSec fixture</oval:product_name><oval:schema_version>5.11.2</oval:schema_version><oval:timestamp>2026-10-21T00:00:00Z</oval:timestamp></generator>
        <definitions>{definitions}</definitions><tests>{tests}</tests>
        <objects><ind:textfilecontent54_object id="oval:org.alinksec:obj:1" version="1">
          <ind:filepath>{escape(str(observed))}</ind:filepath><ind:pattern operation="pattern match">^(.*)$</ind:pattern><ind:instance datatype="int">1</ind:instance>
        </ind:textfilecontent54_object></objects>
        <states>
          <ind:textfilecontent54_state id="oval:org.alinksec:ste:1" version="1"><ind:subexpression var_ref="oval:org.alinksec:var:1" var_check="all"/></ind:textfilecontent54_state>
          <ind:textfilecontent54_state id="oval:org.alinksec:ste:2" version="1"><ind:subexpression>deliberate-mismatch</ind:subexpression></ind:textfilecontent54_state>
          <ind:textfilecontent54_state id="oval:org.alinksec:ste:3" version="1"><ind:subexpression var_ref="oval:org.alinksec:var:2" var_check="all"/></ind:textfilecontent54_state>
        </states>
        <variables><external_variable id="oval:org.alinksec:var:1" version="1" datatype="string" comment="Profile expected value"/>
          <local_variable id="oval:org.alinksec:var:2" version="1" datatype="string" comment="Native concat function"><concat><literal_component datatype="string">observed-</literal_component><literal_component datatype="string">native</literal_component></concat></local_variable>
        </variables>
       </oval_definitions>
      </ds:component>
    </ds:data-stream-collection>'''
    manifest = dict(schemaVersion=1, code='ALINKSEC-SCAP-NATIVE', version='1', name='Native SCAP fixture',
        osType=2 if platform.system()=='Windows' else 1, osVersionPattern='.*',
        benchmarkFile='native-ds.xml', benchmarkId=BENCHMARK, profileId=PROFILE)
    archive = root/'content.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('alinksec-scap.json',json.dumps(manifest))
        z.writestr('native-ds.xml',xml)
    (root/'native-ds.xml').write_text(xml,encoding='utf-8')
    return archive

if __name__=='__main__':
    print(create(sys.argv[1]))
