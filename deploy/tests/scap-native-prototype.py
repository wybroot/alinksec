#!/usr/bin/env python3
"""Exercise actual SCC semantics in a private runtime and disposable fixture."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as E

spec = importlib.util.spec_from_file_location('scap_fixture', Path(__file__).with_name('scap-fixture.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    (root/'reports').mkdir()
    source = Path(os.environ['ALINKSEC_SCAP_TEST_BIN']).resolve().parent
    runtime = root/'private-runtime'
    if runtime.exists():
        raise RuntimeError('Native fixture requires a fresh private directory')
    shutil.copytree(source, runtime, ignore=lambda path, names: ['Content'] if Path(path).name=='Resources' else [])
    (runtime/'Resources'/'Content').mkdir(exist_ok=True)
    tree = E.parse(runtime/'options.xml')
    options = tree.getroot()
    for key in ['contents','ovalContents','ocilContents']:
        element = options.find(key)
        if element is not None:
            element.clear()
    settings = dict(downloadExternalFiles='0', appCheckForUpdates='0', contentCheckForUpdates='0',
        appUpdateURL='',contentRepository='', ignoreCPEOVALResults='0',
        saveResultsForNotApplicableContent='1', answerOCILwithSCAP='0',
        validateContentOnInstall='1', validateContent='1', validateDigitalSignature='0',failOnXMLDSig='0',
        contentDevModeSkipValidation='0', reviewType='local', newInstall='0',filterSCAPContentPerFamily='0',
        sharedOptions='1', customPathLocal=str(root/'reports'), keepXCCDFXML='1', keepOVALXML='0',
        keepOCILXML='0', keepCPEXML='0',keepARFXML='0', saveDISACKL='0', saveDISACKLB='0',
        allSettingsHTMLReport='0', nonComplianceHTMLReport='0', enableScanSessionDB='0',
        enableSummaryViewer='0', maxOVALCollectedItemsPerXCCDFResult='0',maskPasswords='1',
        itemCreationThresholdEnabled='1',itemCreationThreshold='10000',externalCmdTimeout='15',timeout='180')
    for key, value in settings.items():
        element = options.find(key)
        if element is None:
            element = E.SubElement(options,key)
        element.text = value
    tree.write(runtime/'options.xml',encoding='UTF-8',xml_declaration=True)
    archive = fixture.create(root/'fixture')
    binary = runtime/('cscc.exe' if os.name=='nt' else 'cscc')
    evidence = {'kind':'native SCC execution; disposable file, no remediation', 'commands':[], 'outcomes':{}}
    prefix = ['sudo','-n'] if os.name != 'nt' and os.geteuid()!=0 and os.getenv('GITHUB_ACTIONS')=='true' else []
    try:
        for args in [['--installScap',str(archive),fixture.PROFILE], ['--doNotSaveChanges','--userDir',str(root/'reports')]]:
            result = subprocess.run([*prefix,str(binary),*args],cwd=runtime,capture_output=True,text=True,timeout=180)
            evidence['commands'].append({'args':args,'exit':result.returncode,'stdout':result.stdout[-16000:],'stderr':result.stderr[-16000:]})
            if result.returncode:
                raise RuntimeError('Native SCC command failed')
            if args[0]=='--installScap':
                installed=runtime/'Resources'/'Content'/'SCAP12_Content'/'native-ds.xml'
                evidence['sourceXmlSha256']=hashlib.sha256((root/'fixture'/'native-ds.xml').read_bytes()).hexdigest()
                evidence['installedXmlSha256']=hashlib.sha256(installed.read_bytes()).hexdigest() if installed.exists() else ''
                shutil.copyfile(runtime/'options.xml',root/'options-after-install.xml')
                if evidence['sourceXmlSha256']!=evidence['installedXmlSha256']:
                    raise RuntimeError('Native installed source differs from reviewed XML')
        if prefix:
            subprocess.run([*prefix,'chown','-R',f'{os.getuid()}:{os.getgid()}',str(root)],check=True,timeout=30)
        ns={'x':'http://checklists.nist.gov/xccdf/1.2'}
        for path in (root/'reports').rglob('*.xml'):
            document=E.parse(path).getroot()
            for result in document.findall('.//x:rule-result',ns):
                rule=result.attrib['idref']
                if rule.startswith(fixture.PREFIX):
                    if rule in evidence['outcomes']:
                        raise RuntimeError('Duplicate native rule result')
                    evidence['outcomes'][rule]=result.find('x:result',ns).text
        expected={fixture.PREFIX+name:value for name,value in dict(external='pass',failure='fail',compound='pass',unselected='notselected',platform='notapplicable').items()}
        if evidence['outcomes']!=expected:
            raise RuntimeError('Native Profile/OVAL outcomes differ: '+str(evidence['outcomes']))
        evidence['accepted']=True
    finally:
        if prefix:
            subprocess.run([*prefix,'chown','-R',f'{os.getuid()}:{os.getgid()}',str(root)],check=True,timeout=30)
        (root/'result.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(evidence))

if __name__=='__main__':
    main()
