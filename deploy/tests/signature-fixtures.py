"""Independent harmless producer for Windows native signature update checks.

Linux checks use actual Java publication artifacts instead. This never downloads
or constructs malware and is not a production publisher.
"""
import hashlib,json,pathlib,sys,zipfile

root=pathlib.Path(sys.argv[1]);root.mkdir(parents=True,exist_ok=True)
def digest(data):return hashlib.sha256(data).hexdigest()
def key(text):return digest(text.encode())
def document(version,hashes,rule,value):
    return {'manifest.json':json.dumps({'db_version':version,'hash_count':len(hashes),'rule_count':1},separators=(',',':')).encode(),
            'hashes.txt':''.join(f'{h} {name} {severity}\n' for h,(name,severity) in sorted(hashes.items())).encode(),
            'rules.json':json.dumps({'rules':[{'name':rule,'strings':[{'value':value}]}]},separators=(',',':')).encode()}
def identity(entries):return digest(''.join(digest(entries.get(n,b'')) for n in ['manifest.json','hashes.txt','rules.json']).encode('ascii'))
def archive(name,entries):
    with zipfile.ZipFile(root/name,'w',zipfile.ZIP_DEFLATED) as out:
        for entry,data in entries.items():out.writestr(entry,data)
    return digest((root/name).read_bytes())
base={key(f'harmless-delta-{i}'):(f'Fixture.{i}',3) for i in range(1000)}
target=dict(base);removed=key('harmless-delta-3');del target[removed]
target[key('harmless-delta-4')]=('Changed.Metadata',5);target[key('new-harmless-entry')]=('Added.Fixture',4)
a=document('delta-base',base,'Old.Rule','before-only');b=document('delta-target',target,'New.Rule','after-only')
metadata={'contract':1,'base_version':'delta-base','base_content_sha256':identity(a),'target_version':'delta-target','target_content_sha256':identity(b)}
patch={'delta.json':json.dumps(metadata,separators=(',',':')).encode(),'manifest.json':b['manifest.json'],'rules.json':b['rules.json'],
       'hashes.txt':''.join(f'{h} {name} {severity}\n' for h,(name,severity) in sorted(target.items()) if base.get(h)!=(name,severity)).encode(),
       'removed.txt':(removed+'\n').encode()}
release={'producer':'independent-python-fixture','base_version':'delta-base','version':'delta-target','base_content_sha256':identity(a),'content_sha256':identity(b),
         'base_sha256':archive('base.zip',a),'sha256':archive('target.zip',b),'delta_sha256':archive('delta.zip',patch)}
(root/'release.json').write_text(json.dumps(release,indent=2)+'\n')
assert (root/'delta.zip').stat().st_size < (root/'target.zip').stat().st_size*0.8
print('Generated harmless independent signature fixtures:',root)
