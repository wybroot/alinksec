"""Independent readers for actual controller downloads; never evaluate CSV cells."""
import csv,hashlib,io,json,re,sys
from pathlib import Path
root=Path(sys.argv[1]);observed={}
for database in sys.argv[2:] or ['sqlite','postgres']:
    assert database in {'sqlite','postgres'}
    fixture=json.loads((root/f'console-{database}.json').read_text())
    expected=fixture['details'];assert len(expected)==4
    ndjson=(root/f'logs-{database}.ndjson').read_bytes();csv_bytes=(root/f'logs-{database}.csv').read_bytes()
    assert hashlib.sha256(ndjson).hexdigest()==fixture['ndjsonSha256']
    assert hashlib.sha256(csv_bytes).hexdigest()==fixture['csvSha256']
    rows=[json.loads(line) for line in ndjson.decode('utf-8').splitlines()]
    assert len(rows)==4 and {r['id'] for r in rows}==set(expected)
    for row in rows:
        assert row==expected[row['id']]
        assert hashlib.sha256(row['content'].encode('utf-8')).hexdigest()==row['content_sha256']
    table=list(csv.DictReader(io.StringIO(csv_bytes.decode('utf-8-sig'),newline='')))
    assert len(table)==4 and {r['id'] for r in table}==set(expected)
    formulas=0
    for row in table:
        original=expected[row['id']]
        for key in ['agent_id','source','time_kind','content_sha256']:
            assert row[key]==str(original[key])
        assert row['received_at']==original['receivedAt'] and row['agent_time_ms']==str(original['log_ts'])
        assert json.loads(row['fields'])==original['fields']
        raw=original['content']
        dangerous=re.match(r'^[\s\ufeff]*[=+@-]',raw) is not None or (raw and ord(raw[0])<32)
        assert row['content']==("'"+raw if dangerous else raw)
        if dangerous:formulas+=1
    assert formulas==1
    observed[database]={'records':4,'csvRows':4,'neutralizedFormulaCells':formulas,'allRetainedContentDigestsVerified':True,'ndjsonSha256':fixture['ndjsonSha256'],'csvSha256':fixture['csvSha256']}
(root/'documents.json').write_text(json.dumps({'passed':True,'reader':'Python standard csv/json','databases':observed},indent=2)+'\n')
print(json.dumps({'passed':True,'databases':observed}))
