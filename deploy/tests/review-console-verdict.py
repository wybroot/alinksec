#!/usr/bin/env python3
"""Reject incomplete evidence using original HTTP, SQL facts, audit rows and browser captures."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

parser = argparse.ArgumentParser()
parser.add_argument('root', type=Path)
parser.add_argument('source')
parser.add_argument('--allow-working-tree', action='store_true')
parser.add_argument('--backend-only', action='store_true')
args = parser.parse_args()
root = args.root


def read(name):
    path = root / name
    assert 0 < path.stat().st_size < 16 * 1024 * 1024, name
    return json.loads(path.read_text())


def digest(name):
    return hashlib.sha256((root / name).read_bytes()).hexdigest()


run, provenance, accepted = [read(name) for name in ['runner-result.json', 'binary-provenance.json', 'accepted.json']]
assert run['accepted'] and not run['oomKilled'] and run['exitCode'] == 0
assert not run['releaseOrDeployment'] and not run['remainingOwnedContainers'] and not run.get('cleanupFailure')
assert not any(row['oomKilled'] or row['running'] or row['exitCode'] != 0 for row in run['containerStates'])
assert not run['rawContainerLogCredentialLeakDetected'] and run['rawContainerLogCredentialValuesChecked'] >= 20
assert provenance['source'] == args.source and (provenance['worktreeClean'] or args.allow_working_tree)
assert not provenance['productionJarContainsAcceptanceControl'] and provenance['fixtureClasses']
assert all(re.fullmatch('[a-f0-9]{64}', value) for value in [provenance['productionJarSHA256'], *provenance['fixtureClasses'].values()])
assert accepted['accepted'] and accepted['actualHttp'] and accepted['syntheticDatabaseFixtures']
assert accepted['database'] == run['database'] and accepted['database'] in ['sqlite', 'postgres']
assert all(row['availableMiB'] >= 384 and row['fullPSI'] <= 10 for row in read('resource-samples.json'))
observations, cases = read('observations.json'), read('cases.json')
assert len(observations) == accepted['requests'] >= 450 and len(cases) == accepted['cases'] >= 35
names = {row['name']: row for row in observations}
assert len(names) == len(observations)
assert all(row in observations for row in cases.values())


def response(name, http=200, code=0):
    row = names[name]
    assert row['status'] == http and row['response']['code'] == code, name
    return row['response'].get('data')


response('password-rejected', 400, 10001)
response('failed-change-keeps-session')
for name in ['password-changed', 'user-created', 'user-promoted', 'user-disabled', 'user-reset', 'viewer-password-changed']:
    response(name)
for name in ['old-admin-session-denied', 'second-admin-session-denied', 'role-change-revokes-session', 'disable-revokes-session',
             'self-change-revokes-first-session', 'self-change-revokes-second-session']:
    response(name, 401, 40100)
for name in ['old-password-login-denied', 'disabled-login-denied', 'reset-old-password-denied', 'self-old-password-denied']:
    response(name, 200, 40101)
for name in ['viewer-user-create-denied', 'viewer-user-edit-denied', 'viewer-handle-denied']:
    response(name, 403, 40301)
for name in ['new-password-login', 'reset-new-password-login', 'self-new-password-login', 'fresh-self-session-readable']:
    response(name)
account = read('account-facts.json')
assert account['admin']['auth_version'] == 1 and account['admin']['status'] == 1
assert account['managed']['auth_version'] == 4 and account['managed']['status'] == 1 and account['managedRemainingSessions'] == 1
assert account['deniedAccountMutationsUnchanged'] and account['selfServiceCannotSelectAnotherUser']
for name, role, status, version in [('users-created', 'viewer', 1, 0), ('users-promoted', 'operator', 1, 1), ('users-disabled', 'operator', 0, 2), ('users-reset', 'viewer', 1, 3)]:
    row = next(row for row in response(name)['list'] if row['username'] == 'console-managed')
    assert (row['role'], row['status'], row['auth_version']) == (role, status, version)
    assert not any('password' in key.lower() for key in row)
first, second = response('alerts-page-one'), response('alerts-page-two')
assert first['total'] == second['total'] == 105 and len(first['list']) == 100 and len(second['list']) == 5
assert not ({row['id'] for row in first['list']} & {row['id'] for row in second['list']})
alert = read('alert-facts.json')
assert alert['targetId'] in {row['id'] for row in second['list']}
assert response('alerts-open')['total'] == response('alerts-critical')['total'] == 1
assert response('alerts-empty')['total'] == response('alerts-open-after-handle')['total'] == 0
response('alert-handled')
response('alert-duplicate-denied', 200, 30001)
response('alert-missing-denied', 200, 30001)
assert alert['firstTerminalState']['status'] == 2 and alert['firstTerminalState']['handle_remark'] == '标记已处理'
assert alert['duplicatePreservesTerminalState'] and alert['commandRowsBefore'] == alert['commandRowsAfter'] == []
assert not alert['actualSecurityActionsSupportedByThisMarkingOperation']
pagination = read('pagination-facts.json')
assert len(pagination['invalidQueries']) == 18 and pagination['auditLowPrivilegeResponse'] == 403
for endpoint in ['alerts', 'vulnerabilities', 'viruses', 'audit', 'software']:
    cap = 500 if endpoint == 'software' else 100
    facts = [row for row in pagination['endpoints'] if row['endpoint'] == endpoint]
    traversal = next(row for row in facts if 'traversedPages' in row)
    assert traversal['matchesIndependentSql'] and traversal['uniqueRows'] > cap and traversal['traversedPages'] > 1
    for role in ['admin', 'operator', 'viewer']:
        prefix = 'page-' + endpoint + '-' + role + '-'
        forbidden = endpoint == 'audit' and role != 'admin'
        for i, query in enumerate(pagination['invalidQueries']):
            row = names[prefix + 'invalid-' + str(i)]
            assert row['path'].endswith('?' + query) and row['role'] == role
            response(row['name'], 403 if forbidden else 400, 40301 if forbidden else 10001)
        if forbidden:
            response(prefix + 'normal', 403, 40301)
            continue
        fact = next(row for row in facts if row.get('role') == role)
        assert fact['independentSqlCount'] == traversal['uniqueRows'] and fact['cap'] == cap
        valid = [row for row in observations if row['name'].startswith(prefix) and 'invalid-' not in row['name']]
        assert len(valid) == 6
        for row in valid:
            data = response(row['name'])
            query = parse_qs(urlsplit(row['path']).query)
            page, size = int(query['page'][0]), min(int(query['size'][0]), cap)
            rows = data if endpoint == 'software' else data['list']
            assert len(rows) == max(0, min(size, traversal['uniqueRows'] - (page - 1) * size))
            if endpoint != 'software':
                assert data['total'] == traversal['uniqueRows']
audits, logs = read('audit-rows.json'), read('log-checks.json')
assert logs['applicationLogSHA256'] == digest('application-events.log') and logs['auditSHA256'] == digest('audit-rows.json')
assert logs['auditRows'] == len(audits) > 121 and logs['credentialValuesChecked'] >= 20 and not logs['credentialLeakDetected']
password_audits = [row for row in audits if row['method'] == 'password_changed' and row['path'] == '/api/auth/password']
assert len(password_audits) == 2 and all(row['body_digest'] is None for row in password_audits)
assert all(row['body_digest'] is None for row in audits)
summary = {'accepted': True, 'database': run['database'], 'source': args.source, 'actualHttpRequests': len(observations),
           'endpoints': 5, 'roles': 3, 'invalidQueriesPerEndpointRole': 18, 'originalObservationsVerified': True,
           'browserVerified': False, 'releaseOrDeployment': False}
if not args.backend_only:
    browser = read('browser/result.json')
    assert browser['passed'] and browser['scope'] in (['production-bundle', 'current-source-routed-preview'] if args.allow_working_tree else ['production-bundle'])
    assert not browser['backendBrowserOverlap'] and browser['casesSHA256'] == digest('cases.json') and not browser['errors']
    assert len(browser['checks']) == 13 and len(browser['screenshots']) == 7
    assert {'captured-old-password-denial-and-new-password-login', 'viewer-self-service-password-clears-session',
            'injected-marking-network-failure-is-visible-and-preserves-open-row', 'injected-network-failure-clears-data-and-retry-recovers',
            'captured-duplicate-rejection-is-visible-and-reloads-terminal-state'} <= set(browser['checks'])
    assert {row['method'] for row in browser['requests'] if row.get('injectedTransportFailure')} == {'GET', 'POST'}
    for row in browser['requests']:
        if row.get('injectedTransportFailure'):
            assert (row['method'] == 'GET' and row['path'] == '/api/alerts') or (row['method'] == 'POST' and re.fullmatch(r'/api/alerts/[0-9]+/handle', row['path']))
            continue
        original = cases[row['case']]
        assert row['status'] == original['status'] and row['method'] == original['method']
        canonical = json.dumps(original['response'], ensure_ascii=False, separators=(',', ':')).encode()
        assert row['responseSHA256'] == hashlib.sha256(canonical).hexdigest()
    for name, value in browser['screenshots'].items():
        assert re.fullmatch(r'[a-z-]+\.png', name) and value == digest('browser/' + name)
    summary.update(browserVerified=True, browserChecks=len(browser['checks']), browserScope=browser['scope'])
(root / 'verdict.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary))
