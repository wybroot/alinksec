#!/usr/bin/env python3
"""Recheck acceptance from the retained original observations, not summary flags."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


def read(path):
    path = Path(path)
    assert 0 < path.stat().st_size < 16 * 1024 * 1024, path
    return json.loads(path.read_text())


def verify_sessions(path, replicas):
    value = read(path)
    assert value['accepted'] and value['scope'] == 'actual_rest_and_jvm_restart' and value['replicas'] == replicas
    restart = value['restart']
    assert restart['beforePid'] > 0 and restart['afterPid'] > 0 and restart['beforePid'] != restart['afterPid']
    assert restart['signingKeyUnchanged'] and restart['signingKeyBeforeSHA256'] == restart['signingKeyAfterSHA256']
    assert re.fullmatch('[a-f0-9]{64}', restart['signingKeyBeforeSHA256'])
    cases = value['cases']
    assert set(cases) == {'logout', 'disabled', 'demoted', 'password', 'password_second_session'}
    assert len(set(cases.values())) == 5 and all(re.fullmatch('[a-f0-9]{64}', digest) for digest in cases.values())
    observations = value['observations']
    ports = {row['port'] for row in observations}
    assert len(ports) == replicas
    for stage in ['before_restart', 'after_actual_jvm_restart']:
        subset = [row for row in observations if row['stage'] == stage]
        for port in ports:
            for digest in cases.values():
                denied = [row for row in subset if row['port'] == port and row['tokenSHA256'] == digest]
                assert len(denied) == 2 and all(row['status'] == 401 for row in denied)
                assert {row['method'] for row in denied} == {'GET', 'PUT'}
                assert all(row['path'].startswith('/api/protect/rules') for row in denied)
            assert any(row['port'] == port and row['path'] == '/api/users' and row['status'] == 200 for row in subset)
    fresh = [row for row in observations if row['stage'] == 'fresh_sessions']
    for port in ports:
        assert any(row['port'] == port and row['method'] == 'PUT' and row['status'] == 403 for row in fresh)
        assert any(row['port'] == port and row['method'] == 'PUT' and row['status'] == 200 for row in fresh)
    return {'replicas': replicas, 'revokedSessions': 5, 'realJvmRestart': True, 'unchangedSigningKey': True,
            'observedRequests': len(observations)}


def p95(values):
    return sorted(values)[max(0, (95 * len(values) + 99) // 100 - 1)]


def verify_queue(path):
    selected = {'TestQueueAppendAfterInterruptedWritePreservesNewReports', 'TestQueueAppendDelimitsCompleteTailWhileAwaitingReceipt',
                'TestQueueTailSeparatorCannotExceedCapacity', 'TestQueuePeekFailureCompactionAndRestart',
                'TestQueueLargeBacklogAndMalformedOversizePreservesSource', 'TestOfflineQueuePrunesExpiredReportsBeforeReachingCapacity',
                'TestTerminalAckCannotOvertakeDurableResult', 'TestBusinessReportPersistsBeforeSendAndNeedsMatchingReceipt',
                'TestSenderRetainsSuccessfulSendsUntilDurableReceipt', 'TestQueueCompactionContentionDoesNotBlockHeartbeat'}
    records = [json.loads(line) for line in Path(path).read_text(encoding='utf-8-sig').splitlines()]
    passed = {row['Test'] for row in records if row.get('Action') == 'pass' and 'Test' in row}
    assert selected <= passed and not any(row.get('Action') in ['fail', 'skip'] for row in records)
    assert all(row.get('Package', '').endswith('/internal/comm') for row in records)
    return {'accepted': True, 'reliableGoQueueCases': len(selected), 'originalObservationsVerified': True}


def verify_runtime(root, sha, allow_working_tree=False, require_early_ack=False):
    assert not require_early_ack or not allow_working_tree
    root = Path(root)
    result = read(root / 'result.json')
    assert result['source'] == sha and result['passed'] and result['database'] in ['sqlite', 'postgres']
    assert result.get('worktreeClean', False) or allow_working_tree, 'CI acceptance requires committed, clean source'
    regressions = {}
    if not allow_working_tree:
        for name in ['ReviewDefectsIntegrationTest', 'AgentChannelSecurityIntegrationTest']:
            suite = ET.parse(root / ('regressions/TEST-com.alinksec.bootstrap.' + name + '.xml')).getroot()
            assert int(suite.attrib['tests']) > 0 and all(int(suite.attrib.get(key, 0)) == 0 for key in ['errors', 'failures', 'skipped'])
            cases = {case.attrib['name'] for case in suite.findall('testcase')}
            if name == 'ReviewDefectsIntegrationTest':
                assert int(suite.attrib['tests']) == 19
                assert {'failedReportAndDedupRollbackTogetherAndRetryExactlyOnce', 'matchingSqlFailureRollsBackAssetAndDedupBeforeSuccessfulReplay'} <= cases
            else:
                assert 'durableReceiptFollowsCommitAndLostReplyReplaysWithoutDuplicate' in cases
                if require_early_ack:
                    assert int(suite.attrib['tests']) == 20
                    assert 'earlyTerminalAckWaitsForDeliveryCommitAndRejectsUnsentOrForeignCommands' in cases
            regressions[name] = int(suite.attrib['tests'])
        if result['database'] == 'sqlite':
            regressions.update(verify_queue(root / 'regressions/go-queue.jsonl'))
    assert result['remainingOwnedContainers'] == 0 and not result['oomKilled'] and not result['releaseOrDeployment']
    assert result['containerExitStates'] and all(not row['Running'] and not row['OOMKilled'] for row in result['containerExitStates'])
    binaries = read(root / 'binary-provenance.json')
    assert binaries['productionJarContainsFaultControl'] is False and len(binaries['sha256']) == 3 and binaries['fixtureClasses']
    assert all(re.fullmatch('[a-f0-9]{64}', digest) for digest in [*binaries['sha256'].values(), *binaries['fixtureClasses'].values()])
    sessions = verify_sessions(root / 'sessions.json', 1)
    crashes = read(root / 'crash-replay.json')
    assert [case['phase'] for case in crashes] == ['precommit', 'postcommit']
    for case in crashes:
        phase, gate, seed = case['phase'], case['gate'], case['seed']
        raw = (root / (phase + '-report.pb')).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == seed['sha256'] and len(raw) == seed['bytes']
        assert seed == case['duplicateSeed'] and gate['reportId'] == seed['reportId'] and gate['agentId'] == seed['agentId'] and gate['source'] == seed['source']
        assert gate['phase'] == phase and gate['transactionActive'] == (phase == 'precommit')
        assert gate['businessRowsInside'] == gate['dedupRowsInside'] == 1
        assert case['kill']['exitCode'] == 137 and case['kill']['beforePid'] > 0 and not case['kill']['oomKilled']
        for name in ['externalBeforeCrash', 'afterActualJvmRestart']:
            assert case[name]['business'] == case[name]['dedup'] == int(phase == 'postcommit')
        for name in ['afterAgentRestartAndReplay', 'afterDuplicateReplay']:
            assert case[name]['business'] == case[name]['dedup'] == 1
    overload = read(root / 'overload.json')
    assert overload['accepted'] and overload['profile'] == {'producers': 2, 'durationSeconds': 30, 'samplesPerBatch': 257,
            'periodMillis': 100, 'loginAndBusinessP95Millis': 3000, 'loginBusinessCommandMaxMillis': 8000, 'heartbeatGapMaxMillis': 8000}
    start, end = overload['loadStartUnixMillis'], overload['loadEndUnixMillis']
    assert end - start >= 30000 and start + 15000 <= overload['recoveredAt'] <= end
    samples = [json.loads(line) for line in (root / 'metrics.jsonl').read_text().splitlines()]
    assert len(samples) >= 200
    for row in samples:
        assert 0 <= row['statistics']['records'] <= 4096 and 0 <= row['statistics']['bytes'] <= 8 * 1024 * 1024
    assert max(row['statistics']['bytes'] for row in samples if start <= row['at'] <= end) >= 7 * 1024 * 1024
    statistics = overload['finalStatistics']
    assert statistics['records'] == statistics['bytes'] == 0 and all(statistics[key] > 0 for key in ['dropped', 'rejected', 'failed'])
    downstream = [row for row in overload['downstream'] if row['at'] >= start]
    assert overload.get('downstreamErrors', []) == []
    assert any(row['mode'] == 'slow' for row in downstream)
    assert any(row['mode'] == 'healthy' and row['at'] >= overload['recoveredAt'] for row in downstream)
    assert all(0 < row['bytes'] <= 256 * 1024 and row['lines'] > 0 and re.fullmatch('[a-f0-9]{64}', row['sha256']) for row in downstream)
    events = [json.loads(line) for line in (root / 'load.jsonl').read_text().splitlines()]
    producers = [row for row in events if 'producer' in row]
    assert len(producers) == 2 and {row['producer'] for row in producers} == {0, 1}
    assert producers == overload['producers']
    assert all(row['elapsedMillis'] >= 30000 and row['batches'] >= 100 and row['samplesPerBatch'] == 257 and row['batchBytes'] > 256 * 1024 for row in producers)
    sent = {row['reportId']: row for row in events if row.get('kind') == 'business-sent'}
    receipts = {row['reportId']: row for row in events if row.get('kind') == 'business-receipt'}
    assert sent.keys() == receipts.keys() and len(sent) >= 4
    durations = [receipts[key]['at'] - row['at'] for key, row in sent.items()]
    assert durations == overload['businessMillis'] and all(value >= 0 for value in durations)
    expected = collections.Counter(row['agentId'] for row in sent.values())
    facts = overload['businessFacts']
    assert {row['reportId'] for row in facts} == sent.keys() and len(facts) == len(sent)
    assert all(row['dedup'] == 1 and row['business'] == expected[row['agentId']] for row in facts)
    for key in ['loginMillis', 'businessMillis']:
        values = overload[key]
        assert values and p95(values) <= 3000 and max(values) <= 8000
    assert len(overload['loginMillis']) >= 10 and len(overload['heartbeatGapsMillis']) >= 11
    assert max(overload['heartbeatGapsMillis']) <= 8000 and 0 <= overload['nativeCommandMillis'] <= 8000
    accepted = {'accepted': True, 'source': sha, 'sourceScope': 'committed' if result.get('worktreeClean', False) else 'local_working_tree', 'database': result['database'], 'sessions': sessions,
                'actualJvmCrashPhases': 2, 'sameBytesNativeAgentReplay': True, 'metricsProducerSeconds': 30,
                'loginP95Millis': p95(overload['loginMillis']), 'businessP95Millis': p95(durations),
                'nativeCommandMillis': overload['nativeCommandMillis'], 'businessReports': len(sent), 'originalObservationsVerified': True}
    accepted['regressions'] = regressions
    if require_early_ack:
        accepted['earlyAcknowledgementRegressionVerified'] = True
    (root / 'accepted.json').write_text(json.dumps(accepted, indent=2) + '\n')
    return accepted


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path')
    parser.add_argument('source', nargs='?')
    parser.add_argument('--sessions-only', action='store_true')
    parser.add_argument('--queue-only', action='store_true')
    parser.add_argument('--allow-working-tree', action='store_true')
    parser.add_argument('--require-early-ack', action='store_true')
    arguments = parser.parse_args()
    assert not (arguments.sessions_only and arguments.queue_only)
    assert not arguments.require_early_ack or not (arguments.sessions_only or arguments.queue_only)
    verdict = verify_queue(arguments.path) if arguments.queue_only else verify_sessions(arguments.path, 2) if arguments.sessions_only else verify_runtime(arguments.path, arguments.source, arguments.allow_working_tree, arguments.require_early_ack)
    print(json.dumps(verdict, indent=2))
