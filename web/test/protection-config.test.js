import test from 'node:test'
import assert from 'node:assert/strict'
import { fileProtectionPayload, loginProtectionPayload } from '../src/utils/protection.js'

test('file editor preserves platforms and limits, supports paths containing commas, and requires absolute paths', () => {
  const rule = { match: { platforms: ['linux'], max_file_bytes: 123 } }
  const result = fileProtectionPayload(rule, { enabled: true, restore: true, paths: '/etc/passwd\n /opt/a,b \n/etc/passwd' })
  assert.deepEqual(result.match, { ...rule.match, paths: ['/etc/passwd', '/opt/a,b'] })
  assert.deepEqual(result.actions, ['alert', 'restore'])
  for (const paths of ['', 'relative', '/a\0b', Array.from({length:65},(_,i)=>`/a${i}`).join('\n')]) assert.throws(() => fileProtectionPayload(rule,{paths}))
})

test('login editor sends bounded numeric values and preserves hidden platform settings', () => {
  const rule = { match: { platforms: ['linux'] } }
  const form = { enabled: true, block: true, threshold: 3, window: 60, cooldown: 20, duration: 600, ports: '22, 2222,22', trusted: '192.0.2.1\n198.51.100.0/24', users: 'backup,deploy', offHours: true, start: 22, end: 6, timezone: 'Asia/Shanghai' }
  const result = loginProtectionPayload(rule, form)
  assert.deepEqual(result.actions,['alert','block_ip'])
  assert.deepEqual(result.match.ssh_ports,[22,2222])
  assert.deepEqual(result.match.platforms,['linux'])
  assert.equal(result.match.allowed_start_hour,22)
  assert.deepEqual(result.match.trusted_ips,['192.0.2.1','198.51.100.0/24'])
  for (const invalid of [{ports:''},{ports:'22;443'},{ports:'65536'},{threshold:1},{duration:3601},{timezone:''},{window:null}]) assert.throws(()=>loginProtectionPayload(rule,{...form,...invalid}))
  assert.deepEqual(loginProtectionPayload(rule,{...form,block:false}).actions,['alert'])
})

test('Windows login editor uses an explicit independent contract and port scope', async () => {
  const { windowsLoginProtectionPayload, windowsLoginStateLabel, windowsLoginIssueLabel } = await import('../src/utils/protection.js')
  const rule = { match: { windows_contract: 1, platforms: ['windows'] } }
  const form = { enabled: true, block: true, types: [3, 10], threshold: 5, window: 300, cooldown: 300, duration: 600, ports: '3389,445', trusted: '192.0.2.1', users: 'LAB\\backup', offHours: true, start: 8, end: 20, timezone: 'UTC' }
  const body = windowsLoginProtectionPayload(rule, form)
  assert.deepEqual(body.match.windows_ports, [3389, 445])
  assert.deepEqual(body.match.windows_logon_types, [3, 10])
  assert.equal(body.match.windows_contract, 1)
  assert.equal(body.match.ssh_ports, undefined)
  for (const bad of [{ types: [] }, { types: [2] }, { ports: '0' }, { ports: '3389;445' }]) assert.throws(() => windowsLoginProtectionPayload(rule, { ...form, ...bad }))
  assert.throws(() => windowsLoginProtectionPayload({ match: { platforms: ['linux'] } }, form))
  assert.equal(windowsLoginStateLabel('unsupported'), 'Agent 不支持')
  assert.match(windowsLoginIssueLabel('event_buffer_full'), /回执/)
})
