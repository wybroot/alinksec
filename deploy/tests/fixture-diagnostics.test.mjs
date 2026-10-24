import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { diagnosticTail } from './fixture-diagnostics.mjs'

test('bounded diagnostic preserves failure and removes fixture credentials', () => {
  const root = mkdtempSync(join(tmpdir(), 'alinksec-diagnostics-'))
  try {
    const path = join(root, 'server.log')
    writeFileSync(path, 'old material\n'.repeat(30000) + 'native startup failed: ECONNREFUSED\nfixture-password ENROLL-abcd eyJabc.def.ghi\npassword=hidden\n-----BEGIN PRIVATE KEY-----\nsecret-body\n-----END PRIVATE KEY-----\n')
    const output = diagnosticTail(path, ['fixture-password'])
    assert.ok(Buffer.byteLength(output) < 257 * 1024)
    assert.match(output, /earlier output omitted/)
    assert.match(output, /native startup failed: ECONNREFUSED/)
    assert.doesNotMatch(output, /fixture-password|ENROLL-abcd|eyJabc|hidden|secret-body/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})
