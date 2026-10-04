import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

test('server and Agent compile the same platform-specific command set', () => {
  const agent = readFileSync(new URL('../../agent/internal/baseline/commands.json', import.meta.url))
  const server = readFileSync(new URL('../../server/alinksec-service/src/main/resources/baseline/commands.json', import.meta.url))
  assert.deepEqual(server, agent)
  const commands = JSON.parse(agent)
  assert.equal(commands.linux.length, 26)
  assert.equal(commands.windows.length, 4)
  assert.equal(new Set([...commands.linux, ...commands.windows]).size, 30)
})

test('PostgreSQL and SQLite apply the same baseline migrations', () => {
  for (const migration of ['V004__baseline_packages.sql', 'V005__baseline_execution_evidence.sql']) {
    assert.deepEqual(readFileSync(new URL(`../migrations/${migration}`, import.meta.url)),
      readFileSync(new URL(`../../server/alinksec-bootstrap/src/main/resources/db/common/${migration}`, import.meta.url)))
  }
})
