import test from 'node:test'
import assert from 'node:assert/strict'
import { fetchHosts, isolateHost } from '../src/api/index.js'

test('host isolation state is mapped independently from connectivity', async () => {
  const oldFetch = globalThis.fetch
  const oldStorage = globalThis.localStorage
  let requestPath
  globalThis.localStorage = { getItem: () => null }
  globalThis.fetch = async (path) => {
    requestPath = path
    return {
    ok: true,
    status: 200,
    json: async () => ({
      code: 0,
      data: { total: 102, list: [
        { agent_id: 'agent-a', hostname: 'host-a', status: 1, isolation_status: 2 },
        { agent_id: 'agent-b', hostname: 'host-b', status: 2, isolation_status: 4, isolation_error: 'ACK timeout' },
      ] },
    }),
    }
  }

  try {
    const result = await fetchHosts({ keyword: 'host', status: 'isolated', page: 2, size: 20 })
    const hosts = result.list
    assert.equal(requestPath, '/api/hosts?page=2&size=20&keyword=host&isolationStatus=2')
    assert.equal(result.total, 102)
    assert.equal(hosts[0].connectionStatus, 'online')
    assert.equal(hosts[0].status, 'isolated')
    assert.equal(hosts[1].connectionStatus, 'offline')
    assert.equal(hosts[1].status, 'isolate_failed')
    assert.equal(hosts[1].isolationError, 'ACK timeout')
  } finally {
    globalThis.fetch = oldFetch
    globalThis.localStorage = oldStorage
  }
})

test('isolate endpoint returns the durable transitional state', async () => {
  const oldFetch = globalThis.fetch
  const oldStorage = globalThis.localStorage
  let request
  globalThis.localStorage = { getItem: () => null }
  globalThis.fetch = async (path, options) => {
    request = { path, options }
    return {
      ok: true,
      status: 200,
      json: async () => ({ code: 0, data: { cmdId: 'cmd-1', isolationStatus: 'isolating' } }),
    }
  }

  try {
    const result = await isolateHost('agent-a', true)
    assert.equal(request.path, '/api/hosts/agent-a/isolate')
    assert.equal(request.options.method, 'POST')
    assert.equal(result.isolationStatus, 'isolating')
  } finally {
    globalThis.fetch = oldFetch
    globalThis.localStorage = oldStorage
  }
})
