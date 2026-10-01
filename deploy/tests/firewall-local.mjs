import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import net from 'node:net'
import { resolve } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { promisify } from 'node:util'

assert.equal(process.env.ALINKSEC_SMOKE_ALLOW_FIXTURES, 'true')
const exec = promisify(execFile)
const image = process.env.ALINKSEC_SMOKE_AGENT_IMAGE || 'alinksec-agent-validation'
const repo = resolve(new URL('../..', import.meta.url).pathname)
let container, established
const controller = new AbortController()
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => controller.abort(new Error(signal)))
async function command(args) {
  return (await exec('docker', args, { encoding: 'utf8', timeout: 20_000, signal: controller.signal })).stdout.trim()
}
async function inside(...args) { return command(['exec', container, ...args]) }
let address, gateway
async function connect(port, retain = false) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host: address, port, localAddress: gateway })
    let completed = false
    const finish = allowed => {
      if (completed) return
      completed = true
      if (allowed && retain) established = socket
      else socket.destroy()
      resolve(allowed)
    }
    socket.once('connect', () => finish(true))
    socket.once('error', () => finish(false))
    socket.setTimeout(750, () => finish(false))
  })
}
async function apply(management, agent, remove = false) {
  return command(['exec', '-e', 'EXTERNAL_INTERFACE=eth0', '-e', `MANAGEMENT_CIDR=${management}`,
    '-e', `AGENT_CIDR=${agent}`, container, 'bash', '/validation/firewall.sh', ...(remove ? ['remove'] : [])])
}
try {
  assert.equal(await command(['ps', '-q']), '', 'Run firewall validation after stopping other scenarios')
  container = await command(['run', '-d', '--init', '--name', `alinksec-firewall-${process.pid}`,
    '--memory=64m', '--memory-swap=96m', '--cpus=1', '--pids-limit=64', '--cap-add=NET_ADMIN',
    '--mount', `type=bind,src=${repo}/deploy/firewall/alinksec-docker-user.sh,dst=/validation/firewall.sh,readonly`,
    '--entrypoint', '/bin/sh', image, '-c', 'exec sleep infinity'])
  const state = JSON.parse(await command(['inspect', container]))[0].NetworkSettings.Networks.bridge
  address = state.IPAddress
  gateway = state.Gateway
  await inside('iptables', '-N', 'DOCKER-USER')
  await inside('iptables', '-A', 'INPUT', '-j', 'DOCKER-USER')
  for (const port of [8081, 8443, 9443, 4444]) {
    await inside('iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', 'eth0', '-p', 'tcp', '--dport', String(port),
      '-j', 'DNAT', '--to-destination', `${address}:12345`)
  }
  await command(['exec', '-d', container, 'sh', '-c', 'exec nc -k -l -p 12345 >/dev/null'])
  await delay(200)
  for (const port of [8081, 8443, 9443, 4444]) assert.equal(await connect(port), true, `baseline ${port}`)
  await apply(`${gateway}/32`, '10.20.0.0/16')
  assert.equal(await connect(8443), true, 'management HTTPS')
  assert.equal(await connect(8081), true, 'management redirect')
  assert.equal(await connect(9443), false, 'management network must not gain Agent access')
  assert.equal(await connect(4444), true, 'unrelated port')
  console.log('ok - management source filtering uses original destination ports after actual DNAT')
  await apply('10.10.0.0/24', `${gateway}/32`)
  assert.equal(await connect(8443), true, 'Agent HTTPS downloads')
  assert.equal(await connect(9443, true), true, 'Agent gRPC')
  assert.equal(await connect(8081), false, 'Agent network cannot access management redirect')
  console.log('ok - Agent source filtering allows HTTPS/gRPC and rejects management-only port')
  await apply('10.10.0.0/24', '10.20.0.0/16')
  for (const port of [8081, 8443, 9443]) assert.equal(await connect(port), false, `unauthorized source ${port}`)
  assert.equal(await connect(4444), true, 'unrelated container traffic')
  established.write('established-fixture')
  await delay(100)
  const saved = await inside('iptables-save', '-c')
  const accepted = saved.split('\n').find(line => line.includes('-A ALINKSEC-INGRESS')
    && line.includes('--ctstate') && line.includes('-j ACCEPT'))
  assert.ok(Number(accepted.match(/^\[(\d+):/)[1]) > 0, 'Existing connection was not preserved')
  established.destroy()
  console.log('ok - unauthorized source is denied while established and unrelated traffic survive')
  await apply('10.10.0.0/24', '10.20.0.0/16')
  assert.equal((await inside('iptables', '-S', 'DOCKER-USER')).split('\n')
    .filter(line => line.includes('-j ALINKSEC-INGRESS')).length, 1)
  await apply('', '', true)
  await apply('', '', true)
  for (const port of [8081, 8443, 9443]) assert.equal(await connect(port), true, `removed rules ${port}`)
  console.log('ok - production firewall script installs idempotently and removes cleanly')
} finally {
  established?.destroy()
  if (container) await exec('docker', ['rm', '-f', container], { timeout: 30_000 })
}
