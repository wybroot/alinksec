import assert from 'node:assert/strict'
import test from 'node:test'
import { agentTargets, repository, validateAgent, validateImageConfig, validateImageIndex } from '../release/platforms.mjs'

const elf = machine => {
  const bytes = Buffer.alloc(64)
  bytes.set([127, 69, 76, 70, 2, 1])
  bytes.writeUInt16LE(machine, 18)
  return bytes
}

test('release rejects an amd64 binary mislabeled as arm64 and truncated executables', () => {
  for (const target of agentTargets.filter(target => target.os === 'linux')) {
    validateAgent(elf(target.machine), target)
    assert.throws(() => validateAgent(elf(target.machine === 62 ? 183 : 62), target), /wrong architecture/)
    assert.throws(() => validateAgent(Buffer.alloc(4), target), /truncated/)
    const elf32 = elf(target.machine)
    elf32[4] = 1
    assert.throws(() => validateAgent(elf32, target), /ELF64/)
  }
})

test('Windows asset requires an x64 PE executable', () => {
  const target = agentTargets.find(target => target.os === 'windows')
  const bytes = Buffer.alloc(256)
  bytes.write('MZ')
  bytes.writeUInt32LE(128, 60)
  bytes.write('PE\0\0', 128)
  bytes.writeUInt16LE(0x8664, 132)
  bytes.writeUInt16LE(0x20b, 152)
  validateAgent(bytes, target)
  bytes.writeUInt16LE(0xaa64, 132)
  assert.throws(() => validateAgent(bytes, target), /wrong architecture/)
  bytes.writeUInt32LE(0xffffffff, 60)
  assert.throws(() => validateAgent(bytes, target), /invalid PE offset/)
})

const sha = 'a'.repeat(40)
const tag = 'v0.0.2'
test('release image must match the native architecture, source commit and version', () => {
  const config = { os: 'linux', architecture: 'arm64', config: { Labels: {
    'org.opencontainers.image.revision': sha, 'org.opencontainers.image.version': tag,
  } } }
  validateImageConfig(config, 'arm64', tag, sha)
  assert.throws(() => validateImageConfig(config, 'amd64', tag, sha))
  assert.throws(() => validateImageConfig(config, 'arm64', tag, 'b'.repeat(40)))
  assert.throws(() => validateImageConfig(config, 'arm64', 'v0.0.1', sha))
})

test('multi-platform index must contain exactly the tested amd64 and arm64 digests', () => {
  const platforms = ['amd64', 'arm64'].map((arch, i) => ({
    platform: `linux/${arch}`, digest: `${repository}@sha256:${String(i).repeat(64)}`,
  }))
  const index = { schemaVersion: 2, manifests: platforms.map(item => ({
    digest: item.digest.split('@')[1], platform: { os: 'linux', architecture: item.platform.split('/')[1] },
  })) }
  validateImageIndex(index, platforms)
  for (const change of [
    value => value.manifests.pop(),
    value => { value.manifests[1] = value.manifests[0] },
    value => { value.manifests[1].digest = `sha256:${'f'.repeat(64)}` },
    value => { value.manifests[1].platform.os = 'windows' },
    value => { value.manifests[1].platform.architecture = 'arm' },
  ]) {
    const invalid = structuredClone(index)
    change(invalid)
    assert.throws(() => validateImageIndex(invalid, platforms))
  }
  assert.throws(() => validateImageIndex(index, platforms.slice(0, 1)))
})
