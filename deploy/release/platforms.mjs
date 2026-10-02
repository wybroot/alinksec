import assert from 'node:assert/strict'

export const architectures = ['amd64', 'arm64']
export const components = ['server', 'web', 'sqlite-maintenance']
export const repository = 'wangyanbiao/alinksec'
export const agentTargets = [
  { file: 'alinksec-agent-linux-amd64', os: 'linux', arch: 'amd64', machine: 62 },
  { file: 'alinksec-agent-linux-arm64', os: 'linux', arch: 'arm64', machine: 183 },
  { file: 'alinksec-agent-windows-amd64.exe', os: 'windows', arch: 'amd64', machine: 0x8664 },
]

// Check the executable architecture, not just its filename or magic bytes.
export function validateAgent(bytes, target) {
  assert.ok(bytes.length >= 64, `${target.file}: truncated executable`)
  if (target.os === 'linux') {
    assert.ok(bytes.subarray(0, 4).equals(Buffer.from([127, 69, 76, 70])), `${target.file}: expected ELF`)
    assert.equal(bytes[4], 2, `${target.file}: expected ELF64`)
    assert.equal(bytes[5], 1, `${target.file}: expected little-endian ELF`)
    assert.equal(bytes.readUInt16LE(18), target.machine, `${target.file}: wrong architecture`)
  } else {
    assert.equal(bytes.toString('ascii', 0, 2), 'MZ', `${target.file}: expected PE`)
    const pe = bytes.readUInt32LE(60)
    assert.ok(pe >= 64 && pe + 26 <= bytes.length, `${target.file}: invalid PE offset`)
    assert.equal(bytes.toString('ascii', pe, pe + 4), 'PE\0\0', `${target.file}: invalid PE signature`)
    assert.equal(bytes.readUInt16LE(pe + 4), target.machine, `${target.file}: wrong architecture`)
    assert.equal(bytes.readUInt16LE(pe + 24), 0x20b, `${target.file}: expected PE32+`)
  }
}

export function validateImageConfig(config, arch, tag, sha) {
  assert.ok(architectures.includes(arch), `Unsupported architecture: ${arch}`)
  assert.equal(config.os, 'linux')
  assert.equal(config.architecture, arch)
  assert.equal(config.config?.Labels?.['org.opencontainers.image.revision'], sha)
  assert.equal(config.config?.Labels?.['org.opencontainers.image.version'], tag)
}

export function validateImageIndex(index, platforms) {
  assert.equal(index.schemaVersion, 2)
  assert.equal(index.manifests?.length, architectures.length, 'Image must contain exactly amd64 and arm64')
  assert.deepEqual(platforms.map(item => item.platform).sort(), architectures.map(arch => `linux/${arch}`))
  for (const expected of platforms) {
    const [os, architecture] = expected.platform.split('/')
    const matches = index.manifests.filter(item => item.platform?.os === os && item.platform?.architecture === architecture)
    assert.equal(matches.length, 1, `Missing or duplicate ${expected.platform}`)
    assert.equal(`${repository}@${matches[0].digest}`, expected.digest, `Untested digest for ${expected.platform}`)
  }
}
