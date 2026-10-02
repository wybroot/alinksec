import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { delimiter, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const scripts = fileURLToPath(new URL('../release/', import.meta.url))
const components = ['server', 'web', 'sqlite-maintenance']
const arches = ['amd64', 'arm64']
const repository = 'wangyanbiao/alinksec'
const hash = bytes => createHash('sha256').update(bytes).digest('hex')

test('native image records assemble a release with both architectures and verified attachments', t => {
  const root = mkdtempSync(join(tmpdir(), 'alinksec-release-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const cwd = join(root, 'source')
  const bin = join(root, 'bin')
  mkdirSync(cwd)
  mkdirSync(bin)
  writeFileSync(join(cwd, 'VERSION'), '0.0.2\n')
  writeFileSync(join(cwd, '.gitignore'), 'release/\n')
  const git = args => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
  git(['init', '-q'])
  git(['add', 'VERSION', '.gitignore'])
  git(['-c', 'user.name=Release fixture', '-c', 'user.email=fixture@example.test',
    '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Fixture'])
  const sha = git(['rev-parse', 'HEAD'])
  const state = { images: {}, configs: {}, indexes: {} }
  for (const component of components) {
    const manifests = []
    for (const arch of arches) {
      const digest = `sha256:${hash(`${component}/${arch}`)}`
      const labels = { 'org.opencontainers.image.version': 'v0.0.2', 'org.opencontainers.image.revision': sha }
      const ref = `${repository}@${digest}`
      state.images[`${repository}:${component}-v0.0.2-${arch}`] = [{
        Os: 'linux', Architecture: arch, Config: { Labels: labels }, RepoDigests: [ref],
      }]
      state.configs[ref] = { os: 'linux', architecture: arch, config: { Labels: labels } }
      manifests.push({ digest, platform: { os: 'linux', architecture: arch } })
    }
    const index = { schemaVersion: 2, manifests }
    const digest = `sha256:${hash(JSON.stringify(index))}`
    state.indexes[`${repository}:${component}-v0.0.2`] = { digest, ...index }
    state.indexes[`${repository}@${digest}`] = index
  }
  const stateFile = join(root, 'registry.json')
  writeFileSync(stateFile, JSON.stringify(state))
  const dockerFile = join(bin, 'docker')
  writeFileSync(dockerFile, `#!${process.execPath}
const fs = require('node:fs');
const state = JSON.parse(fs.readFileSync(process.env.ALINKSEC_TEST_REGISTRY, 'utf8'));
const args = process.argv.slice(2);
fs.appendFileSync(process.env.ALINKSEC_TEST_DOCKER_LOG, JSON.stringify(args) + '\\n');
let result;
if (args[0] === 'image' && args[1] === 'inspect') result = state.images[args[2]];
else if (args.slice(0, 3).join(' ') === 'buildx imagetools create') process.exit(0);
else if (args.slice(0, 3).join(' ') === 'buildx imagetools inspect') {
  if (args[3] === '--raw') result = state.indexes[args[4]];
  else if (args[5] === '{{json .Image}}') result = state.configs[args[3]];
  else if (args[5] === '{{json .Manifest}}') result = state.indexes[args[3]];
}
if (!result) throw new Error('Unexpected Docker call: ' + args.join(' '));
console.log(JSON.stringify(result));
`)
  chmodSync(dockerFile, 0o755)
  const env = { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}`,
    ALINKSEC_TEST_REGISTRY: stateFile, ALINKSEC_TEST_DOCKER_LOG: join(root, 'docker.log'), ALINKSEC_CI_RUN_ID: '123' }
  const run = (script, ...args) => execFileSync(process.execPath, [resolve(scripts, script), ...args],
    { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] })
  for (const arch of arches) run('images.mjs', 'record', arch)
  const armFile = join(cwd, 'release/images-arm64.json')
  const arm = JSON.parse(readFileSync(armFile, 'utf8'))
  writeFileSync(armFile, JSON.stringify({ ...arm, commit: 'b'.repeat(40) }))
  assert.throws(() => run('images.mjs', 'merge'), 'must reject another source commit')
  writeFileSync(armFile, JSON.stringify(arm))
  run('images.mjs', 'merge')
  const calls = readFileSync(env.ALINKSEC_TEST_DOCKER_LOG, 'utf8').trim().split('\n').map(JSON.parse)
  const creates = calls.filter(args => args[2] === 'create')
  assert.equal(creates.length, 3)
  for (const args of creates) {
    assert.equal(args.length, 7)
    assert.ok(args.slice(5).every(ref => /^wangyanbiao\/alinksec@sha256:[a-f0-9]{64}$/.test(ref)))
  }
  mkdirSync(join(cwd, 'release/bin'))
  for (const [arch, machine] of [['amd64', 62], ['arm64', 183]]) {
    const bytes = Buffer.alloc(64)
    bytes.set([127, 69, 76, 70, 2, 1])
    bytes.writeUInt16LE(machine, 18)
    writeFileSync(join(cwd, `release/bin/alinksec-agent-linux-${arch}`), bytes)
  }
  const windows = Buffer.alloc(256)
  windows.write('MZ')
  windows.writeUInt32LE(128, 60)
  windows.write('PE\0\0', 128)
  windows.writeUInt16LE(0x8664, 132)
  windows.writeUInt16LE(0x20b, 152)
  writeFileSync(join(cwd, 'release/bin/alinksec-agent-windows-amd64.exe'), windows)
  run('make-assets.mjs')
  const manifest = JSON.parse(readFileSync(join(cwd, 'release/release-manifest.json'), 'utf8'))
  assert.equal(manifest.commit, sha)
  assert.equal(manifest.ciRun, 123)
  assert.equal(manifest.assets.length, 4)
  assert.ok(manifest.assets.some(asset => asset.file === 'alinksec-agent-linux-arm64'))
  assert.equal(manifest.images.length, 3)
  assert.ok(manifest.images.every(image => image.platforms.length === 2))
  const checksums = readFileSync(join(cwd, 'release/SHA256SUMS'), 'utf8').trim().split('\n')
  assert.equal(checksums.length, 5)
  for (const line of checksums) {
    const [expected, file] = line.split('  ')
    assert.equal(hash(readFileSync(join(cwd, 'release', file))), expected)
  }
})
