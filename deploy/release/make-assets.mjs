import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { gzipSync } from 'node:zlib'

const version = readFileSync('VERSION', 'utf8').trim()
assert.match(version, /^\d+\.\d+\.\d+$/)
const tag = `v${version}`
const output = resolve('release')
mkdirSync(output, { recursive: true })
const sha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
assert.equal(execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], { encoding: 'utf8' }).trim(), '',
  'Release source must be clean')
const assets = [`alinksec-${tag}.tar.gz`, 'alinksec-agent-linux-amd64', 'alinksec-agent-windows-amd64.exe']
writeFileSync(resolve(output, assets[0]), gzipSync(execFileSync('git', ['archive', '--format=tar', `--prefix=alinksec-${tag}/`, 'HEAD'],
  { maxBuffer: 64 * 1024 * 1024 }), { level: 9 }))
for (const file of assets.slice(1)) {
  const source = resolve(output, 'bin', file)
  const header = readFileSync(source).subarray(0, 4)
  assert.ok(file.endsWith('.exe') ? header.subarray(0, 2).equals(Buffer.from('MZ')) : header.equals(Buffer.from([127, 69, 76, 70])),
    `${file}: unexpected executable format`)
  copyFileSync(source, resolve(output, file))
}
const images = ['server', 'web', 'sqlite-maintenance'].map(component => {
  const image = `wangyanbiao/alinksec:${component}-${tag}`
  const [details] = JSON.parse(execFileSync('docker', ['image', 'inspect', image], { encoding: 'utf8' }))
  assert.equal(details.Config.Labels['org.opencontainers.image.revision'], sha)
  assert.equal(details.Config.Labels['org.opencontainers.image.version'], tag)
  assert.equal(details.Os, 'linux')
  assert.equal(details.Architecture, 'amd64')
  const digest = details.RepoDigests?.find(value => value.startsWith('wangyanbiao/alinksec@sha256:'))
  assert.ok(digest, `${image}: missing pushed repository digest`)
  return { component, image, digest }
})
const manifest = {
  version: tag, commit: sha, ciRun: Number(process.env.ALINKSEC_CI_RUN_ID), images,
  assets: assets.map(file => ({ file, sha256: createHash('sha256').update(readFileSync(resolve(output, file))).digest('hex') })),
}
assert.ok(Number.isSafeInteger(manifest.ciRun) && manifest.ciRun > 0, 'Missing validated CI run')
writeFileSync(resolve(output, 'release-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`)
assets.push('release-manifest.json')
writeFileSync(resolve(output, 'SHA256SUMS'), assets.map(file =>
  `${createHash('sha256').update(readFileSync(resolve(output, file))).digest('hex')}  ${file}\n`).join(''))
console.log(`Release assets prepared for ${tag} (${sha})`)
