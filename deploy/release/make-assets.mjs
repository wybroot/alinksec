import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { gzipSync } from 'node:zlib'
import { agentTargets, components, repository, validateAgent, validateImageIndex } from './platforms.mjs'

const version = readFileSync('VERSION', 'utf8').trim()
assert.match(version, /^\d+\.\d+\.\d+$/)
const tag = `v${version}`
const output = resolve('release')
mkdirSync(output, { recursive: true })
const sha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
assert.equal(execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], { encoding: 'utf8' }).trim(), '',
  'Release source must be clean')
const assets = [`alinksec-${tag}.tar.gz`, ...agentTargets.map(target => target.file)]
writeFileSync(resolve(output, assets[0]), gzipSync(execFileSync('git', ['archive', '--format=tar', `--prefix=alinksec-${tag}/`, 'HEAD'],
  { maxBuffer: 64 * 1024 * 1024 }), { level: 9 }))
for (const target of agentTargets) {
  const source = resolve(output, 'bin', target.file)
  validateAgent(readFileSync(source), target)
  copyFileSync(source, resolve(output, target.file))
}
const recorded = JSON.parse(readFileSync(resolve(output, 'images.json'), 'utf8'))
assert.equal(recorded.version, tag)
assert.equal(recorded.commit, sha)
const images = recorded.images
assert.deepEqual(images.map(image => image.component).sort(), [...components].sort())
for (const image of images) {
  assert.equal(image.image, `${repository}:${image.component}-${tag}`)
  assert.match(image.digest, /^wangyanbiao\/alinksec@sha256:[a-f0-9]{64}$/)
  const index = JSON.parse(execFileSync('docker', ['buildx', 'imagetools', 'inspect', '--raw', image.digest],
    { encoding: 'utf8', timeout: 120_000 }))
  validateImageIndex(index, image.platforms)
}
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
