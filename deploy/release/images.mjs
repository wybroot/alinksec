import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { architectures, components, repository, validateImageConfig, validateImageIndex } from './platforms.mjs'

const tag = `v${readFileSync('VERSION', 'utf8').trim()}`
const sha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const docker = args => execFileSync('docker', args, { encoding: 'utf8', timeout: 120_000 })
const inspect = (ref, field) => JSON.parse(docker(['buildx', 'imagetools', 'inspect', ref, '--format', `{{json .${field}}}`]))
const read = file => JSON.parse(readFileSync(file, 'utf8'))
const write = (file, value) => writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`)
const digestPattern = /^wangyanbiao\/alinksec@sha256:[a-f0-9]{64}$/
mkdirSync('release', { recursive: true })

if (process.argv[2] === 'record') {
  const arch = process.argv[3]
  assert.ok(architectures.includes(arch), 'Usage: images.mjs record amd64|arm64')
  const images = components.map(component => {
    const image = `${repository}:${component}-${tag}-${arch}`
    const [details] = JSON.parse(docker(['image', 'inspect', image]))
    validateImageConfig({ os: details.Os, architecture: details.Architecture, config: details.Config }, arch, tag, sha)
    const digest = details.RepoDigests?.find(value => digestPattern.test(value))
    assert.ok(digest, `${image}: missing pushed digest`)
    return { component, platform: `linux/${arch}`, digest }
  })
  write(`release/images-${arch}.json`, { version: tag, commit: sha, architecture: arch, images })
} else if (process.argv[2] === 'merge') {
  const records = architectures.map(arch => {
    const record = read(`release/images-${arch}.json`)
    assert.equal(record.version, tag)
    assert.equal(record.commit, sha)
    assert.equal(record.architecture, arch)
    assert.deepEqual(record.images.map(image => image.component).sort(), [...components].sort())
    for (const image of record.images) {
      assert.equal(image.platform, `linux/${arch}`)
      assert.match(image.digest, digestPattern)
      // Recheck the immutable registry object before making it a public release tag.
      validateImageConfig(inspect(image.digest, 'Image'), arch, tag, sha)
    }
    return record
  })
  const images = components.map(component => {
    const image = `${repository}:${component}-${tag}`
    const platforms = records.map(record => {
      const { platform, digest } = record.images.find(item => item.component === component)
      return { platform, digest }
    })
    docker(['buildx', 'imagetools', 'create', '--tag', image, ...platforms.map(item => item.digest)])
    const descriptor = inspect(image, 'Manifest')
    assert.match(descriptor.digest, /^sha256:[a-f0-9]{64}$/)
    const digest = `${repository}@${descriptor.digest}`
    const index = JSON.parse(docker(['buildx', 'imagetools', 'inspect', '--raw', digest]))
    validateImageIndex(index, platforms)
    return { component, image, digest, platforms }
  })
  write('release/images.json', { version: tag, commit: sha, images })
} else {
  throw new Error('Usage: images.mjs record amd64|arm64 OR images.mjs merge')
}
