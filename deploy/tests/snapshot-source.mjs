import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { copyFileSync, lstatSync, mkdirSync, readlinkSync, symlinkSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const target = resolve(process.argv[2])
assert.ok(target.startsWith(`${repo}/.tmp/`), 'Snapshot must use the temporary validation directory')
const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
  { cwd: repo, encoding: 'utf8' }).split('\0').filter(Boolean)
let count = 0
for (const file of files) {
  if (file.split('/').some(part => ['.git', '.tmp', 'target', 'node_modules', 'dist', 'tools'].includes(part))) continue
  const source = join(repo, file)
  const destination = join(target, file)
  const stat = lstatSync(source, { throwIfNoEntry: false })
  if (!stat || stat.isDirectory()) continue
  mkdirSync(dirname(destination), { recursive: true })
  if (stat.isSymbolicLink()) symlinkSync(readlinkSync(source), destination)
  else copyFileSync(source, destination)
  count++
}
console.log(`Fresh source snapshot: ${count} files; no tools, targets or dependencies`)
