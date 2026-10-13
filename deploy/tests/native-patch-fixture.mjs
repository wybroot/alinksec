import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

// Trusted disposable binary fixtures; no package is installed by this builder.
export function debFixture(name, version, architecture = 'all') {
  for (const value of [name, version, architecture]) if (!/^[a-zA-Z0-9:+_.~-]+$/.test(value)) throw new Error('Unsafe fixture field')
  const root = mkdtempSync(join(tmpdir(), 'alinksec-native-patch-'))
  try {
    const tree = join(root, 'package'); mkdirSync(join(tree, 'DEBIAN'), { recursive: true })
    writeFileSync(join(tree, 'DEBIAN/control'), `Package: ${name}\nVersion: ${version}\nArchitecture: ${architecture}\nMaintainer: CI <ci@example.test>\nDescription: disposable validation fixture\n`)
    const file = join(root, 'fixture.deb')
    execFileSync('/usr/bin/dpkg-deb', ['--build', '--root-owner-group', tree, file], { stdio: 'ignore', timeout: 15_000 })
    return readFileSync(file)
  } finally { rmSync(root, { recursive: true, force: true }) }
}
