import { closeSync, fstatSync, openSync, readSync } from 'node:fs'

// Upload only a bounded log tail, never fixture certificates, DBs or configs.
export function diagnosticTail(path, secrets = [], limit = 256 * 1024) {
  const fd = openSync(path, 'r')
  try {
    const size = fstatSync(fd).size
    const bytes = Buffer.alloc(Math.min(size, limit))
    const count = readSync(fd, bytes, 0, bytes.length, Math.max(0, size - bytes.length))
    let text = bytes.subarray(0, count).toString('utf8')
    if (size > limit) text = '[earlier output omitted]\n' + text.slice(text.indexOf('\n') + 1)
    for (const secret of secrets.filter(Boolean).sort((a, b) => b.length - a.length)) text = text.replaceAll(secret, '[redacted]')
    return text.replace(/-----BEGIN [^-]+-----[\s\S]*?(-----END [^-]+-----|$)/g, '[redacted PEM]')
      .replace(/\b(?:ENROLL-[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g, '[redacted credential]')
      .replace(/((?:password|secret|token|authorization)\s*[=:]\s*)[^\s,;]+/gi, '$1[redacted]')
      .replace(/^[A-Za-z0-9+/]{64,}={0,2}$/gm, '[redacted encoded material]')
  } finally { closeSync(fd) }
}
