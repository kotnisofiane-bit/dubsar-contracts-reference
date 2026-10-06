import { createHash } from 'node:crypto'

export function canonicalJson(value) {
  return encode(value, '$')
}

export function canonicalBytes(value) {
  return Buffer.from(canonicalJson(value), 'utf8')
}

export function domainSeparatedHash(domain, value) {
  if (typeof domain !== 'string' || !/^[a-z0-9.-]{8,128}$/.test(domain)) {
    throw new TypeError('invalid canonical hash domain')
  }
  const hash = createHash('sha256')
  hash.update(domain, 'utf8')
  hash.update(Buffer.from([0]))
  hash.update(canonicalBytes(value))
  return `sha256:${hash.digest('hex')}`
}

function encode(value, path) {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new TypeError(`${path} must be a safe integer`)
    }
    return String(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry, index) => encode(entry, `${path}[${index}]`)).join(',')}]`
  }
  if (typeof value !== 'object' || value === undefined) {
    throw new TypeError(`${path} contains a non-JSON value`)
  }
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${path} must be a plain JSON object`)
  }
  const keys = Object.keys(value).sort()
  const pairs = keys.map(key => `${JSON.stringify(key)}:${encode(value[key], `${path}.${key}`)}`)
  return `{${pairs.join(',')}}`
}
