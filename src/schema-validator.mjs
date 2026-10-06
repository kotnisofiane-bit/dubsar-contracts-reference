import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { canonicalJson } from './canonical-json.mjs'

export class SchemaRegistry {
  constructor(schemaDirectory) {
    this.documents = new Map()
    this.identifiers = new Map()
    const files = fs.readdirSync(schemaDirectory)
      .filter(name => name.endsWith('.schema.json'))
      .sort()
    for (const name of files) {
      const filePath = path.resolve(schemaDirectory, name)
      const schema = JSON.parse(fs.readFileSync(filePath, 'utf8'))
      const fileUrl = pathToFileURL(filePath).href
      const document = { schema, filePath, fileUrl, identifier: schema.$id ?? fileUrl }
      this.documents.set(name, document)
      this.identifiers.set(fileUrl, document)
      this.identifiers.set(document.identifier, document)
    }
  }

  schemaNames() {
    return [...this.documents.keys()]
  }

  resolveSchema(name) {
    const document = this.documents.get(name)
    if (document === undefined) throw new Error(`unknown schema: ${name}`)
    return document
  }

  validate(name, instance) {
    const document = this.resolveSchema(name)
    const errors = []
    validateNode(instance, document.schema, document, this, '$', errors, 0)
    return errors
  }

  assertValid(name, instance) {
    const errors = this.validate(name, instance)
    if (errors.length > 0) {
      throw new Error(`${name} rejected: ${errors.slice(0, 8).join('; ')}`)
    }
  }

  assertAllReferencesClosed() {
    const resolved = []
    for (const document of this.documents.values()) {
      walkSchema(document.schema, entry => {
        if (typeof entry.$ref !== 'string') return
        const target = resolveReference(entry.$ref, document, this)
        resolved.push({ source: path.basename(document.filePath), reference: entry.$ref, target: path.basename(target.document.filePath) })
      })
    }
    return resolved
  }
}

function validateNode(value, schema, document, registry, instancePath, errors, depth) {
  if (depth > 256) {
    errors.push(`${instancePath}: schema recursion limit exceeded`)
    return
  }
  if (schema === true) return
  if (schema === false) {
    errors.push(`${instancePath}: rejected by false schema`)
    return
  }
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) {
    errors.push(`${instancePath}: invalid schema node`)
    return
  }

  if (typeof schema.$ref === 'string') {
    const target = resolveReference(schema.$ref, document, registry)
    validateNode(value, target.schema, target.document, registry, instancePath, errors, depth + 1)
  }

  if (Array.isArray(schema.allOf)) {
    for (const branch of schema.allOf) validateNode(value, branch, document, registry, instancePath, errors, depth + 1)
  }
  if (Array.isArray(schema.anyOf)) {
    const matches = schema.anyOf.filter(branch => branchMatches(value, branch, document, registry, instancePath, depth)).length
    if (matches === 0) errors.push(`${instancePath}: must match at least one anyOf branch`)
  }
  if (Array.isArray(schema.oneOf)) {
    const matches = schema.oneOf.filter(branch => branchMatches(value, branch, document, registry, instancePath, depth)).length
    if (matches !== 1) errors.push(`${instancePath}: must match exactly one oneOf branch (matched ${matches})`)
  }
  if (schema.not !== undefined && branchMatches(value, schema.not, document, registry, instancePath, depth)) {
    errors.push(`${instancePath}: matches forbidden schema`)
  }

  if (schema.type !== undefined && !matchesType(value, schema.type)) {
    errors.push(`${instancePath}: expected type ${JSON.stringify(schema.type)}`)
    return
  }
  if (schema.const !== undefined && !deepEqual(value, schema.const)) {
    errors.push(`${instancePath}: expected constant ${JSON.stringify(schema.const)}`)
  }
  if (Array.isArray(schema.enum) && !schema.enum.some(entry => deepEqual(value, entry))) {
    errors.push(`${instancePath}: value is not in enum`)
  }

  if (typeof value === 'string') validateString(value, schema, instancePath, errors)
  if (typeof value === 'number') validateNumber(value, schema, instancePath, errors)
  if (Array.isArray(value)) validateArray(value, schema, document, registry, instancePath, errors, depth)
  if (isObject(value)) validateObject(value, schema, document, registry, instancePath, errors, depth)
}

function branchMatches(value, schema, document, registry, instancePath, depth) {
  const branchErrors = []
  validateNode(value, schema, document, registry, instancePath, branchErrors, depth + 1)
  return branchErrors.length === 0
}

function validateString(value, schema, instancePath, errors) {
  if (Number.isInteger(schema.minLength) && [...value].length < schema.minLength) errors.push(`${instancePath}: string shorter than minLength`)
  if (Number.isInteger(schema.maxLength) && [...value].length > schema.maxLength) errors.push(`${instancePath}: string longer than maxLength`)
  if (typeof schema.pattern === 'string' && !new RegExp(schema.pattern, 'u').test(value)) errors.push(`${instancePath}: string does not match pattern`)
  if (schema.format === 'date-time' && !isRfc3339DateTime(value)) errors.push(`${instancePath}: invalid RFC 3339 date-time`)
}

function validateNumber(value, schema, instancePath, errors) {
  if (schema.type === 'integer' && !Number.isSafeInteger(value)) errors.push(`${instancePath}: integer is not safe`)
  if (typeof schema.minimum === 'number' && value < schema.minimum) errors.push(`${instancePath}: number below minimum`)
  if (typeof schema.maximum === 'number' && value > schema.maximum) errors.push(`${instancePath}: number above maximum`)
}

function validateArray(value, schema, document, registry, instancePath, errors, depth) {
  if (Number.isInteger(schema.minItems) && value.length < schema.minItems) errors.push(`${instancePath}: array shorter than minItems`)
  if (Number.isInteger(schema.maxItems) && value.length > schema.maxItems) errors.push(`${instancePath}: array longer than maxItems`)
  if (schema.uniqueItems === true) {
    const seen = new Set()
    for (const entry of value) {
      const key = canonicalJson(entry)
      if (seen.has(key)) errors.push(`${instancePath}: array items must be unique`)
      seen.add(key)
    }
  }
  if (schema.items !== undefined) {
    value.forEach((entry, index) => validateNode(entry, schema.items, document, registry, `${instancePath}[${index}]`, errors, depth + 1))
  }
}

function validateObject(value, schema, document, registry, instancePath, errors, depth) {
  const keys = Object.keys(value)
  if (Number.isInteger(schema.minProperties) && keys.length < schema.minProperties) errors.push(`${instancePath}: object has too few properties`)
  if (Number.isInteger(schema.maxProperties) && keys.length > schema.maxProperties) errors.push(`${instancePath}: object has too many properties`)
  if (Array.isArray(schema.required)) {
    for (const key of schema.required) {
      if (!Object.hasOwn(value, key)) errors.push(`${instancePath}: missing required property ${key}`)
    }
  }
  if (schema.propertyNames !== undefined) {
    for (const key of keys) validateNode(key, schema.propertyNames, document, registry, `${instancePath}{property:${key}}`, errors, depth + 1)
  }
  const properties = isObject(schema.properties) ? schema.properties : {}
  for (const key of keys) {
    if (Object.hasOwn(properties, key)) {
      validateNode(value[key], properties[key], document, registry, `${instancePath}.${key}`, errors, depth + 1)
      continue
    }
    if (schema.additionalProperties === false) {
      errors.push(`${instancePath}: additional property ${key} is not allowed`)
    } else if (isObject(schema.additionalProperties) || typeof schema.additionalProperties === 'boolean') {
      validateNode(value[key], schema.additionalProperties, document, registry, `${instancePath}.${key}`, errors, depth + 1)
    }
  }
}

function resolveReference(reference, currentDocument, registry) {
  const hashIndex = reference.indexOf('#')
  const source = hashIndex === -1 ? reference : reference.slice(0, hashIndex)
  const fragment = hashIndex === -1 ? '' : reference.slice(hashIndex + 1)
  let document = currentDocument
  if (source.length > 0) {
    const identifier = new URL(source, currentDocument.identifier).href
    document = registry.identifiers.get(identifier)
    if (document === undefined) throw new Error(`unresolved schema reference: ${reference} from ${currentDocument.identifier}`)
  }
  let node = document.schema
  if (fragment.length > 0) {
    if (!fragment.startsWith('/')) throw new Error(`unsupported schema fragment: #${fragment}`)
    for (const rawPart of fragment.slice(1).split('/')) {
      const part = decodeURIComponent(rawPart).replaceAll('~1', '/').replaceAll('~0', '~')
      if (!isObject(node) || !Object.hasOwn(node, part)) throw new Error(`unresolved schema pointer: ${reference}`)
      node = node[part]
    }
  }
  return { schema: node, document }
}

function walkSchema(value, visit) {
  if (Array.isArray(value)) {
    for (const entry of value) walkSchema(entry, visit)
    return
  }
  if (!isObject(value)) return
  visit(value)
  for (const entry of Object.values(value)) walkSchema(entry, visit)
}

function matchesType(value, expected) {
  const types = Array.isArray(expected) ? expected : [expected]
  return types.some(type => {
    if (type === 'null') return value === null
    if (type === 'array') return Array.isArray(value)
    if (type === 'object') return isObject(value)
    if (type === 'integer') return typeof value === 'number' && Number.isSafeInteger(value)
    if (type === 'number') return typeof value === 'number' && Number.isFinite(value)
    return typeof value === type
  })
}

function isRfc3339DateTime(value) {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
    && Number.isFinite(Date.parse(value))
}

function deepEqual(left, right) {
  try {
    return canonicalJson(left) === canonicalJson(right)
  } catch {
    return false
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}
