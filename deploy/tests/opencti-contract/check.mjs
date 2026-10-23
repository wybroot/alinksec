import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve, basename } from 'node:path'
import { parse, print, Kind, buildASTSchema, validate, graphqlSync } from 'graphql'

const folder = resolve(process.argv[2] || '.tmp/opencti-contract')
const fixture = resolve(process.argv[3] || '.tmp/opencti-fixtures')
const manifest = JSON.parse(readFileSync(resolve(folder, 'upstream.json')))
const hash = value => createHash('sha256').update(value).digest('hex')
const types = new Map(), scalarNames = new Set(['Int', 'Float', 'String', 'Boolean', 'ID'])
for (const file of manifest.files) {
  const raw = readFileSync(resolve(folder, basename(file.path)))
  assert.equal(hash(raw), file.sha256)
  for (const definition of parse(raw.toString(), { noLocation: true }).definitions) {
    if (!definition.name) continue
    const name = definition.name.value, old = types.get(name)
    if (!old) types.set(name, structuredClone(definition))
    else if ([Kind.OBJECT_TYPE_DEFINITION, Kind.OBJECT_TYPE_EXTENSION].includes(definition.kind)) {
      assert([Kind.OBJECT_TYPE_DEFINITION, Kind.OBJECT_TYPE_EXTENSION].includes(old.kind))
      const fields = new Map(old.fields.map(field => [field.name.value, field]))
      for (const field of definition.fields) {
        if (fields.has(field.name.value)) assert.equal(print(field), print(fields.get(field.name.value)))
        fields.set(field.name.value, structuredClone(field))
      }
      old.fields = [...fields.values()]
    } else assert.equal(print(old), print(definition))
  }
}
const source = readFileSync(resolve('server/alinksec-service/src/main/java/com/alinksec/service/library/OpenCtiAdapter.java'), 'utf8')
const block = source.match(/public static final String QUERY="""\n([\s\S]*?)\n\s*""";/)
assert(block, 'production GraphQL query must be captured')
const query = block[1].split('\n').map(line => line.replace(/^ {12}/, '')).join('\n') + '\n'
const operation = parse(query), selected = new Map(), checked = []
const named = type => type.kind === Kind.NAMED_TYPE ? type.name.value : named(type.type)
function leaf(name) {
  if (scalarNames.has(name) || selected.has(name)) return
  const original = types.get(name); assert(original, `upstream type missing: ${name}`)
  assert([Kind.SCALAR_TYPE_DEFINITION, Kind.ENUM_TYPE_DEFINITION].includes(original.kind), `unexpected input type: ${name}`)
  const copy = structuredClone(original); copy.directives = []
  if (copy.values) copy.values.forEach(value => { value.directives = [] })
  selected.set(name, copy)
}
function visit(typeName, selections) {
  const original = types.get(typeName); assert(original?.fields, `upstream object missing: ${typeName}`)
  if (!selected.has(typeName)) selected.set(typeName, { ...structuredClone(original), kind: Kind.OBJECT_TYPE_DEFINITION, interfaces: [], directives: [], fields: [] })
  const object = selected.get(typeName)
  for (const selection of selections.selections) {
    assert.equal(selection.kind, Kind.FIELD)
    const actual = original.fields.find(field => field.name.value === selection.name.value)
    assert(actual, `production query field missing upstream: ${typeName}.${selection.name.value}`)
    const used = new Set((selection.arguments || []).map(argument => argument.name.value))
    for (const name of used) assert((actual.arguments || []).some(argument => argument.name.value === name), `unsupported argument ${name}`)
    const field = structuredClone(actual); field.directives = []
    // Preserve actual requested arguments and every required argument; prune unused optional modules.
    field.arguments = (field.arguments || []).filter(argument => used.has(argument.name.value) || argument.type.kind === Kind.NON_NULL_TYPE && !argument.defaultValue)
    field.arguments.forEach(argument => { argument.directives = []; leaf(named(argument.type)) })
    const previous = object.fields.find(item => item.name.value === field.name.value)
    if (previous) assert.equal(print(previous), print(field)); else object.fields.push(field)
    checked.push(`${typeName}.${field.name.value}`)
    if (selection.selectionSet) visit(named(field.type), selection.selectionSet); else leaf(named(field.type))
  }
}
visit('Query', operation.definitions[0].selectionSet)
const subset = { kind: Kind.DOCUMENT, definitions: [...selected.values()] }
const schema = buildASTSchema(subset)
assert.deepEqual(validate(schema, operation).map(error => error.message), [])
const indicator = JSON.parse(readFileSync(resolve(fixture, 'indicator.json'))).document
const principal = '11111111-1111-4111-8111-111111111111'
const response = graphqlSync({ schema, source: query, variableValues: { first: 200, after: null }, rootValue: {
  me: { id: principal }, about: { version: manifest.tag },
  indicators: ({ first, after, orderBy, orderMode }) => {
    assert.equal(first, 200); assert.equal(after, null); assert.equal(orderBy, 'created_at'); assert.equal(orderMode, 'asc')
    return { pageInfo: { hasNextPage: false, endCursor: 'cursor-1', globalCount: 1 }, edges: [{ cursor: 'cursor-1', node: indicator }] }
  }
} })
assert.equal(response.errors, undefined)
assert.equal(response.data.indicators.edges[0].node.pattern, indicator.pattern)
const negative = [query.replace('globalCount', 'inventedCount'), query.replace('orderBy: created_at', 'orderBy: invented_order'), query.replace('$after: ID', '$after: String')]
for (const invalid of negative) assert(validate(schema, parse(invalid)).length > 0)
mkdirSync(folder, { recursive: true })
writeFileSync(resolve(folder, 'query.graphql'), query)
writeFileSync(resolve(folder, 'queried-contract.graphql'), print(subset))
writeFileSync(resolve(folder, 'controlled-response.json'), JSON.stringify(response, null, 2))
writeFileSync(resolve(folder, 'result.json'), JSON.stringify({
  upstreamCommit: manifest.commit, upstreamTag: manifest.tag, graphqlVersion: '17.0.2', verifiedOfficialFiles: manifest.files.length,
  queriedFields: checked, querySha256: hash(query), selectedNodeSha256: hash(JSON.stringify(indicator)), negativeChecks: negative.length,
  validation: 'Actual production query validated against fields, argument types, nullability and enum values extracted from immutable official upstream SDL; controlled execution uses a database-captured indicator. This is a scoped schema contract check, not a live OpenCTI instance.'
}, null, 2))
console.log(JSON.stringify({ verifiedOfficialFiles: manifest.files.length, queriedFields: checked.length, negativeChecks: negative.length }))
