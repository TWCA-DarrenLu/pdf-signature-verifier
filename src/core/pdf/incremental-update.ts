import { decompressFlate } from './xref-parser'

/**
 * Change detection between a signed revision and the final document.
 *
 * A signature only covers the bytes of its own revision. Incremental updates
 * appended later can change what the reader sees (incremental saving / shadow
 * attacks). This module rebuilds both revisions from their cross-reference
 * data — classic tables, xref streams (with PNG predictors), hybrids and
 * object streams — and compares object by object.
 *
 * Model: everything reachable from the Catalog (except /DSS, /Metadata and
 * /StructTreeRoot, which are never rendered) can affect what the reader sees.
 * In that graph,
 *   - an unchanged object may only reference objects that existed before
 *     (a previously dangling reference must not be "filled in"),
 *   - a changed object must match one of the permitted change rules, and
 *   - a new object is only reachable through a changed object whose rule
 *     validated that reference.
 *
 * Permitted changes by policy (DocMDP):
 *   'ltv'         — DSS / VRI / XMP / Info; new document timestamp fields (P1)
 *   'signing'     — + new or newly signed signature fields, form fill-in (P2, default)
 *   'annotations' — + new annotations (P3)
 * A new or newly signed signature field is accepted only when its /V is a
 * signature dictionary added later whose ByteRange covers a later revision —
 * i.e. the change is itself signed. Its appearance is part of that signature.
 *
 * Anything that cannot be parsed is reported, never skipped (fail closed).
 */
export type ChangePolicy = 'ltv' | 'signing' | 'annotations'

export interface ChangeAnalysis {
  /** Any non-whitespace bytes follow the revision. */
  hasChanges: boolean
  /** Both revisions could be reconstructed and compared. */
  analysable: boolean
  /** Changes not permitted by the policy (empty = all permitted). */
  violations: string[]
}

export interface ChangeAnalyzer {
  changesSince(revisionEnd: number, policy: ChangePolicy): Promise<ChangeAnalysis>
}

type XrefEntry = { type: 0 } | { type: 1; offset: number } | { type: 2; stream: number; index: number }

interface Revision {
  entries: Map<number, XrefEntry>
  root: number | null
  encrypt: string | null
}

interface PdfObject {
  /** Value text (dictionary of a stream, or the whole value). */
  value: string
  /** Raw stream bytes, when the object is a stream. */
  stream?: Uint8Array
}

/** Catalog keys an update may change (AcroForm contents are checked separately). */
const ROOT_KEYS_ALLOWED = new Set(['DSS', 'Extensions', 'Metadata', 'AcroForm'])
const ROOT_KEYS_NOT_RENDERED = new Set(['DSS', 'Metadata', 'StructTreeRoot'])
const ACROFORM_KEYS_ALLOWED = new Set(['Fields', 'SigFlags', 'DR'])
const SIGNING_FIELD_KEYS = new Set(['V', 'AP', 'AS', 'MK', 'F', 'Lock', 'SV', 'DA'])
const FILL_FIELD_KEYS = new Set(['V', 'AP', 'AS'])
const FILLABLE_FIELD_TYPES = new Set(['Tx', 'Ch', 'Btn'])
const BACK_REFERENCE_KEYS = new Set(['Parent', 'P'])
const GROWABLE_ARRAY_KEYS = new Set(['Annots', 'Fields'])

export function createChangeAnalyzer(data: Uint8Array): ChangeAnalyzer {
  const reader = new PdfReader(data)
  let finalRevision: Promise<Revision | null> | null = null
  return {
    async changesSince(revisionEnd: number, policy: ChangePolicy): Promise<ChangeAnalysis> {
      if (!hasNonWhitespace(data, revisionEnd)) return { hasChanges: false, analysable: true, violations: [] }
      // Appended bytes must form proper revisions: viewers that repair files
      // may pick up objects that no cross-reference section declares.
      if (reader.text.lastIndexOf('startxref') < revisionEnd) {
        return notAnalysable('data appended without a cross-reference section')
      }
      const lastEof = reader.text.lastIndexOf('%%EOF')
      if (lastEof === -1 || hasNonWhitespace(data, lastEof + 5)) {
        return notAnalysable('data after the final %%EOF')
      }
      try {
        finalRevision ??= reader.readRevision(data.length)
        const [signed, final] = await Promise.all([reader.readRevision(revisionEnd), finalRevision])
        if (!signed || !final) return notAnalysable('cross-reference data could not be read')
        return await new RevisionComparison(reader, signed, final, policy, revisionEnd).run()
      } catch (error) {
        return notAnalysable(error instanceof Error ? error.message : 'analysis error')
      }
    },
  }
}

function notAnalysable(reason: string): ChangeAnalysis {
  return { hasChanges: true, analysable: false, violations: [reason] }
}

// ─── Comparison ──────────────────────────────────────────────────

class RevisionComparison {
  private readonly changed = new Set<number>()
  private readonly added = new Set<number>()
  private readonly deleted = new Set<number>()
  /** Accepted changes whose subtree is part of a permitted change. */
  private readonly boundary = new Set<number>()
  private readonly violations: string[] = []

  constructor(
    private readonly reader: PdfReader,
    private readonly signed: Revision,
    private readonly final: Revision,
    private readonly policy: ChangePolicy,
    private readonly revisionEnd: number
  ) {}

  async run(): Promise<ChangeAnalysis> {
    const { signed, final } = this
    if (signed.root === null || final.root === null) return notAnalysable('no /Root')
    if (final.root !== signed.root) this.violations.push(`trailer /Root changed (${signed.root} → ${final.root})`)
    if (final.encrypt !== signed.encrypt) this.violations.push('encryption dictionary changed')

    const unreadable = await this.classify()
    if (unreadable !== null) return notAnalysable(`object ${unreadable} could not be read`)
    if (!this.changed.size && !this.added.size && !this.deleted.size && !this.violations.length) {
      return { hasChanges: true, analysable: true, violations: [] }
    }

    await this.findBoundary()
    const { reached, referrers } = await this.walk(final.root)

    for (const num of this.deleted) {
      if (referrers.has(num)) this.violations.push(`object ${num} deleted but still referenced`)
    }
    for (const num of reached) {
      const refs = referrers.get(num) ?? []
      if (this.added.has(num)) {
        // Only a changed (validated) or new object may point at a new object —
        // even a permitted one: a previously dangling reference must not be filled.
        if (refs.some((r) => !this.added.has(r.from) && !this.changed.has(r.from))) {
          this.violations.push(`new object ${num} fills a reference of an unchanged object`)
        }
        continue
      }
      if (this.boundary.has(num)) continue
      if (this.changed.has(num)) {
        const why = await this.changeProblem(num, refs.map((r) => r.key))
        if (why) this.violations.push(`object ${num}: ${why}`)
      }
    }
    return { hasChanges: true, analysable: true, violations: this.violations }
  }

  /** Returns the number of an unreadable object, or null. */
  private async classify(): Promise<number | null> {
    const { signed, final } = this
    for (const num of new Set([...signed.entries.keys(), ...final.entries.keys()])) {
      const before = signed.entries.get(num)
      const after = final.entries.get(num)
      const inUseBefore = !!before && before.type !== 0
      const inUseAfter = !!after && after.type !== 0
      if (inUseBefore && !inUseAfter) this.deleted.add(num)
      else if (!inUseBefore && inUseAfter) this.added.add(num)
      else if (inUseBefore && inUseAfter) {
        // Same byte offset inside the signed part = same bytes. Anything else
        // (including members of object streams) is compared by content.
        if (before!.type === 1 && after!.type === 1 && before!.offset === after!.offset) continue
        const [a, b] = await Promise.all([this.reader.loadObject(signed, num), this.reader.loadObject(final, num)])
        if (!a || !b) return num
        if (!sameObject(a, b)) this.changed.add(num)
      }
    }
    return null
  }

  private load(rev: Revision, num: number): Promise<PdfObject | null> {
    return this.reader.loadObject(rev, num)
  }

  private async dict(rev: Revision, num: number | null): Promise<Map<string, string> | null> {
    if (num === null) return null
    return parseTopLevelDict((await this.load(rev, num))?.value ?? '')
  }

  /** Permitted new signature fields / annotations and permitted field updates. */
  private async findBoundary(): Promise<void> {
    for (const num of this.added) {
      const dict = await this.dict(this.final, num)
      if (!dict) continue
      if (await this.isNewSignatureField(dict)) this.boundary.add(num)
      else if (this.policy === 'annotations' && isPlainAnnotation(dict)) this.boundary.add(num)
    }
    for (const num of this.changed) {
      const [old, now] = await Promise.all([this.dict(this.signed, num), this.dict(this.final, num)])
      if (!old || !now) continue
      if ((await this.isFieldBeingSigned(old, now)) || (this.policy !== 'ltv' && (await this.isFieldBeingFilled(old, now)))) {
        this.boundary.add(num)
      }
    }
  }

  /** A signature dictionary added later whose ByteRange covers a later revision. */
  private async isLaterSignature(num: number | null): Promise<boolean> {
    if (num === null || !this.added.has(num)) return false
    const dict = await this.dict(this.final, num)
    const type = nameValue(dict?.get('Type'))
    if (type !== 'DocTimeStamp' && (type !== 'Sig' || this.policy === 'ltv')) return false
    const range = numbersIn(dict?.get('ByteRange') ?? '')
    return range.length === 4 && range[0] === 0 && range[2] + range[3] > this.revisionEnd
  }

  /** The field dictionary of a field or widget (via /Parent), in a revision. */
  private async fieldOf(rev: Revision, dict: Map<string, string>): Promise<Map<string, string>> {
    if (dict.has('FT')) return dict
    return (await this.dict(rev, refNumber(dict.get('Parent')))) ?? dict
  }

  private async isNewSignatureField(dict: Map<string, string>): Promise<boolean> {
    if (dict.has('A') || dict.has('AA')) return false
    const field = await this.fieldOf(this.final, dict)
    if (nameValue(field.get('FT')) !== 'Sig') return false
    return this.isLaterSignature(refNumber(field.get('V')))
  }

  /** An existing, unsigned signature field (or its widget) receiving a later signature. */
  private async isFieldBeingSigned(old: Map<string, string>, now: Map<string, string>): Promise<boolean> {
    const oldField = await this.fieldOf(this.signed, old)
    if (nameValue(oldField.get('FT')) !== 'Sig' || oldField.has('V')) return false
    if (!diffKeys(old, now).every((k) => SIGNING_FIELD_KEYS.has(k))) return false
    const newField = await this.fieldOf(this.final, now)
    return this.isLaterSignature(refNumber(newField.get('V')))
  }

  /** Form fill-in: value / appearance of an existing text, choice or button field. */
  private async isFieldBeingFilled(old: Map<string, string>, now: Map<string, string>): Promise<boolean> {
    const field = await this.fieldOf(this.signed, old)
    if (!FILLABLE_FIELD_TYPES.has(nameValue(field.get('FT')) ?? '')) return false
    return diffKeys(old, now).every((k) => FILL_FIELD_KEYS.has(k))
  }

  /** Breadth-first walk of the rendered graph of the final revision. */
  private async walk(root: number): Promise<{
    reached: Set<number>
    referrers: Map<number, Array<{ from: number; key: string }>>
  }> {
    const reached = new Set<number>()
    const referrers = new Map<number, Array<{ from: number; key: string }>>()
    const queue: Array<{ num: number; key: string }> = [{ num: root, key: '' }]
    while (queue.length) {
      const { num, key: contextKey } = queue.shift()!
      if (reached.has(num)) continue
      reached.add(num)
      if (this.boundary.has(num)) continue
      const obj = await this.load(this.final, num)
      if (!obj) {
        if (this.final.entries.get(num)?.type) this.violations.push(`object ${num} unreadable`)
        continue
      }
      const dict = parseTopLevelDict(obj.value)
      // Elements of an array are reached under the array's own key.
      const entries: Array<[string, string]> = dict ? [...dict.entries()] : [[contextKey, obj.value]]
      for (const [key, value] of entries) {
        if (BACK_REFERENCE_KEYS.has(key)) continue
        if (num === root && ROOT_KEYS_NOT_RENDERED.has(key)) continue
        for (const ref of refsIn(value)) {
          const list = referrers.get(ref) ?? []
          list.push({ from: num, key })
          referrers.set(ref, list)
          queue.push({ num: ref, key })
        }
      }
    }
    return { reached, referrers }
  }

  private async changeProblem(num: number, contexts: string[]): Promise<string | null> {
    const [before, after] = await Promise.all([this.load(this.signed, num), this.load(this.final, num)])
    if (!before || !after) return 'unreadable'
    if (before.stream || after.stream) return 'stream content changed'

    if (isArray(before.value) && isArray(after.value)) {
      if (!contexts.length || !contexts.every((k) => GROWABLE_ARRAY_KEYS.has(k))) return 'array changed'
      return this.growthProblem(refsIn(before.value), refsIn(after.value))
    }
    const old = parseTopLevelDict(before.value)
    const now = parseTopLevelDict(after.value)
    if (!old || !now) return 'value changed'
    const changedKeys = diffKeys(old, now)

    if (num === this.final.root) {
      const bad = changedKeys.filter((k) => !ROOT_KEYS_ALLOWED.has(k))
      if (bad.length) return `catalog keys changed: ${bad.map((k) => '/' + k).join(' ')}`
      if (!changedKeys.includes('AcroForm')) return null
      const oldForm = (await this.resolveDict(this.signed, old.get('AcroForm'))) ?? new Map()
      const newForm = await this.resolveDict(this.final, now.get('AcroForm'))
      if (!newForm) return 'AcroForm not readable'
      return this.acroFormProblem(oldForm, newForm)
    }
    if (contexts.includes('AcroForm')) return this.acroFormProblem(old, now)
    if (contexts.length && contexts.every((k) => k === 'DR')) return additiveProblem(old, now)
    if (nameValue(old.get('Type')) === 'Page' && nameValue(now.get('Type')) === 'Page') {
      const bad = changedKeys.filter((k) => k !== 'Annots')
      if (bad.length) return `page keys changed: ${bad.map((k) => '/' + k).join(' ')}`
      return this.arrayKeyProblem(old.get('Annots'), now.get('Annots'))
    }
    return `object changed (${describe(after)})`
  }

  private async acroFormProblem(old: Map<string, string>, now: Map<string, string>): Promise<string | null> {
    const changedKeys = diffKeys(old, now)
    const bad = changedKeys.filter((k) => !ACROFORM_KEYS_ALLOWED.has(k))
    if (bad.length) return `AcroForm keys changed: ${bad.map((k) => '/' + k).join(' ')}`
    if (changedKeys.includes('DR')) {
      const oldDr = parseTopLevelDict(old.get('DR') ?? '<<>>')
      const newDr = parseTopLevelDict(now.get('DR') ?? '')
      // An indirect /DR object is checked on its own (context 'DR').
      if (oldDr && newDr) {
        const why = additiveProblem(oldDr, newDr)
        if (why) return `/DR ${why}`
      } else if (refNumber(old.get('DR')) !== refNumber(now.get('DR'))) {
        return '/DR replaced'
      }
    }
    return this.arrayKeyProblem(old.get('Fields'), now.get('Fields'))
  }

  /** /Annots or /Fields given inline or by reference, before vs after. */
  private async arrayKeyProblem(before: string | undefined, after: string | undefined): Promise<string | null> {
    const a = await this.resolveArray(this.signed, before)
    const b = await this.resolveArray(this.final, after)
    if (!a || !b) return 'array not readable'
    return this.growthProblem(a, b)
  }

  private growthProblem(before: number[], after: number[]): string | null {
    const removed = before.filter((r) => !after.includes(r))
    if (removed.length) return `entries removed: ${removed.join(', ')}`
    const notPermitted = after.filter((r) => !before.includes(r) && !this.boundary.has(r))
    return notPermitted.length ? `entries added that are not permitted: ${notPermitted.join(', ')}` : null
  }

  private async resolveArray(rev: Revision, value: string | undefined): Promise<number[] | null> {
    if (value === undefined) return []
    if (isArray(value)) return refsIn(value)
    const ref = refNumber(value)
    if (ref === null) return null
    const obj = await this.load(rev, ref)
    return obj && isArray(obj.value) ? refsIn(obj.value) : null
  }

  private async resolveDict(rev: Revision, value: string | undefined): Promise<Map<string, string> | null> {
    if (value === undefined) return null
    const inline = parseTopLevelDict(value)
    if (inline) return inline
    return this.dict(rev, refNumber(value))
  }
}

/** A new annotation with no actions (P3). Widgets belong to form fields and are not covered. */
function isPlainAnnotation(dict: Map<string, string>): boolean {
  if (dict.has('A') || dict.has('AA') || dict.has('FT')) return false
  const subtype = nameValue(dict.get('Subtype'))
  const type = nameValue(dict.get('Type'))
  return !!subtype && subtype !== 'Widget' && dict.has('Rect') && (type === null || type === 'Annot')
}

/** Resource dictionaries may gain entries; existing entries must stay identical. */
function additiveProblem(old: Map<string, string>, now: Map<string, string>): string | null {
  for (const [key, value] of old) {
    const next = now.get(key)
    if (next === undefined) return `entry /${key} removed`
    const oldSub = parseTopLevelDict(value)
    const newSub = parseTopLevelDict(next)
    if (oldSub && newSub) {
      for (const [k, v] of oldSub) {
        if (normalize(newSub.get(k) ?? '') !== normalize(v)) return `entry /${key}/${k} changed`
      }
    } else if (normalize(next) !== normalize(value)) {
      return `entry /${key} changed`
    }
  }
  return null
}

// ─── Reader ──────────────────────────────────────────────────────

class PdfReader {
  readonly text: string
  private objStmCache = new Map<string, Promise<Array<{ num: number; text: string }> | null>>()

  constructor(readonly data: Uint8Array) {
    this.text = new TextDecoder('latin1').decode(data)
  }

  /** Cross-reference data of the revision ending at `end` (exclusive). */
  async readRevision(end: number): Promise<Revision | null> {
    const head = this.text.slice(0, end)
    const sx = head.lastIndexOf('startxref')
    if (sx === -1) return null
    let offset: number | null = Number(/startxref\s+(\d+)/.exec(head.slice(sx))?.[1])
    if (!Number.isFinite(offset)) return null

    const rev: Revision = { entries: new Map(), root: null, encrypt: null }
    const visited = new Set<number>()
    while (offset !== null && !visited.has(offset)) {
      if (offset < 0 || offset >= end) return null
      visited.add(offset)
      const section = await this.readXrefSection(offset, end)
      if (!section) return null
      for (const [num, entry] of section.entries) if (!rev.entries.has(num)) rev.entries.set(num, entry)
      rev.root ??= refNumber(section.trailer.get('Root'))
      rev.encrypt ??= section.trailer.get('Encrypt')?.trim() ?? null
      const xrefStm = Number(section.trailer.get('XRefStm'))
      if (Number.isFinite(xrefStm) && xrefStm > 0 && !visited.has(xrefStm)) {
        visited.add(xrefStm)
        const hybrid = await this.readXrefSection(xrefStm, end)
        if (!hybrid) return null
        for (const [num, entry] of hybrid.entries) if (!rev.entries.has(num)) rev.entries.set(num, entry)
      }
      const prev = Number(section.trailer.get('Prev'))
      offset = section.trailer.has('Prev') && Number.isFinite(prev) ? prev : null
    }
    return rev
  }

  private async readXrefSection(
    offset: number,
    end: number
  ): Promise<{ entries: Map<number, XrefEntry>; trailer: Map<string, string> } | null> {
    const i = skipWs(this.text, offset)
    if (this.text.startsWith('xref', i)) return this.readClassicXref(i + 4, end)
    const obj = this.parseIndirectAt(offset)
    if (!obj?.stream) return null
    const dict = parseTopLevelDict(obj.value)
    if (!dict || nameValue(dict.get('Type')) !== 'XRef') return null
    const data = await decodeStream(dict, obj.stream)
    if (!data) return null
    const w = numbersIn(dict.get('W') ?? '')
    if (w.length !== 3) return null
    const size = Number(dict.get('Size'))
    const index = dict.has('Index') ? numbersIn(dict.get('Index')!) : [0, size]
    const entries = new Map<number, XrefEntry>()
    const width = w[0] + w[1] + w[2]
    let pos = 0
    for (let p = 0; p + 1 < index.length; p += 2) {
      for (let k = 0; k < index[p + 1]; k++) {
        if (pos + width > data.length) return null
        const type = w[0] ? readInt(data, pos, w[0]) : 1
        const f2 = readInt(data, pos + w[0], w[1])
        const f3 = readInt(data, pos + w[0] + w[1], w[2])
        pos += width
        const num = index[p] + k
        // Readers disagree on duplicate entries within one section: refuse them.
        if (entries.has(num)) return null
        // Unknown entry types are references to the null object (ISO 32000 7.5.8.3).
        if (type === 1) entries.set(num, { type: 1, offset: f2 })
        else if (type === 2) entries.set(num, { type: 2, stream: f2, index: f3 })
        else entries.set(num, { type: 0 })
      }
    }
    return { entries, trailer: dict }
  }

  private readClassicXref(start: number, end: number): { entries: Map<number, XrefEntry>; trailer: Map<string, string> } | null {
    const entries = new Map<number, XrefEntry>()
    let i = start
    for (;;) {
      i = skipWs(this.text, i)
      if (i >= end) return null
      if (this.text.startsWith('trailer', i)) break
      const header = /^(\d+)\s+(\d+)/.exec(this.text.slice(i, i + 40))
      if (!header) return null
      i += header[0].length
      const first = Number(header[1])
      const count = Number(header[2])
      for (let k = 0; k < count; k++) {
        i = skipWs(this.text, i)
        const row = /^(\d{10})\s(\d{5})\s([nf])/.exec(this.text.slice(i, i + 20))
        if (!row) return null
        i += row[0].length
        // Readers disagree on duplicate entries within one section: refuse them.
        if (entries.has(first + k)) return null
        entries.set(first + k, row[3] === 'n' && Number(row[1]) > 0 ? { type: 1, offset: Number(row[1]) } : { type: 0 })
      }
    }
    i = skipWs(this.text, i + 'trailer'.length)
    const value = readValue(this.text, i)
    const trailer = value ? parseTopLevelDict(value.text) : null
    return trailer ? { entries, trailer } : null
  }

  /** Indirect object at a byte offset (tolerates comments and a missing endobj). */
  parseIndirectAt(offset: number, expected?: number): PdfObject | null {
    let i = skipWs(this.text, offset)
    const num = /^\d+/.exec(this.text.slice(i, i + 12))
    if (!num) return null
    if (expected !== undefined && Number(num[0]) !== expected) return null
    i = skipWs(this.text, i + num[0].length)
    const gen = /^\d+/.exec(this.text.slice(i, i + 12))
    if (!gen) return null
    i = skipWs(this.text, i + gen[0].length)
    if (!this.text.startsWith('obj', i)) return null
    i = skipWs(this.text, i + 3)
    const value = readValue(this.text, i)
    if (!value) return null
    i = skipWs(this.text, value.end)
    if (!this.text.startsWith('stream', i)) {
      return this.objectEndsAt(i) ? { value: value.text } : null
    }
    let dataStart = i + 6
    if (this.text[dataStart] === '\r' && this.text[dataStart + 1] === '\n') dataStart += 2
    else if (this.text[dataStart] === '\n' || this.text[dataStart] === '\r') dataStart += 1
    const dict = parseTopLevelDict(value.text)
    const lengthText = dict?.get('Length') ?? ''
    const length = Number(lengthText)
    let dataEnd = Number.isInteger(length) && length >= 0 ? dataStart + length : -1
    if (dataEnd < dataStart || !this.text.startsWith('endstream', skipEol(this.text, dataEnd))) {
      const es = this.text.indexOf('endstream', dataStart)
      if (es === -1) return null
      dataEnd = es
      while (dataEnd > dataStart && (this.text[dataEnd - 1] === '\n' || this.text[dataEnd - 1] === '\r')) dataEnd--
    }
    return { value: value.text, stream: this.data.subarray(dataStart, dataEnd) }
  }

  /** What may follow an object's value: endobj, or (tolerated) the next object / xref / trailer / EOF. */
  private objectEndsAt(i: number): boolean {
    if (i >= this.text.length) return true
    const rest = this.text.slice(i, i + 32)
    return (
      rest.startsWith('endobj') ||
      /^\d+\s+\d+\s+obj\b/.test(rest) ||
      rest.startsWith('xref') ||
      rest.startsWith('trailer') ||
      rest.startsWith('startxref')
    )
  }

  async loadObject(rev: Revision, num: number): Promise<PdfObject | null> {
    const entry = rev.entries.get(num)
    if (!entry || entry.type === 0) return null
    if (entry.type === 1) return this.parseIndirectAt(entry.offset, num)
    const members = await this.objectStream(rev, entry.stream)
    const member = members?.[entry.index]
    // The cross-reference index is authoritative; the member must be the requested object.
    return member && member.num === num ? { value: member.text } : null
  }

  private objectStream(rev: Revision, streamNum: number): Promise<Array<{ num: number; text: string }> | null> {
    const entry = rev.entries.get(streamNum)
    if (!entry || entry.type !== 1) return Promise.resolve(null)
    const key = `${streamNum}@${entry.offset}`
    let cached = this.objStmCache.get(key)
    if (!cached) {
      cached = (async () => {
        const obj = this.parseIndirectAt(entry.offset, streamNum)
        const dict = obj?.stream ? parseTopLevelDict(obj.value) : null
        if (!obj?.stream || !dict || nameValue(dict.get('Type')) !== 'ObjStm') return null
        const data = await decodeStream(dict, obj.stream)
        if (!data) return null
        const text = new TextDecoder('latin1').decode(data)
        const n = Number(dict.get('N'))
        const first = Number(dict.get('First'))
        const header = numbersIn(text.slice(0, first))
        if (!Number.isInteger(n) || header.length < n * 2) return null
        const members: Array<{ num: number; text: string }> = []
        for (let k = 0; k < n; k++) {
          const v = readValue(text, skipWs(text, first + header[k * 2 + 1]))
          if (!v) return null
          members.push({ num: header[k * 2], text: v.text })
        }
        return members
      })()
      this.objStmCache.set(key, cached)
    }
    return cached
  }
}

async function decodeStream(dict: Map<string, string>, raw: Uint8Array): Promise<Uint8Array | null> {
  const filter = (dict.get('Filter') ?? '').replace(/[[\]\s]/g, '')
  if (filter === '') return raw
  if (filter !== '/FlateDecode') return null
  const inflated = await decompressFlate(raw)
  if (!inflated) return null
  const parms = parseTopLevelDict(dict.get('DecodeParms') ?? '')
  const predictor = Number(parms?.get('Predictor') ?? 1)
  if (predictor <= 1) return inflated
  if (predictor < 10) return null
  return undoPngPredictor(inflated, Number(parms?.get('Columns') ?? 1))
}

function undoPngPredictor(data: Uint8Array, columns: number): Uint8Array | null {
  const rowLength = columns + 1
  if (data.length % rowLength !== 0) return null
  const rows = data.length / rowLength
  const out = new Uint8Array(rows * columns)
  const prev = new Uint8Array(columns)
  for (let r = 0; r < rows; r++) {
    const filter = data[r * rowLength]
    for (let c = 0; c < columns; c++) {
      const x = data[r * rowLength + 1 + c]
      const left = c > 0 ? out[r * columns + c - 1] : 0
      const up = prev[c]
      const upLeft = c > 0 ? prev[c - 1] : 0
      let v: number
      switch (filter) {
        case 0: v = x; break
        case 1: v = x + left; break
        case 2: v = x + up; break
        case 3: v = x + ((left + up) >> 1); break
        case 4: {
          const p = left + up - upLeft
          const pa = Math.abs(p - left)
          const pb = Math.abs(p - up)
          const pc = Math.abs(p - upLeft)
          v = x + (pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft)
          break
        }
        default: return null
      }
      out[r * columns + c] = v & 0xff
    }
    prev.set(out.subarray(r * columns, (r + 1) * columns))
  }
  return out
}

// ─── Lexing helpers ──────────────────────────────────────────────

function isWs(ch: string): boolean {
  return ch === ' ' || ch === '\n' || ch === '\r' || ch === '\t' || ch === '\f' || ch === '\0'
}

/** Skip whitespace and comments. */
function skipWs(s: string, i: number): number {
  while (i < s.length) {
    if (isWs(s[i])) i++
    else if (s[i] === '%') {
      while (i < s.length && s[i] !== '\n' && s[i] !== '\r') i++
    } else break
  }
  return i
}

function skipEol(s: string, i: number): number {
  while (s[i] === '\r' || s[i] === '\n') i++
  return i
}

const DELIMITERS = /[\s\0/<>[\]()%{}]/

function readToken(s: string, i: number): { text: string; end: number } | null {
  const start = i
  while (i < s.length && !DELIMITERS.test(s[i])) i++
  return i > start ? { text: s.slice(start, i), end: i } : null
}

/**
 * One PDF value starting at i: dict, array, string, hex string, name, number,
 * indirect reference (comments allowed between its tokens) or keyword.
 */
function readValue(s: string, i: number): { text: string; end: number } | null {
  const start = i
  if (s.startsWith('<<', i)) {
    i += 2
    for (;;) {
      i = skipWs(s, i)
      if (i >= s.length) return null
      if (s.startsWith('>>', i)) return { text: s.slice(start, i + 2), end: i + 2 }
      const v = readValue(s, i)
      if (!v) return null
      i = v.end
    }
  }
  if (s[i] === '[') {
    i++
    for (;;) {
      i = skipWs(s, i)
      if (i >= s.length) return null
      if (s[i] === ']') return { text: s.slice(start, i + 1), end: i + 1 }
      const v = readValue(s, i)
      if (!v) return null
      i = v.end
    }
  }
  if (s[i] === '(') {
    let depth = 0
    for (; i < s.length; i++) {
      if (s[i] === '\\') {
        i++
        continue
      }
      if (s[i] === '(') depth++
      else if (s[i] === ')' && --depth === 0) return { text: s.slice(start, i + 1), end: i + 1 }
    }
    return null
  }
  if (s[i] === '<') {
    const close = s.indexOf('>', i)
    return close === -1 ? null : { text: s.slice(start, close + 1), end: close + 1 }
  }
  if (s[i] === '/') {
    const name = readToken(s, i + 1)
    const end = name ? name.end : i + 1
    return { text: s.slice(start, end), end }
  }
  const first = readToken(s, i)
  if (!first) return null
  if (/^\d+$/.test(first.text)) {
    // "N G R" — comments and whitespace may separate the tokens
    const j = skipWs(s, first.end)
    const second = readToken(s, j)
    if (second && /^\d+$/.test(second.text)) {
      const k = skipWs(s, second.end)
      const third = readToken(s, k)
      if (third?.text === 'R') return { text: `${first.text} ${second.text} R`, end: third.end }
    }
  }
  return first
}

/** Top-level /Key → value text of a dictionary (null if not a dictionary). */
export function parseTopLevelDict(text: string): Map<string, string> | null {
  const s = text.trim()
  if (!s.startsWith('<<')) return null
  const out = new Map<string, string>()
  let i = 2
  for (;;) {
    i = skipWs(s, i)
    if (i >= s.length) return null
    if (s.startsWith('>>', i)) return out
    if (s[i] !== '/') return null
    const key = readValue(s, i)
    if (!key) return null
    i = skipWs(s, key.end)
    const value = readValue(s, i)
    if (!value) return null
    out.set(key.text.slice(1), value.text)
    i = value.end
  }
}

/** Indirect references in a value, using the same tokenizer as readers. */
function refsIn(text: string): number[] {
  const out: number[] = []
  const walk = (s: string): void => {
    let i = 0
    while (i < s.length) {
      i = skipWs(s, i)
      if (i >= s.length) break
      if (s.startsWith('<<', i) || s[i] === '[' || s[i] === '(' || s[i] === '<' || s[i] === '/') {
        const v = readValue(s, i)
        if (!v) {
          i++
          continue
        }
        if (s.startsWith('<<', i)) walk(v.text.slice(2, -2))
        else if (s[i] === '[') walk(v.text.slice(1, -1))
        i = v.end
        continue
      }
      if (s.startsWith('>>', i) || s[i] === ']' || s[i] === ')' || s[i] === '>' || s[i] === '{' || s[i] === '}') {
        i++
        continue
      }
      const v = readValue(s, i)
      if (!v) {
        i++
        continue
      }
      const ref = /^(\d+) \d+ R$/.exec(v.text)
      if (ref) out.push(Number(ref[1]))
      i = v.end
    }
  }
  walk(text)
  return out
}

function refNumber(value: string | undefined): number | null {
  const v = value === undefined ? null : readValue(value.trim(), 0)
  const m = v ? /^(\d+) \d+ R$/.exec(v.text) : null
  return m ? Number(m[1]) : null
}

function nameValue(value: string | undefined): string | null {
  const m = /^\s*\/(\S+)\s*$/.exec(value ?? '')
  return m ? m[1] : null
}

function numbersIn(text: string): number[] {
  return (text.match(/-?\d+/g) ?? []).map(Number)
}

function isArray(text: string): boolean {
  return text.trim().startsWith('[')
}

function normalize(text: string): string {
  return text.replace(/\s+/g, ' ').replace(/\s*([<>[\]/()])\s*/g, '$1').trim()
}

function diffKeys(a: Map<string, string>, b: Map<string, string>): string[] {
  const keys = new Set([...a.keys(), ...b.keys()])
  return [...keys].filter((k) => normalize(a.get(k) ?? '') !== normalize(b.get(k) ?? ''))
}

function sameObject(a: PdfObject, b: PdfObject): boolean {
  if (normalize(a.value) !== normalize(b.value)) return false
  if (!a.stream && !b.stream) return true
  if (!a.stream || !b.stream || a.stream.length !== b.stream.length) return false
  return a.stream.every((v, i) => v === b.stream![i])
}

function describe(obj: PdfObject | null): string {
  if (!obj) return 'unreadable'
  const dict = parseTopLevelDict(obj.value)
  const type = nameValue(dict?.get('Type')) ?? nameValue(dict?.get('Subtype'))
  return type ?? (obj.stream ? 'stream' : isArray(obj.value) ? 'array' : 'dictionary')
}

function readInt(data: Uint8Array, offset: number, width: number): number {
  let v = 0
  for (let k = 0; k < width; k++) v = v * 256 + data[offset + k]
  return v
}

function hasNonWhitespace(data: Uint8Array, from: number): boolean {
  for (let i = from; i < data.length; i++) {
    const b = data[i]
    if (b !== 0x20 && b !== 0x0a && b !== 0x0d && b !== 0x09 && b !== 0x00 && b !== 0x0c) return true
  }
  return false
}
