import { asBufferSource } from '../bytes'
/**
 * PDF Cross-Reference Stream Parser
 *
 * Modern PDFs use cross-reference streams (instead of text xref tables)
 * and object streams (ObjStm) to store objects in compressed form.
 * Objects inside ObjStm cannot be found by text regex — they must be
 * extracted by parsing the xref stream to locate the containing ObjStm,
 * decompressing it, and indexing into the decompressed data.
 *
 * References:
 *   - PDF 1.7 spec §7.5.8 (Cross-Reference Streams)
 *   - PDF 1.7 spec §7.5.7 (Object Streams)
 */

const XREF_TYPE_UNCOMPRESSED = 1
const XREF_TYPE_COMPRESSED = 2

interface XRefEntry {
  type: number
  /** For type 1: byte offset. For type 2: object stream number. */
  field2: number
  /** For type 1: generation number. For type 2: index within object stream. */
  field3: number
}

export interface XRefTable {
  entries: Map<number, XRefEntry>
}

/**
 * Build a complete xref table by parsing all xref streams in the PDF.
 * Follows the /Prev chain for incremental updates.
 */
export async function buildXRefTable(data: Uint8Array): Promise<XRefTable | null> {
  const text = new TextDecoder('latin1').decode(data)

  // Find startxref offset (last one in the file)
  const startxrefPattern = /startxref\s+(\d+)/g
  let lastStartxref: number | null = null
  let m: RegExpExecArray | null
  while ((m = startxrefPattern.exec(text)) !== null) {
    lastStartxref = parseInt(m[1])
  }

  if (lastStartxref === null) {
    return null
  }

  const entries = new Map<number, XRefEntry>()
  const visited = new Set<number>()
  let offset: number | null = lastStartxref

  while (offset !== null && !visited.has(offset)) {
    visited.add(offset)

    const result = await parseXRefStreamAt(data, text, offset)
    if (!result) break

    // Later incremental updates have higher priority
    for (const [objNum, entry] of result.entries) {
      if (!entries.has(objNum)) {
        entries.set(objNum, entry)
      }
    }

    offset = result.prev
  }

  if (entries.size === 0) {
    return null
  }

  return { entries }
}

/**
 * Parse a single xref stream object at the given byte offset.
 */
async function parseXRefStreamAt(
  data: Uint8Array,
  text: string,
  offset: number
): Promise<{ entries: Map<number, XRefEntry>; prev: number | null } | null> {
  const slice = text.slice(offset, Math.min(offset + 100, text.length))
  const objMatch = slice.match(/^(\d+)\s+(\d+)\s+obj\b/)
  if (!objMatch) return null

  const objStart = offset + objMatch[0].length
  const endobjIdx = text.indexOf('endobj', objStart)
  if (endobjIdx === -1) return null

  const dictStart = text.indexOf('<<', objStart)
  if (dictStart === -1 || dictStart > endobjIdx) return null

  const dictEnd = findMatchingEnd(text, dictStart)
  if (dictEnd === -1 || dictEnd > endobjIdx) return null

  const dictText = text.slice(dictStart, dictEnd + 2)

  // Verify /Type /XRef
  if (!/\/Type\s*\/XRef/.test(dictText)) return null

  // Parse /W array [w1 w2 w3]
  const wMatch = dictText.match(/\/W\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s*\]/)
  if (!wMatch) return null
  const w1 = parseInt(wMatch[1])
  const w2 = parseInt(wMatch[2])
  const w3 = parseInt(wMatch[3])
  const entrySize = w1 + w2 + w3

  // Parse /Size
  const sizeMatch = dictText.match(/\/Size\s+(\d+)/)
  if (!sizeMatch) return null
  const size = parseInt(sizeMatch[1])

  // Parse /Index array (optional, defaults to [0 size])
  let indexPairs: number[] = [0, size]
  const indexMatch = dictText.match(/\/Index\s*\[([\d\s]+)\]/)
  if (indexMatch) {
    indexPairs = indexMatch[1].trim().split(/\s+/).map(Number)
  }

  // Parse /Prev
  const prevMatch = dictText.match(/\/Prev\s+(\d+)/)
  const prev = prevMatch ? parseInt(prevMatch[1]) : null

  // Extract and decompress stream data
  const streamData = await extractRawStreamAsync(data, text, objStart, endobjIdx, dictText)
  if (!streamData) return null

  // Parse entries
  const entries = new Map<number, XRefEntry>()
  let byteIdx = 0

  for (let p = 0; p < indexPairs.length; p += 2) {
    const startObj = indexPairs[p]
    const count = indexPairs[p + 1]

    for (let i = 0; i < count; i++) {
      if (byteIdx + entrySize > streamData.length) break

      const type = w1 > 0 ? readInt(streamData, byteIdx, w1) : 1
      const field2 = readInt(streamData, byteIdx + w1, w2)
      const field3 = w3 > 0 ? readInt(streamData, byteIdx + w1 + w2, w3) : 0

      entries.set(startObj + i, { type, field2, field3 })
      byteIdx += entrySize
    }
  }

  return { entries, prev }
}

/**
 * Extract an object from an object stream (ObjStm).
 * Returns the text content of the object (its dictionary/value).
 */
async function extractObjectFromObjStm(
  data: Uint8Array,
  text: string,
  xref: XRefTable,
  targetObjNum: number
): Promise<string | null> {
  const entry = xref.entries.get(targetObjNum)
  if (!entry || entry.type !== XREF_TYPE_COMPRESSED) return null

  const objStmNum = entry.field2
  const indexInStm = entry.field3

  const objStmEntry = xref.entries.get(objStmNum)
  if (!objStmEntry || objStmEntry.type !== XREF_TYPE_UNCOMPRESSED) return null

  // Extract and decompress the object stream
  const objStmData = await extractStreamAtOffset(data, text, objStmEntry.field2)
  if (!objStmData) return null

  // Read /N and /First from the ObjStm dictionary at its byte offset
  const objStmOffset = objStmEntry.field2
  const objStmSlice = text.slice(objStmOffset, Math.min(objStmOffset + 500, text.length))
  const nMatch = objStmSlice.match(/\/N\s+(\d+)/)
  const firstMatch = objStmSlice.match(/\/First\s+(\d+)/)
  if (!nMatch || !firstMatch) return null

  const n = parseInt(nMatch[1])
  const first = parseInt(firstMatch[1])
  // Parse the header: N pairs of (objNum byteOffset) as text integers
  const headerText = new TextDecoder('latin1').decode(objStmData.slice(0, first))
  const tokens = headerText.trim().split(/\s+/).map(Number)

  if (tokens.length < n * 2) return null

  // Find target object's offset
  let targetOffset = -1
  let nextOffset = -1

  for (let i = 0; i < n; i++) {
    if (i === indexInStm) {
      targetOffset = tokens[i * 2 + 1]
      if (i + 1 < n) {
        nextOffset = tokens[(i + 1) * 2 + 1]
      }
      break
    }
  }

  if (targetOffset === -1) return null

  const dataStart = first + targetOffset
  const dataEnd = nextOffset !== -1 ? first + nextOffset : objStmData.length

  const extractedText = new TextDecoder('latin1').decode(objStmData.slice(dataStart, dataEnd)).trim()
  return extractedText
}

/**
 * Extract a stream object's decompressed data given its byte offset.
 */
export async function extractStreamAtOffset(
  data: Uint8Array,
  text: string,
  offset: number
): Promise<Uint8Array | null> {
  const slice = text.slice(offset, Math.min(offset + 100, text.length))
  const objMatch = slice.match(/^(\d+)\s+(\d+)\s+obj\b/)
  if (!objMatch) return null

  const objStart = offset + objMatch[0].length
  const endobjIdx = text.indexOf('endobj', objStart)
  if (endobjIdx === -1) return null

  const dictStart = text.indexOf('<<', objStart)
  if (dictStart === -1 || dictStart > endobjIdx) return null
  const dictEnd = findMatchingEnd(text, dictStart)
  if (dictEnd === -1 || dictEnd > endobjIdx) return null

  const dictText = text.slice(dictStart, dictEnd + 2)

  return extractRawStreamAsync(data, text, objStart, endobjIdx, dictText)
}

/**
 * Extract and optionally decompress raw stream data from an object (async).
 */
async function extractRawStreamAsync(
  data: Uint8Array,
  text: string,
  objStart: number,
  endobjIdx: number,
  dictText: string
): Promise<Uint8Array | null> {
  const streamIdx = text.indexOf('stream', objStart)
  if (streamIdx === -1 || streamIdx > endobjIdx) return null

  let dataStart = streamIdx + 6 // 'stream'.length
  if (data[dataStart] === 0x0d && data[dataStart + 1] === 0x0a) {
    dataStart += 2
  } else if (data[dataStart] === 0x0a || data[dataStart] === 0x0d) {
    dataStart += 1
  }

  // Determine stream length
  const indirectLenMatch = dictText.match(/\/Length\s+(\d+)\s+(\d+)\s+R/)
  const directLenMatch = dictText.match(/\/Length\s+(\d+)(?!\s+\d+\s+R)/)

  let streamLength: number
  if (indirectLenMatch) {
    const lenObjNum = parseInt(indirectLenMatch[1])
    const lenGenNum = parseInt(indirectLenMatch[2])
    const resolved = resolveIntegerFromText(text, lenObjNum, lenGenNum)
    streamLength = resolved ?? findEndstreamDistance(text, data, dataStart)
  } else if (directLenMatch) {
    streamLength = parseInt(directLenMatch[1])
  } else {
    streamLength = findEndstreamDistance(text, data, dataStart)
  }

  const rawStream = data.slice(dataStart, dataStart + streamLength)

  // Check filter
  const filterMatch = dictText.match(/\/Filter\s*(?:\[?\s*)?\/(\w+)/)
  if (filterMatch && filterMatch[1] === 'FlateDecode') {
    return decompressFlate(rawStream)
  }

  return rawStream
}

function findEndstreamDistance(text: string, data: Uint8Array, dataStart: number): number {
  const endstreamIdx = text.indexOf('endstream', dataStart)
  if (endstreamIdx === -1) return 0
  let len = endstreamIdx - dataStart
  while (len > 0 && (data[dataStart + len - 1] === 0x0a || data[dataStart + len - 1] === 0x0d)) {
    len--
  }
  return len
}

function resolveIntegerFromText(text: string, objNum: number, genNum: number): number | null {
  const pattern = new RegExp(`(?:^|[^0-9])${objNum}\\s+${genNum}\\s+obj\\s+(\\d+)\\s+endobj`, 'g')
  let lastMatch: RegExpExecArray | null = null
  let match: RegExpExecArray | null
  while ((match = pattern.exec(text)) !== null) {
    lastMatch = match
  }
  return lastMatch ? parseInt(lastMatch[1]) : null
}

/**
 * Decompress FlateDecode using DecompressionStream API.
 * Tries zlib (deflate) first, then raw deflate as fallback.
 */
export async function decompressFlate(compressed: Uint8Array): Promise<Uint8Array | null> {
  if (typeof DecompressionStream === 'undefined') return null

  const formats: CompressionFormat[] = ['deflate', 'raw' as CompressionFormat]

  for (const format of formats) {
    try {
      const ds = new DecompressionStream(format)
      const writer = ds.writable.getWriter()
      const reader = ds.readable.getReader()

      writer.write(asBufferSource(compressed)).catch(() => {})
      writer.close().catch(() => {})

      const chunks: Uint8Array[] = []
      try {
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          chunks.push(value)
        }
      } catch {
        if (chunks.length === 0) continue
      }

      const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
      if (totalLength === 0) continue

      const result = new Uint8Array(totalLength)
      let offset = 0
      for (const chunk of chunks) {
        result.set(chunk, offset)
        offset += chunk.length
      }

      return result
    } catch {
      continue
    }
  }

  return null
}

// ── Public API ──────────────────────────────────────────────

/**
 * Resolve a PDF object that might be in an object stream.
 * Returns the object's dictionary text content.
 * Tries text-regex first, falls back to xref+objstm parsing.
 */
export async function resolveObject(
  data: Uint8Array,
  text: string,
  objNum: number,
  genNum: number,
  xref: XRefTable | null
): Promise<string | null> {
  const textResult = findObjectDictByText(text, objNum, genNum)
  if (textResult) return textResult

  if (!xref) return null
  return extractObjectFromObjStm(data, text, xref, objNum)
}

/**
 * Extract a stream object's decompressed data.
 * Tries text-regex first, falls back to xref byte offset.
 */
export async function resolveStreamObject(
  data: Uint8Array,
  text: string,
  objNum: number,
  genNum: number,
  xref: XRefTable | null
): Promise<Uint8Array | null> {
  const textResult = await extractStreamByText(data, text, objNum, genNum)
  if (textResult) return textResult

  // Stream objects themselves cannot be inside object streams per PDF spec,
  // so they must be type 1 (uncompressed at a byte offset).
  if (!xref) return null

  const entry = xref.entries.get(objNum)
  if (!entry || entry.type !== XREF_TYPE_UNCOMPRESSED) return null

  return extractStreamAtOffset(data, text, entry.field2)
}

// ── Text-based fallback helpers ─────────────────────────────

function findObjectDictByText(text: string, objNum: number, genNum: number): string | null {
  const objPattern = new RegExp(`(?:^|[^0-9])${objNum}\\s+${genNum}\\s+obj\\b`, 'g')
  let lastMatch: RegExpExecArray | null = null
  let match: RegExpExecArray | null
  while ((match = objPattern.exec(text)) !== null) {
    lastMatch = match
  }
  if (!lastMatch) return null

  const objKeywordIdx = text.indexOf('obj', lastMatch.index)
  if (objKeywordIdx === -1) return null
  const objStart = objKeywordIdx + 3
  const endObjIdx = text.indexOf('endobj', objStart)
  if (endObjIdx === -1) return null

  const dictStart = text.indexOf('<<', objStart)
  if (dictStart === -1 || dictStart > endObjIdx) return null

  const dictEnd = findMatchingEnd(text, dictStart)
  if (dictEnd === -1 || dictEnd > endObjIdx) return null

  return text.slice(dictStart, dictEnd + 2)
}

async function extractStreamByText(
  data: Uint8Array,
  text: string,
  objNum: number,
  genNum: number
): Promise<Uint8Array | null> {
  const objPattern = new RegExp(`(?:^|[^0-9])${objNum}\\s+${genNum}\\s+obj\\b`, 'g')
  let lastMatch: RegExpExecArray | null = null
  let match: RegExpExecArray | null
  while ((match = objPattern.exec(text)) !== null) {
    lastMatch = match
  }
  if (!lastMatch) return null

  const objKeywordIdx = text.indexOf('obj', lastMatch.index)
  if (objKeywordIdx === -1) return null
  const objStart = objKeywordIdx + 3
  const endobjIdx = text.indexOf('endobj', objStart)
  if (endobjIdx === -1) return null

  const dictStart = text.indexOf('<<', objStart)
  if (dictStart === -1 || dictStart > endobjIdx) return null
  const dictEnd = findMatchingEnd(text, dictStart)
  if (dictEnd === -1 || dictEnd > endobjIdx) return null

  const dictText = text.slice(dictStart, dictEnd + 2)

  return extractRawStreamAsync(data, text, objStart, endobjIdx, dictText)
}

// ── Shared utilities ────────────────────────────────────────

function findMatchingEnd(text: string, start: number): number {
  let depth = 0
  let i = start
  while (i < text.length - 1) {
    if (text[i] === '<' && text[i + 1] === '<') {
      depth++
      i += 2
    } else if (text[i] === '>' && text[i + 1] === '>') {
      depth--
      if (depth === 0) return i
      i += 2
    } else {
      i++
    }
  }
  return -1
}

function readInt(data: Uint8Array, offset: number, width: number): number {
  let value = 0
  for (let i = 0; i < width; i++) {
    value = (value << 8) | data[offset + i]
  }
  return value
}
