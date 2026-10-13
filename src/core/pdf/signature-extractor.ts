import type { PdfSignatureField, ByteRange, EmbeddedRevocationInfo } from '@/types'
import { buildXRefTable, resolveObject, resolveStreamObject } from './xref-parser'
import type { XRefTable } from './xref-parser'
import { asBufferSource } from '../bytes'

/**
 * Alternative signature extraction using raw PDF parsing
 * This is used when pdfjs-dist cannot access the internal structure
 */
export function extractSignaturesFromRaw(data: Uint8Array): PdfSignatureField[] {
  const signatures: PdfSignatureField[] = []
  const text = new TextDecoder('latin1').decode(data)

  // Find all signature dictionaries (/Type /Sig and /Type /DocTimeStamp).
  // Matches inside stream data are skipped: an attached (embedded) PDF can
  // carry its own signature dictionaries, whose ByteRanges refer to the
  // attachment, not to this document.
  const streamSpans = findStreamDataSpans(data, text)
  const sigRegex = /\/Type\s*\/(Sig|DocTimeStamp)\b/g
  let match: RegExpExecArray | null

  while ((match = sigRegex.exec(text)) !== null) {
    if (isInsideSpan(match.index, streamSpans)) continue
    const sigField = extractSignatureAtPosition(data, text, match.index)
    if (sigField) {
      if (match[1] === 'DocTimeStamp') {
        sigField.isDocTimeStamp = true
      }
      signatures.push(sigField)
    }
  }

  return signatures
}

/**
 * Byte spans [start, end) of stream data. Uses a direct /Length when present,
 * otherwise the next "endstream".
 */
function findStreamDataSpans(data: Uint8Array, text: string): Array<[number, number]> {
  const spans: Array<[number, number]> = []
  const re = /\bstream\r?\n/g
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    if (text.slice(Math.max(0, m.index - 3), m.index) === 'end') continue
    const start = m.index + m[0].length
    const dictEnd = text.lastIndexOf('>>', m.index)
    const dictStart = dictEnd === -1 ? -1 : text.lastIndexOf(' obj', dictEnd)
    const lengthMatch = dictStart === -1 ? null : text.slice(dictStart, dictEnd).match(/\/Length\s+(\d+)\b(?!\s+\d+\s+R)/)
    let end = lengthMatch ? start + Number(lengthMatch[1]) : -1
    if (end <= start || end > data.length || !text.startsWith('endstream', skipEol(text, end))) {
      end = text.indexOf('endstream', start)
    }
    if (end === -1) break
    spans.push([start, end])
    re.lastIndex = end
  }
  return spans
}

function skipEol(text: string, i: number): number {
  while (text[i] === '\r' || text[i] === '\n') i++
  return i
}

function isInsideSpan(index: number, spans: Array<[number, number]>): boolean {
  return spans.some(([start, end]) => index >= start && index < end)
}

function extractSignatureAtPosition(
  data: Uint8Array,
  text: string,
  position: number
): PdfSignatureField | null {
  // Find the dictionary boundaries
  const dictStart = findDictStart(text, position)
  const dictEnd = findDictEnd(text, position)

  if (dictStart === -1 || dictEnd === -1) {
    return null
  }

  const dictText = text.slice(dictStart, dictEnd + 2)

  // Extract ByteRange
  const byteRange = extractByteRange(dictText)
  if (!byteRange) {
    return null
  }

  // Extract Contents
  const contents = extractContents(data, text, dictStart, dictEnd)
  if (!contents) {
    return null
  }

  // Extract SubFilter
  const subFilter = extractSubFilter(dictText)

  // Extract optional fields
  const reason = extractStringField(dictText, 'Reason')
  const location = extractStringField(dictText, 'Location')
  const contactInfo = extractStringField(dictText, 'ContactInfo')
  const name = extractStringField(dictText, 'Name') || `Signature`

  // Detect DocTimeStamp via SubFilter
  const isDocTimeStamp = /\/SubFilter\s*\/ETSI\.RFC3161/.test(dictText)
    || /\/Type\s*\/DocTimeStamp/.test(dictText)

  // Audit P2-7: parse DocMDP / FieldMDP from /Reference array
  const { docMdp, fieldMdp } = extractMdpInfo(dictText)

  return {
    name,
    byteRange,
    contents,
    subFilter,
    isDocTimeStamp: isDocTimeStamp || undefined,
    reason,
    location,
    contactInfo,
    docMdp,
    fieldMdp,
  }
}

/**
 * Audit P2-7: extract DocMDP and FieldMDP transform-method info from the
 * signature's /Reference array. A signature is a certification signature
 * when it contains a /Reference entry with /TransformMethod /DocMDP.
 *
 * Structure (PDF 1.7, ISO 32000-1 §12.8.2.2):
 *   /Reference [ << /TransformMethod /DocMDP
 *                   /TransformParams << /Type /TransformParams
 *                                       /P 1
 *                                       /V /1.2
 *                                       /DigestMethod /SHA1 >> >> ]
 *
 * /P values: 1 = No changes; 2 = form fill-in/signatures; 3 = above + annotations.
 */
function extractMdpInfo(dictText: string): {
  docMdp?: PdfSignatureField['docMdp']
  fieldMdp?: PdfSignatureField['fieldMdp']
} {
  const result: ReturnType<typeof extractMdpInfo> = {}

  const docMdpMatch = dictText.match(
    /\/TransformMethod\s*\/DocMDP[\s\S]*?\/TransformParams\s*<<([\s\S]*?)>>/
  )
  if (docMdpMatch) {
    const params = docMdpMatch[1]
    const pMatch = params.match(/\/P\s+(\d)/)
    const digestMatch = params.match(/\/DigestMethod\s*\/(\w+)/)
    const rawLevel = pMatch ? parseInt(pMatch[1], 10) : 2
    const level: 1 | 2 | 3 = rawLevel === 1 ? 1 : rawLevel === 3 ? 3 : 2
    result.docMdp = {
      permissionLevel: level,
      digestMethod: digestMatch ? digestMatch[1] : undefined,
    }
  }

  const fieldMdpMatch = dictText.match(
    /\/TransformMethod\s*\/FieldMDP[\s\S]*?\/TransformParams\s*<<([\s\S]*?)>>/
  )
  if (fieldMdpMatch) {
    const params = fieldMdpMatch[1]
    const actionMatch = params.match(/\/Action\s*\/(\w+)/)
    const fieldsMatch = params.match(/\/Fields\s*\[([^\]]*)\]/)
    const action = (actionMatch ? actionMatch[1] : 'All') as 'All' | 'Include' | 'Exclude'
    const fields: string[] = []
    if (fieldsMatch) {
      const fieldsContent = fieldsMatch[1]
      const fieldPattern = /\(([^)]+)\)/g
      let fm: RegExpExecArray | null
      while ((fm = fieldPattern.exec(fieldsContent)) !== null) {
        fields.push(fm[1])
      }
    }
    result.fieldMdp = { action, fields }
  }

  return result
}

function findDictStart(text: string, position: number): number {
  let depth = 0
  let i = position

  // Go backwards to find the opening <<
  while (i >= 0) {
    if (text[i] === '>' && text[i - 1] === '>') {
      depth++
      i -= 2
    } else if (text[i] === '<' && text[i - 1] === '<') {
      if (depth === 0) {
        return i - 1
      }
      depth--
      i -= 2
    } else {
      i--
    }
  }

  return -1
}

function findDictEnd(text: string, position: number): number {
  let depth = 1
  let i = position

  // Find the first << before position
  while (i >= 0 && !(text[i] === '<' && text[i + 1] === '<')) {
    i--
  }

  // Now find the matching >>
  i += 2
  while (i < text.length) {
    if (text[i] === '<' && text[i + 1] === '<') {
      depth++
      i += 2
    } else if (text[i] === '>' && text[i + 1] === '>') {
      depth--
      if (depth === 0) {
        return i
      }
      i += 2
    } else {
      i++
    }
  }

  return -1
}

function extractByteRange(dictText: string): ByteRange | null {
  const match = dictText.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/)
  if (!match) {
    return null
  }

  return {
    start1: parseInt(match[1]),
    length1: parseInt(match[2]),
    start2: parseInt(match[3]),
    length2: parseInt(match[4]),
  }
}

function extractContents(
  data: Uint8Array,
  text: string,
  dictStart: number,
  dictEnd: number
): Uint8Array | null {
  const dictText = text.slice(dictStart, dictEnd + 2)

  // Find /Contents in the dictionary
  const contentsMatch = dictText.match(/\/Contents\s*<([0-9A-Fa-f]+)>/)
  if (contentsMatch) {
    return hexToBytes(contentsMatch[1])
  }

  // Try to find indirect reference
  const refMatch = dictText.match(/\/Contents\s+(\d+)\s+(\d+)\s+R/)
  if (refMatch) {
    const objNum = parseInt(refMatch[1])
    const genNum = parseInt(refMatch[2])
    return extractObjectContents(data, text, objNum, genNum)
  }

  return null
}

function extractObjectContents(
  _data: Uint8Array,
  text: string,
  objNum: number,
  genNum: number
): Uint8Array | null {
  // Find the object definition
  const objPattern = new RegExp(`${objNum}\\s+${genNum}\\s+obj`)
  const match = objPattern.exec(text)
  if (!match) {
    return null
  }

  // Find the stream or hex string
  const objStart = match.index
  const objEnd = text.indexOf('endobj', objStart)
  if (objEnd === -1) {
    return null
  }

  const objText = text.slice(objStart, objEnd)

  // Check for hex string
  const hexMatch = objText.match(/<([0-9A-Fa-f]+)>/)
  if (hexMatch) {
    return hexToBytes(hexMatch[1])
  }

  return null
}

function extractSubFilter(dictText: string): string {
  const match = dictText.match(/\/SubFilter\s*\/(\S+)/)
  if (match) {
    return match[1]
  }
  return 'adbe.pkcs7.detached'
}

function extractStringField(dictText: string, fieldName: string): string | undefined {
  // Try parentheses notation
  const parenMatch = dictText.match(new RegExp(`\\/${fieldName}\\s*\\(([^)]+)\\)`))
  if (parenMatch) {
    return decodePdfString(parenMatch[1])
  }

  // Try hex string notation
  const hexMatch = dictText.match(new RegExp(`\\/${fieldName}\\s*<([0-9A-Fa-f]+)>`))
  if (hexMatch) {
    return decodeHexString(hexMatch[1])
  }

  return undefined
}

function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.replace(/\s/g, '')
  const bytes = new Uint8Array(cleanHex.length / 2)

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16)
  }

  return bytes
}

function decodePdfString(str: string): string {
  // Handle escape sequences
  return str
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\b/g, '\b')
    .replace(/\\f/g, '\f')
    .replace(/\\\(/g, '(')
    .replace(/\\\)/g, ')')
    .replace(/\\\\/g, '\\')
}

function decodeHexString(hex: string): string {
  const bytes = hexToBytes(hex)
  return new TextDecoder('utf-8').decode(bytes)
}

/**
 * Get the signed data ranges from a PDF based on ByteRange
 */
export function getSignedDataRanges(
  data: Uint8Array,
  byteRange: ByteRange
): { range1: Uint8Array; range2: Uint8Array } {
  const range1 = data.slice(byteRange.start1, byteRange.start1 + byteRange.length1)
  const range2 = data.slice(byteRange.start2, byteRange.start2 + byteRange.length2)

  return { range1, range2 }
}

/**
 * Combine signed data ranges for hashing
 */
export function combineSignedData(
  data: Uint8Array,
  byteRange: ByteRange
): Uint8Array {
  const { range1, range2 } = getSignedDataRanges(data, byteRange)

  const combined = new Uint8Array(range1.length + range2.length)
  combined.set(range1, 0)
  combined.set(range2, range1.length)

  return combined
}

/**
 * Extract DSS (Document Security Store) from PDF catalog.
 * DSS is where LTV-enabled PDFs store OCSP responses, CRLs, and certificates
 * at the document level (outside the PKCS#7 signature).
 *
 * PDF structure:
 *   /DSS << /OCSPs [ stream-ref ... ] /CRLs [ stream-ref ... ] /Certs [ stream-ref ... ] >>
 */
export async function extractDss(data: Uint8Array): Promise<EmbeddedRevocationInfo | null> {
  const text = new TextDecoder('latin1').decode(data)

  // Build xref table for resolving objects in object streams (ObjStm)
  const xref = await buildXRefTable(data)
  // Find /DSS dictionary reference in the catalog or as a direct dictionary
  const dssRefMatch = text.match(/\/DSS\s+(\d+)\s+(\d+)\s+R/)
  const dssDictMatch = text.match(/\/DSS\s*<</)

  let dssText: string | null = null

  if (dssRefMatch) {
    const objNum = parseInt(dssRefMatch[1])
    const genNum = parseInt(dssRefMatch[2])
    // Try text-regex first, then fall back to xref+ObjStm extraction
    dssText = findObjectDict(text, objNum, genNum)
    if (!dssText) {
      dssText = await resolveObject(data, text, objNum, genNum, xref)
    }
  } else if (dssDictMatch) {
    const startIdx = dssDictMatch.index! + '/DSS'.length
    const dictStart = text.indexOf('<<', startIdx)
    if (dictStart !== -1) {
      const dictEnd = findMatchingDictEnd(text, dictStart)
      if (dictEnd !== -1) {
        dssText = text.slice(dictStart, dictEnd + 2)
      }
    }
  }

  if (!dssText) {
    return null
  }

  const ocspResponses: Uint8Array[] = []
  const crls: Uint8Array[] = []
  const certs: Uint8Array[] = []

  // Extract /OCSPs array of stream references (top-level DSS uses plural keys)
  const rawOcspRefs = extractArrayRefs(dssText, 'OCSPs')
  const ocspRefs = await resolveArrayOrStreamRefs(rawOcspRefs, data, text, xref)
  for (const ref of ocspRefs) {
    const streamData = await resolveStreamObject(data, text, ref.objNum, ref.genNum, xref)
      ?? await extractStreamData(data, text, ref.objNum, ref.genNum)
    if (streamData) {
      ocspResponses.push(streamData)
    }
  }

  // Extract /CRLs array of stream references
  const rawCrlRefs = extractArrayRefs(dssText, 'CRLs')
  const crlRefs = await resolveArrayOrStreamRefs(rawCrlRefs, data, text, xref)
  for (const ref of crlRefs) {
    const streamData = await resolveStreamObject(data, text, ref.objNum, ref.genNum, xref)
      ?? await extractStreamData(data, text, ref.objNum, ref.genNum)
    if (streamData) {
      crls.push(streamData)
    }
  }

  // Extract /Certs array of stream references (intermediate CA certificates)
  const rawCertRefs = extractArrayRefs(dssText, 'Certs')
  const certRefs = await resolveArrayOrStreamRefs(rawCertRefs, data, text, xref)
  for (const ref of certRefs) {
    const streamData = await resolveStreamObject(data, text, ref.objNum, ref.genNum, xref)
      ?? await extractStreamData(data, text, ref.objNum, ref.genNum)
    if (streamData) {
      certs.push(streamData)
    }
  }

  // Also try extracting from VRI (Validation Related Information) sub-dictionaries
  // VRI uses SINGULAR keys: /OCSP, /CRL, /Cert
  await extractFromVri(data, text, dssText, ocspResponses, crls, xref)

  if (ocspResponses.length === 0 && crls.length === 0 && certs.length === 0) {
    return null
  }

  return { ocspResponses, crls, certs }
}

/**
 * Extract revocation data from VRI dictionaries inside DSS.
 * VRI maps SHA-1 hashes of signature contents to per-signature validation data.
 */
async function extractFromVri(
  data: Uint8Array,
  text: string,
  dssText: string,
  ocspResponses: Uint8Array[],
  crls: Uint8Array[],
  xref: XRefTable | null = null
): Promise<void> {
  // VRI as indirect reference
  const vriRefMatch = dssText.match(/\/VRI\s+(\d+)\s+(\d+)\s+R/)
  if (vriRefMatch) {
    const vriObjNum = parseInt(vriRefMatch[1])
    const vriGenNum = parseInt(vriRefMatch[2])
    let vriDict = findObjectDict(text, vriObjNum, vriGenNum)
    if (!vriDict) {
      vriDict = await resolveObject(data, text, vriObjNum, vriGenNum, xref)
    }
    if (vriDict) {
      await extractVriEntries(data, text, vriDict, ocspResponses, crls, xref)
    }
    return
  }

  // VRI as inline dictionary
  const vriInlineIdx = dssText.indexOf('/VRI')
  if (vriInlineIdx === -1) return

  const vriDictStart = dssText.indexOf('<<', vriInlineIdx + 4)
  if (vriDictStart === -1) return

  const vriDictEnd = findMatchingDictEnd(dssText, vriDictStart)
  if (vriDictEnd === -1) return

  const vriDict = dssText.slice(vriDictStart, vriDictEnd + 2)
  await extractVriEntries(data, text, vriDict, ocspResponses, crls, xref)
}

/**
 * Extract OCSP/CRL data from all VRI sub-entries.
 * Each VRI entry key is a SHA-1 hash; value is a dict with /OCSP, /CRL, /Cert (singular).
 */
async function extractVriEntries(
  data: Uint8Array,
  text: string,
  vriDict: string,
  ocspResponses: Uint8Array[],
  crls: Uint8Array[],
  xref: XRefTable | null = null
): Promise<void> {
  // Find all sub-dictionaries (each VRI entry is /HASH << ... >>)
  // Also handle indirect refs: /HASH 123 0 R
  const entryRefPattern = /\/[A-F0-9]{40}\s+(\d+)\s+(\d+)\s+R/gi
  let entryRefMatch: RegExpExecArray | null
  while ((entryRefMatch = entryRefPattern.exec(vriDict)) !== null) {
    const entryObjNum = parseInt(entryRefMatch[1])
    const entryGenNum = parseInt(entryRefMatch[2])
    let entryDict = findObjectDict(text, entryObjNum, entryGenNum)
    if (!entryDict) {
      entryDict = await resolveObject(data, text, entryObjNum, entryGenNum, xref)
    }
    if (entryDict) {
      await extractVriSingleEntry(data, text, entryDict, ocspResponses, crls, xref)
    }
  }

  // Inline VRI entries: /HASH << /OCSP [...] /CRL [...] >>
  const inlinePattern = /\/[A-F0-9]{40}\s*<</gi
  let inlineMatch: RegExpExecArray | null
  while ((inlineMatch = inlinePattern.exec(vriDict)) !== null) {
    const dictStart = vriDict.indexOf('<<', inlineMatch.index + 41)
    if (dictStart === -1) continue
    const dictEnd = findMatchingDictEnd(vriDict, dictStart)
    if (dictEnd === -1) continue
    const entryDict = vriDict.slice(dictStart, dictEnd + 2)
    await extractVriSingleEntry(data, text, entryDict, ocspResponses, crls, xref)
  }
}

/**
 * Extract OCSP/CRL from a single VRI entry dict (uses singular keys /OCSP, /CRL).
 */
async function extractVriSingleEntry(
  data: Uint8Array,
  text: string,
  entryDict: string,
  ocspResponses: Uint8Array[],
  crls: Uint8Array[],
  xref: XRefTable | null = null
): Promise<void> {
  // VRI uses singular keys: /OCSP (not /OCSPs), /CRL (not /CRLs)
  const rawOcspRefs = extractArrayRefs(entryDict, 'OCSP')
  const ocspRefs = await resolveArrayOrStreamRefs(rawOcspRefs, data, text, xref)
  for (const ref of ocspRefs) {
    const streamData = await resolveStreamObject(data, text, ref.objNum, ref.genNum, xref)
      ?? await extractStreamData(data, text, ref.objNum, ref.genNum)
    if (streamData) {
      ocspResponses.push(streamData)
    }
  }

  const rawCrlRefs = extractArrayRefs(entryDict, 'CRL')
  const crlRefs = await resolveArrayOrStreamRefs(rawCrlRefs, data, text, xref)
  for (const ref of crlRefs) {
    const streamData = await resolveStreamObject(data, text, ref.objNum, ref.genNum, xref)
      ?? await extractStreamData(data, text, ref.objNum, ref.genNum)
    if (streamData) {
      crls.push(streamData)
    }
  }
}

/**
 * Find a PDF object's dictionary by object number.
 * Searches ALL occurrences and takes the LAST one (for incremental updates).
 * Only returns dict content (<<...>>).
 */
function findObjectDict(text: string, objNum: number, genNum: number): string | null {
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

  const dictEnd = findMatchingDictEnd(text, dictStart)
  if (dictEnd === -1 || dictEnd > endObjIdx) return null

  return text.slice(dictStart, dictEnd + 2)
}

/**
 * Find a PDF object's raw value (any type: dict, array, value, stream).
 * Returns the trimmed content between `obj` and `endobj`/`stream`.
 */
function findObjectValue(text: string, objNum: number, genNum: number): string | null {
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

  // Stop at 'stream' keyword if present (stream objects)
  const streamIdx = text.indexOf('stream', objStart)
  const contentEnd = (streamIdx !== -1 && streamIdx < endObjIdx) ? streamIdx : endObjIdx

  return text.slice(objStart, contentEnd).trim()
}

function findMatchingDictEnd(text: string, start: number): number {
  let depth = 0
  let i = start

  while (i < text.length - 1) {
    if (text[i] === '<' && text[i + 1] === '<') {
      depth++
      i += 2
    } else if (text[i] === '>' && text[i + 1] === '>') {
      depth--
      if (depth === 0) {
        return i
      }
      i += 2
    } else {
      i++
    }
  }

  return -1
}

interface ObjRef {
  objNum: number
  genNum: number
}

/**
 * Extract object references from a PDF dictionary key.
 * Handles three formats:
 *   1. /Key [ 1 0 R 2 0 R ]           — inline array
 *   2. /Key 86 0 R                     — single indirect ref (could be array object or stream)
 *   3. /Key with value resolved later  — indirect array object in ObjStm
 */
function extractArrayRefs(dictText: string, key: string): ObjRef[] {
  const refs: ObjRef[] = []

  // Format 1: /Key [ 1 0 R 2 0 R ... ]
  const arrayMatch = dictText.match(new RegExp(`\\/${key}(?![A-Za-z])\\s*\\[([^\\]]+)\\]`))
  if (arrayMatch) {
    const arrayContent = arrayMatch[1]
    const refPattern = /(\d+)\s+(\d+)\s+R/g
    let refMatch: RegExpExecArray | null
    while ((refMatch = refPattern.exec(arrayContent)) !== null) {
      refs.push({
        objNum: parseInt(refMatch[1]),
        genNum: parseInt(refMatch[2]),
      })
    }
    return refs
  }

  // Format 2: /Key N G R (single indirect reference)
  const singleRefMatch = dictText.match(new RegExp(`\\/${key}(?![A-Za-z])\\s+(\\d+)\\s+(\\d+)\\s+R`))
  if (singleRefMatch) {
    refs.push({
      objNum: parseInt(singleRefMatch[1]),
      genNum: parseInt(singleRefMatch[2]),
    })
  }

  return refs
}

/**
 * Resolve refs that might point to array objects (not streams).
 * If a ref points to an array object like `[1 0 R 2 0 R]`, expand it.
 * Otherwise keep the ref as-is (it's a direct stream ref).
 */
async function resolveArrayOrStreamRefs(
  refs: ObjRef[],
  data: Uint8Array,
  text: string,
  xref: XRefTable | null
): Promise<ObjRef[]> {
  const resolved: ObjRef[] = []

  for (const ref of refs) {
    // Try to get the raw object value (supports arrays, dicts, etc.)
    const objText = findObjectValue(text, ref.objNum, ref.genNum)
      ?? await resolveObject(data, text, ref.objNum, ref.genNum, xref)

    if (objText && objText.trimStart().startsWith('[')) {
      // It's an array object — parse refs from it
      const refPattern = /(\d+)\s+(\d+)\s+R/g
      let m: RegExpExecArray | null
      while ((m = refPattern.exec(objText)) !== null) {
        resolved.push({ objNum: parseInt(m[1]), genNum: parseInt(m[2]) })
      }
    } else {
      // It's a stream or dict — keep the original ref
      resolved.push(ref)
    }
  }

  return resolved
}

async function extractStreamData(
  data: Uint8Array,
  text: string,
  objNum: number,
  genNum: number
): Promise<Uint8Array | null> {
  // Find the LAST occurrence of the object (for incremental updates)
  const objPattern = new RegExp(`(?:^|[^0-9])${objNum}\\s+${genNum}\\s+obj\\b`, 'g')
  let lastMatch: RegExpExecArray | null = null
  let match: RegExpExecArray | null
  while ((match = objPattern.exec(text)) !== null) {
    lastMatch = match
  }
  if (!lastMatch) {
    return null
  }

  const objKeywordIdx = text.indexOf('obj', lastMatch.index)
  if (objKeywordIdx === -1) return null
  const objStart = objKeywordIdx + 3
  const endObjIdx = text.indexOf('endobj', objStart)
  if (endObjIdx === -1) {
    return null
  }

  // Find stream keyword
  const streamKeyword = 'stream'
  const endstreamKeyword = 'endstream'

  const streamStart = text.indexOf(streamKeyword, objStart)
  if (streamStart === -1 || streamStart > endObjIdx) {
    return null
  }

  // Stream data starts after "stream\r\n" or "stream\n"
  let dataStart = streamStart + streamKeyword.length
  if (data[dataStart] === 0x0d && data[dataStart + 1] === 0x0a) {
    dataStart += 2
  } else if (data[dataStart] === 0x0a) {
    dataStart += 1
  } else if (data[dataStart] === 0x0d) {
    dataStart += 1
  }

  const endstreamIdx = text.indexOf(endstreamKeyword, dataStart)
  if (endstreamIdx === -1) {
    return null
  }

  // Check for /Length in the dictionary
  const dictSlice = text.slice(objStart, streamStart)
  const directLengthMatch = dictSlice.match(/\/Length\s+(\d+)/)
  const indirectLengthMatch = dictSlice.match(/\/Length\s+(\d+)\s+(\d+)\s+R/)

  let streamLength: number
  if (indirectLengthMatch) {
    // /Length is an indirect reference — resolve it
    const lenObjNum = parseInt(indirectLengthMatch[1])
    const lenGenNum = parseInt(indirectLengthMatch[2])
    const resolvedLength = resolveIntegerObject(text, lenObjNum, lenGenNum)
    streamLength = resolvedLength ?? (endstreamIdx - dataStart)
  } else if (directLengthMatch) {
    streamLength = parseInt(directLengthMatch[1])
  } else {
    // Fallback: use the distance to endstream (trim trailing whitespace)
    streamLength = endstreamIdx - dataStart
    while (streamLength > 0 && (data[dataStart + streamLength - 1] === 0x0a || data[dataStart + streamLength - 1] === 0x0d)) {
      streamLength--
    }
  }

  const rawStream = data.slice(dataStart, dataStart + streamLength)

  // Check if the stream is compressed
  const filterMatch = dictSlice.match(/\/Filter\s*(?:\[?\s*)?\/(\w+)/)
  if (filterMatch) {
    const filter = filterMatch[1]
    if (filter === 'FlateDecode') {
      return decompressFlate(rawStream)
    }
    // Unsupported filter
    return null
  }

  return rawStream
}

function resolveIntegerObject(text: string, objNum: number, genNum: number): number | null {
  const pattern = new RegExp(`(?:^|[^0-9])${objNum}\\s+${genNum}\\s+obj\\s+(\\d+)\\s+endobj`, 'g')
  let lastMatch: RegExpExecArray | null = null
  let match: RegExpExecArray | null
  while ((match = pattern.exec(text)) !== null) {
    lastMatch = match
  }
  if (lastMatch) {
    return parseInt(lastMatch[1])
  }
  return null
}

async function decompressFlate(compressed: Uint8Array): Promise<Uint8Array | null> {
  if (typeof DecompressionStream === 'undefined') {
    return null
  }

  // PDF FlateDecode uses zlib (RFC 1950) format.
  // DecompressionStream('deflate') handles zlib-wrapped data.
  // Try zlib first, then raw deflate as fallback.
  const formats: CompressionFormat[] = ['deflate', 'raw' as CompressionFormat]

  for (const format of formats) {
    try {
      const result = await decompressWithFormat(compressed, format)
      if (result && result.length > 0) {
        return result
      }
    } catch {
      continue
    }
  }

  return null
}

async function decompressWithFormat(
  compressed: Uint8Array,
  format: CompressionFormat
): Promise<Uint8Array | null> {
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
    // Partial read is still useful if we got some data
    if (chunks.length === 0) {
      return null
    }
  }

  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.length
  }

  return result
}
