// @vitest-environment node
/**
 * Regression tests for change-detection bypasses and false positives found in
 * review (synthetic, unsigned PDF structures only).
 */
import { describe, it, expect } from 'vitest'
import { createChangeAnalyzer } from '@/core/pdf/incremental-update'

const enc = (s: string) => new TextEncoder().encode(s)
type Obj = [number, string]

/** Revision with a classic xref table. */
function classic(base: string, objects: Obj[], trailer: string, prev?: number): string {
  let out = base
  const offsets: Array<[number, number]> = []
  for (const [num, body] of objects) {
    offsets.push([num, out.length])
    out += `${num} 0 obj\n${body}\nendobj\n`
  }
  const xrefAt = out.length
  out += 'xref\n'
  for (const [num, off] of offsets.sort((a, b) => a[0] - b[0])) out += `${num} 1\n${String(off).padStart(10, '0')} 00000 n \n`
  return out + `trailer\n<<${trailer}${prev !== undefined ? `/Prev ${prev}` : ''}>>\nstartxref\n${xrefAt}\n%%EOF\n`
}

/** Uncompressed object stream body for [num, value] members. */
function objStm(members: Obj[]): string {
  let header = ''
  let body = ''
  for (const [num, value] of members) {
    header += `${num} ${body.length} `
    body += value + '\n'
  }
  const content = header + body
  return `<</Type/ObjStm/N ${members.length}/First ${header.length}/Length ${content.length}>>\nstream\n${content}\nendstream`
}

/**
 * Revision with an (unfiltered) xref stream. `entries`: [num, type, f2, f3].
 * Uncompressed objects get their offsets filled in automatically (type 1, f2 = -1).
 */
function xrefStream(base: string, objects: Obj[], entries: Array<[number, number, number, number]>, trailer: string, xrefNum: number, prev?: number): string {
  let out = base
  const offsets = new Map<number, number>()
  for (const [num, body] of objects) {
    offsets.set(num, out.length)
    out += `${num} 0 obj\n${body}\nendobj\n`
  }
  const xrefAt = out.length
  const rows = [...entries, [xrefNum, 1, xrefAt, 0] as [number, number, number, number]]
    .map(([num, type, f2, f3]) => [num, type, f2 === -1 ? offsets.get(num)! : f2, f3] as const)
    .sort((a, b) => a[0] - b[0])
  const bytes: number[] = []
  for (const [, type, f2, f3] of rows) bytes.push(type, (f2 >>> 24) & 255, (f2 >>> 16) & 255, (f2 >>> 8) & 255, f2 & 255, (f3 >>> 8) & 255, f3 & 255)
  const index = rows.map(([num]) => `${num} 1`).join(' ')
  const data = String.fromCharCode(...bytes)
  out += `${xrefNum} 0 obj\n<</Type/XRef/W[1 4 2]/Index[${index}]/Size ${xrefNum + 1}${trailer}${prev !== undefined ? `/Prev ${prev}` : ''}/Length ${bytes.length}>>\nstream\n${data}\nendstream\nendobj\n`
  return out + `startxref\n${xrefAt}\n%%EOF\n`
}

function lastXref(pdf: string): number {
  return Number(/startxref\s+(\d+)\s*%%EOF\s*$/.exec(pdf)![1])
}

/** latin1 bytes (xref stream rows are binary). */
const bin = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0))

const CONTENT = '<</Length 9>>\nstream\nBT 1 Tj\nendstream'

const BASE = classic(
  '%PDF-1.7\n',
  [
    [1, '<</Type/Catalog/Pages 2 0 R/AcroForm 5 0 R>>'],
    [2, '<</Type/Pages/Kids[3 0 R]/Count 1>>'],
    [3, '<</Type/Page/Parent 2 0 R/Contents 4 0 R/MediaBox[0 0 10 10]/Annots[11 0 R 13 0 R]>>'],
    [4, CONTENT],
    [5, '<</Fields[11 0 R 13 0 R]/DR<</Font<</Helv 30 0 R>>>>>>'],
    [11, '<</Type/Annot/Subtype/Widget/FT/Sig/T(Empty)/Rect[0 0 0 0]/P 3 0 R>>'],
    [13, '<</Type/Annot/Subtype/Widget/FT/Tx/T(Name)/V(a)/Rect[0 0 5 5]/P 3 0 R>>'],
    [30, '<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>'],
  ],
  '/Size 31/Root 1 0 R'
)
const BASE_END = enc(BASE).length
const later = (n: number) => `<</Type/Sig/Filter/Adobe.PPKLite/Contents<00>/ByteRange[0 1 2 ${BASE_END + 1000}]>>`.replace('Sig', n === 1 ? 'Sig' : 'DocTimeStamp')

async function analyse(pdf: string, end: number, policy: 'ltv' | 'signing' | 'annotations') {
  return createChangeAnalyzer(bin(pdf)).changesSince(end, policy)
}

describe('change detection — bypass regressions', () => {
  it('detects a page rewritten inside a relocated object stream (same object-stream number)', async () => {
    // Signed revision keeps page 3 in object stream 20.
    const signed = xrefStream(
      '%PDF-1.7\n',
      [
        [1, '<</Type/Catalog/Pages 2 0 R>>'],
        [2, '<</Type/Pages/Kids[3 0 R]/Count 1>>'],
        [20, objStm([[3, '<</Type/Page/Parent 2 0 R/MediaBox[0 0 10 10]>>']])],
      ],
      [[1, 1, -1, 0], [2, 1, -1, 0], [20, 1, -1, 0], [3, 2, 20, 0]],
      '/Root 1 0 R',
      21
    )
    const end = bin(signed).length
    const pdf = xrefStream(signed, [[20, objStm([[3, '<</Type/Page/Parent 2 0 R/MediaBox[0 0 99 99]>>']])]], [[20, 1, -1, 0]], '/Root 1 0 R', 22, lastXref(signed))
    for (const policy of ['ltv', 'signing'] as const) {
      const result = await analyse(pdf, end, policy)
      expect(result.violations.join(), policy).toContain('object 3')
    }
  })

  it('uses the object-stream index from the xref (duplicate member numbers)', async () => {
    const signed = xrefStream(
      '%PDF-1.7\n',
      [
        [1, '<</Type/Catalog/Pages 2 0 R>>'],
        [2, '<</Type/Pages/Kids[3 0 R]/Count 1>>'],
        [3, '<</Type/Page/Parent 2 0 R/MediaBox[0 0 10 10]>>'],
      ],
      [[1, 1, -1, 0], [2, 1, -1, 0], [3, 1, -1, 0]],
      '/Root 1 0 R',
      21
    )
    const end = bin(signed).length
    const stm = objStm([
      [3, '<</Type/Page/Parent 2 0 R/MediaBox[0 0 99 99]>>'],
      [3, '<</Type/Page/Parent 2 0 R/MediaBox[0 0 10 10]>>'],
    ])
    const pdf = xrefStream(signed, [[23, stm]], [[23, 1, -1, 0], [3, 2, 23, 0]], '/Root 1 0 R', 24, lastXref(signed))
    const result = await analyse(pdf, end, 'signing')
    expect(result.violations.join()).toContain('object 3')
  })

  it('sees references split by comments', async () => {
    const pdf = classic(
      BASE,
      [
        [50, '<</Type/Annot/Subtype/FreeText/Rect[0 0 10 10]/Contents(x)>>'],
        [3, '<</Type/Page/Parent 2 0 R/Contents 4 0 R/MediaBox[0 0 10 10]/Annots[11 0 R 13 0 R 50%c\n0%c\nR]>>'],
      ],
      '/Size 51/Root 1 0 R',
      lastXref(BASE)
    )
    const result = await analyse(pdf, BASE_END, 'ltv')
    expect(result.violations.join()).toContain('50')
  })

  it('does not trust an annotation that merely calls itself a document timestamp', async () => {
    const pdf = classic(
      BASE,
      [
        [50, '<</Type/DocTimeStamp/Subtype/FreeText/Rect[0 0 10 10]/Contents(x)>>'],
        [3, '<</Type/Page/Parent 2 0 R/Contents 4 0 R/MediaBox[0 0 10 10]/Annots[11 0 R 13 0 R 50 0 R]>>'],
      ],
      '/Size 51/Root 1 0 R',
      lastXref(BASE)
    )
    expect((await analyse(pdf, BASE_END, 'ltv')).violations.length).toBeGreaterThan(0)
  })

  it('flags growth of an indirect /Contents array', async () => {
    const signed = classic(
      '%PDF-1.7\n',
      [
        [1, '<</Type/Catalog/Pages 2 0 R>>'],
        [2, '<</Type/Pages/Kids[3 0 R]/Count 1>>'],
        [3, '<</Type/Page/Parent 2 0 R/Contents 20 0 R>>'],
        [20, '[4 0 R]'],
        [4, CONTENT],
      ],
      '/Size 21/Root 1 0 R'
    )
    const end = enc(signed).length
    const pdf = classic(signed, [[21, '<</Type/DocTimeStamp/Length 9>>\nstream\nBT 2 Tj\nendstream'], [20, '[4 0 R 21 0 R]']], '/Size 22/Root 1 0 R', lastXref(signed))
    const result = await analyse(pdf, end, 'ltv')
    expect(result.violations.join()).toContain('object 20')
  })

  it('rejects a new signature field that carries no later signature', async () => {
    const pdf = classic(
      BASE,
      [
        [60, '<</Type/Annot/Subtype/Widget/FT/Sig/T(S2)/Rect[0 0 10 10]/AP<</N 61 0 R>>>>'],
        [61, '<</Type/XObject/Subtype/Form/BBox[0 0 10 10]/Length 9>>\nstream\nBT 9 Tj\nendstream'],
        [3, '<</Type/Page/Parent 2 0 R/Contents 4 0 R/MediaBox[0 0 10 10]/Annots[11 0 R 13 0 R 60 0 R]>>'],
        [5, '<</Fields[11 0 R 13 0 R 60 0 R]/DR<</Font<</Helv 30 0 R>>>>>>'],
      ],
      '/Size 62/Root 1 0 R',
      lastXref(BASE)
    )
    expect((await analyse(pdf, BASE_END, 'signing')).violations.length).toBeGreaterThan(0)
  })

  it('rejects a new signature field with actions even when signed', async () => {
    const pdf = classic(
      BASE,
      [
        [59, later(1)],
        [60, '<</Type/Annot/Subtype/Widget/FT/Sig/T(S2)/V 59 0 R/Rect[0 0 10 10]/AA<</O 62 0 R>>>>'],
        [62, '<</S/JavaScript/JS(app.alert(1))>>'],
        [3, '<</Type/Page/Parent 2 0 R/Contents 4 0 R/MediaBox[0 0 10 10]/Annots[11 0 R 13 0 R 60 0 R]>>'],
        [5, '<</Fields[11 0 R 13 0 R 60 0 R]/DR<</Font<</Helv 30 0 R>>>>>>'],
      ],
      '/Size 63/Root 1 0 R',
      lastXref(BASE)
    )
    expect((await analyse(pdf, BASE_END, 'signing')).violations.length).toBeGreaterThan(0)
  })

  it('treats unknown xref entry types as null (object removed)', async () => {
    const signed = xrefStream(
      '%PDF-1.7\n',
      [
        [1, '<</Type/Catalog/Pages 2 0 R>>'],
        [2, '<</Type/Pages/Kids[3 0 R]/Count 1>>'],
        [3, '<</Type/Page/Parent 2 0 R/Contents 4 0 R>>'],
        [4, CONTENT],
      ],
      [[1, 1, -1, 0], [2, 1, -1, 0], [3, 1, -1, 0], [4, 1, -1, 0]],
      '/Root 1 0 R',
      21
    )
    const end = bin(signed).length
    const pdf = xrefStream(signed, [], [[4, 3, 0, 0]], '/Root 1 0 R', 22, lastXref(signed))
    const result = await analyse(pdf, end, 'signing')
    expect(result.violations.join()).toContain('object 4')
  })

  it('flags a new object that fills a previously dangling reference', async () => {
    const signed = classic(
      '%PDF-1.7\n',
      [
        [1, '<</Type/Catalog/Pages 2 0 R>>'],
        [2, '<</Type/Pages/Kids[3 0 R]/Count 1>>'],
        [3, '<</Type/Page/Parent 2 0 R/Annots[40 0 R]>>'],
      ],
      '/Size 4/Root 1 0 R'
    )
    const end = enc(signed).length
    const pdf = classic(signed, [[40, '<</Type/Annot/Subtype/FreeText/Rect[0 0 5 5]/Contents(x)>>']], '/Size 41/Root 1 0 R', lastXref(signed))
    const result = await analyse(pdf, end, 'annotations')
    expect(result.violations.join()).toContain('new object 40')
  })

  it('flags a font swapped in /DR but accepts an added font', async () => {
    const swap = classic(BASE, [[31, '<</Type/Font/Subtype/Type1/BaseFont/Courier>>'], [5, '<</Fields[11 0 R 13 0 R]/DR<</Font<</Helv 31 0 R>>>>>>']], '/Size 32/Root 1 0 R', lastXref(BASE))
    expect((await analyse(swap, BASE_END, 'signing')).violations.join()).toContain('/DR')
    const add = classic(BASE, [[31, '<</Type/Font/Subtype/Type1/BaseFont/Courier>>'], [5, '<</Fields[11 0 R 13 0 R]/DR<</Font<</Helv 30 0 R/Cour 31 0 R>>>>>>']], '/Size 32/Root 1 0 R', lastXref(BASE))
    expect((await analyse(add, BASE_END, 'signing')).violations).toEqual([])
  })
})

describe('change detection — legitimate updates are not flagged', () => {
  it('signing a pre-existing empty signature field (P2) is permitted; under P1 it is not', async () => {
    const pdf = classic(
      BASE,
      [
        [59, later(1)],
        [61, '<</Type/XObject/Subtype/Form/BBox[0 0 10 10]/Length 9>>\nstream\nBT 9 Tj\nendstream'],
        [11, '<</Type/Annot/Subtype/Widget/FT/Sig/T(Empty)/Rect[0 0 0 0]/P 3 0 R/V 59 0 R/AP<</N 61 0 R>>>>'],
      ],
      '/Size 62/Root 1 0 R',
      lastXref(BASE)
    )
    expect((await analyse(pdf, BASE_END, 'signing')).violations).toEqual([])
    expect((await analyse(pdf, BASE_END, 'ltv')).violations.length).toBeGreaterThan(0)
  })

  it('a document timestamp in a pre-existing field is permitted under P1', async () => {
    const pdf = classic(BASE, [[59, later(2)], [11, '<</Type/Annot/Subtype/Widget/FT/Sig/T(Empty)/Rect[0 0 0 0]/P 3 0 R/V 59 0 R>>']], '/Size 60/Root 1 0 R', lastXref(BASE))
    expect((await analyse(pdf, BASE_END, 'ltv')).violations).toEqual([])
  })

  it('form fill-in (value and appearance) is permitted under P2 but not under P1', async () => {
    const pdf = classic(
      BASE,
      [
        [62, '<</Type/XObject/Subtype/Form/BBox[0 0 5 5]/Length 9>>\nstream\nBT 7 Tj\nendstream'],
        [13, '<</Type/Annot/Subtype/Widget/FT/Tx/T(Name)/V(b)/Rect[0 0 5 5]/P 3 0 R/AP<</N 62 0 R>>>>'],
      ],
      '/Size 63/Root 1 0 R',
      lastXref(BASE)
    )
    expect((await analyse(pdf, BASE_END, 'signing')).violations).toEqual([])
    expect((await analyse(pdf, BASE_END, 'ltv')).violations.length).toBeGreaterThan(0)
  })

  it('/Annots moving from inline to a new indirect array with a signed widget is permitted', async () => {
    const pdf = classic(
      BASE,
      [
        [59, later(1)],
        [60, '<</Type/Annot/Subtype/Widget/FT/Sig/T(S2)/V 59 0 R/Rect[0 0 0 0]/P 3 0 R>>'],
        [64, '[11 0 R 13 0 R 60 0 R]'],
        [3, '<</Type/Page/Parent 2 0 R/Contents 4 0 R/MediaBox[0 0 10 10]/Annots 64 0 R>>'],
        [5, '<</Fields[11 0 R 13 0 R 60 0 R]/DR<</Font<</Helv 30 0 R>>>>>>'],
      ],
      '/Size 65/Root 1 0 R',
      lastXref(BASE)
    )
    expect((await analyse(pdf, BASE_END, 'signing')).violations).toEqual([])
  })
})

describe('change detection — ambiguous cross-reference data', () => {
  it('refuses an xref section that lists the same object twice', async () => {
    const evil = '3 5 obj\n<</Type/Page/Parent 2 0 R/Contents 4 0 R/MediaBox[0 0 1 1]>>\nendobj\n'
    const base = BASE + evil
    const xrefAt = base.length
    const pdf =
      base +
      `xref\n3 1\n${String(BASE.length).padStart(10, '0')} 00005 n \n3 1\n${String(BASE.indexOf('3 0 obj')).padStart(10, '0')} 00000 n \n` +
      `trailer\n<</Size 31/Root 1 0 R/Prev ${lastXref(BASE)}>>\nstartxref\n${xrefAt}\n%%EOF\n`
    const result = await analyse(pdf, BASE_END, 'signing')
    expect(result.analysable).toBe(false)
  })
})
