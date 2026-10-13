import { describe, it, expect } from 'vitest'
import { createChangeAnalyzer, parseTopLevelDict } from '@/core/pdf/incremental-update'
import { extractSignaturesFromRaw } from '@/core/pdf/signature-extractor'

const enc = (s: string) => new TextEncoder().encode(s)
type Obj = [number, string]

/** Append a revision (objects + classic xref + trailer) to `base`. */
function revision(base: string, objects: Obj[], trailer: string, prev?: number): string {
  let out = base
  const offsets: Array<[number, number]> = []
  for (const [num, body] of objects) {
    offsets.push([num, out.length])
    out += `${num} 0 obj\n${body}\nendobj\n`
  }
  const xrefAt = out.length
  out += 'xref\n'
  for (const [num, off] of offsets.sort((a, b) => a[0] - b[0])) {
    out += `${num} 1\n${String(off).padStart(10, '0')} 00000 n \n`
  }
  out += `trailer\n<<${trailer}${prev !== undefined ? `/Prev ${prev}` : ''}>>\nstartxref\n${xrefAt}\n%%EOF\n`
  return out
}

function lastXref(pdf: string): number {
  return Number(/startxref\s+(\d+)\s*%%EOF\s*$/.exec(pdf)![1])
}

const PAGE_CONTENT = '<</Length 9>>\nstream\nBT 1 Tj\nendstream'

/** Signed revision: catalog 1, pages 2, page 3 (content 4), AcroForm 5. */
const SIGNED = revision(
  '%PDF-1.7\n',
  [
    [1, '<</Type/Catalog/Pages 2 0 R/AcroForm 5 0 R>>'],
    [2, '<</Type/Pages/Kids[3 0 R]/Count 1>>'],
    [3, '<</Type/Page/Parent 2 0 R/Contents 4 0 R/MediaBox[0 0 10 10]>>'],
    [4, PAGE_CONTENT],
    [5, '<</Fields[]>>'],
  ],
  '/Size 6/Root 1 0 R'
)
const END = enc(SIGNED).length

function update(objects: Obj[], trailer = '/Size 20/Root 1 0 R'): Uint8Array {
  return enc(revision(SIGNED, objects, trailer, lastXref(SIGNED)))
}

describe('createChangeAnalyzer — revision diff', () => {
  it('reports no changes when nothing follows the signed revision', async () => {
    const result = await createChangeAnalyzer(enc(SIGNED + '\n')).changesSince(END, 'signing')
    expect(result).toMatchObject({ hasChanges: false })
  })

  it('accepts an LTV update (new DSS objects, catalog adds /DSS)', async () => {
    const pdf = update([
      [6, '<</Length 3>>\nstream\nabc\nendstream'],
      [7, '<</Type/DSS/CRLs[6 0 R]>>'],
      [1, '<</Type/Catalog/Pages 2 0 R/AcroForm 5 0 R/DSS 7 0 R/Extensions<</ADBE<</BaseVersion/1.7>>>>>>'],
    ])
    for (const policy of ['ltv', 'signing'] as const) {
      const result = await createChangeAnalyzer(pdf).changesSince(END, policy)
      expect(result.violations).toEqual([])
      expect(result.analysable).toBe(true)
    }
  })

  it('flags a rewritten content stream', async () => {
    const result = await createChangeAnalyzer(update([[4, '<</Length 9>>\nstream\nBT 2 Tj\nendstream']])).changesSince(END, 'signing')
    expect(result.violations.join()).toContain('object 4')
  })

  it('flags a rewrite hidden behind a comment in the object header', async () => {
    const tail = '4 0 %hidden\nobj\n<</Length 9>>\nstream\nBT 2 Tj\nendstream\nendobj\n'
    const base = SIGNED + tail
    const xrefAt = base.length
    const pdf =
      base +
      `xref\n4 1\n${String(SIGNED.length).padStart(10, '0')} 00000 n \ntrailer\n<</Size 6/Root 1 0 R/Prev ${lastXref(SIGNED)}>>\nstartxref\n${xrefAt}\n%%EOF\n`
    const result = await createChangeAnalyzer(enc(pdf)).changesSince(END, 'signing')
    expect(result.violations.join()).toContain('object 4')
  })

  it('flags an xref entry pointing back to an older definition', async () => {
    // Revision 0 has the old page content; revision 1 (signed) replaces it.
    const rev0 = revision('%PDF-1.7\n', [
      [1, '<</Type/Catalog/Pages 2 0 R>>'],
      [2, '<</Type/Pages/Kids[3 0 R]/Count 1>>'],
      [3, '<</Type/Page/Parent 2 0 R/Contents 4 0 R>>'],
      [4, '<</Length 9>>\nstream\nBT 0 Tj\nendstream'],
    ], '/Size 5/Root 1 0 R')
    const oldContentOffset = rev0.indexOf('4 0 obj')
    const signed = revision(rev0, [[4, PAGE_CONTENT]], '/Size 5/Root 1 0 R', lastXref(rev0))
    const end = enc(signed).length
    const xrefAt = signed.length
    const pdf =
      signed +
      `xref\n4 1\n${String(oldContentOffset).padStart(10, '0')} 00000 n \ntrailer\n<</Size 5/Root 1 0 R/Prev ${lastXref(signed)}>>\nstartxref\n${xrefAt}\n%%EOF\n`
    const result = await createChangeAnalyzer(enc(pdf)).changesSince(end, 'signing')
    expect(result.violations.join()).toContain('object 4')
  })

  it('flags a re-pointed trailer /Root', async () => {
    const pdf = update(
      [
        [9, '<</Type/Catalog/Pages 10 0 R>>'],
        [10, '<</Type/Pages/Kids[]/Count 0>>'],
      ],
      '/Size 20/Root 9 0 R'
    )
    const result = await createChangeAnalyzer(pdf).changesSince(END, 'signing')
    expect(result.violations.join()).toContain('/Root')
  })

  it('flags a catalog change beyond LTV keys (/OpenAction)', async () => {
    const pdf = update([
      [8, '<</S/JavaScript/JS(app.alert(1))>>'],
      [1, '<</Type/Catalog/Pages 2 0 R/AcroForm 5 0 R/OpenAction 8 0 R>>'],
    ])
    const result = await createChangeAnalyzer(pdf).changesSince(END, 'signing')
    expect(result.violations.join()).toContain('/OpenAction')
  })

  const signatureUpdate = (vType: 'Sig' | 'DocTimeStamp'): Obj[] => [
    // A later signature: its ByteRange covers the revision that adds it.
    [10, `<</Type/${vType}/Filter/Adobe.PPKLite/Contents<00>/ByteRange[0 1 2 ${END + 500}]>>`],
    [11, '<</Type/Annot/Subtype/Widget/FT/Sig/T(S1)/V 10 0 R/Rect[0 0 0 0]/P 3 0 R/AP<</N 12 0 R>>>>'],
    [12, '<</Type/XObject/Subtype/Form/BBox[0 0 0 0]/Length 0>>\nstream\n\nendstream'],
    [3, '<</Type/Page/Parent 2 0 R/Contents 4 0 R/MediaBox[0 0 10 10]/Annots[11 0 R]>>'],
    [5, '<</Fields[11 0 R]/SigFlags 3>>'],
  ]

  it('permits adding a signature field (P2 / no DocMDP)', async () => {
    const result = await createChangeAnalyzer(update(signatureUpdate('Sig'))).changesSince(END, 'signing')
    expect(result.violations).toEqual([])
  })

  it('rejects an approval signature under DocMDP P1 but permits a document timestamp', async () => {
    const approval = await createChangeAnalyzer(update(signatureUpdate('Sig'))).changesSince(END, 'ltv')
    expect(approval.violations.length).toBeGreaterThan(0)
    const docTs = await createChangeAnalyzer(update(signatureUpdate('DocTimeStamp'))).changesSince(END, 'ltv')
    expect(docTs.violations).toEqual([])
  })

  it('permits new annotations only under DocMDP P3', async () => {
    const objects: Obj[] = [
      [13, '<</Type/Annot/Subtype/FreeText/Rect[0 0 5 5]/Contents(covered)>>'],
      [3, '<</Type/Page/Parent 2 0 R/Contents 4 0 R/MediaBox[0 0 10 10]/Annots[13 0 R]>>'],
    ]
    expect((await createChangeAnalyzer(update(objects)).changesSince(END, 'signing')).violations.length).toBeGreaterThan(0)
    expect((await createChangeAnalyzer(update(objects)).changesSince(END, 'annotations')).violations).toEqual([])
  })

  it('flags page keys other than /Annots', async () => {
    const pdf = update([[3, '<</Type/Page/Parent 2 0 R/Contents 4 0 R/MediaBox[0 0 20 20]>>']])
    const result = await createChangeAnalyzer(pdf).changesSince(END, 'annotations')
    expect(result.violations.join()).toContain('/MediaBox')
  })

  it('reports unreadable cross-reference data as not analysable', async () => {
    const result = await createChangeAnalyzer(enc(SIGNED + 'garbage after the signed revision')).changesSince(END, 'signing')
    expect(result.analysable).toBe(false)
  })
})

describe('parseTopLevelDict', () => {
  it('splits keys and nested values', () => {
    const d = parseTopLevelDict('<</A 1 0 R/B<</C [1 2]>>/D(x\\)y)/E/Name/F [<</G 1>>]>>')!
    expect([...d.keys()]).toEqual(['A', 'B', 'D', 'E', 'F'])
    expect(d.get('A')).toBe('1 0 R')
    expect(d.get('D')).toBe('(x\\)y)')
  })
})

describe('extractSignaturesFromRaw', () => {
  it('ignores signature dictionaries inside stream data (attached PDFs)', () => {
    const attached = '9 0 obj <</Type/Sig/ByteRange [0 10 20 5]/Contents <3000>>> endobj'
    const pdf = [
      '%PDF-1.7',
      `5 0 obj <</Type/EmbeddedFile/Length ${enc(attached).length}>> stream`,
      attached,
      'endstream endobj',
      '%%EOF',
    ].join('\n')
    expect(extractSignaturesFromRaw(enc(pdf))).toHaveLength(0)
  })
})
