import type { PdfSignatureField, EmbeddedRevocationInfo } from '@/types'
import { extractSignaturesFromRaw, extractDss } from './signature-extractor'

export interface PdfDocument {
  data: Uint8Array
  numPages: number
  signatureFields: PdfSignatureField[]
  dssRevocationInfo: EmbeddedRevocationInfo | null
}

export interface ParseOptions {
  extractSignatures?: boolean
}

/**
 * Parse PDF and extract signature fields
 * Uses custom parser to avoid PDF.js worker issues in extension environment
 */
export async function parsePdf(
  data: ArrayBuffer | Uint8Array,
  options: ParseOptions = {}
): Promise<PdfDocument> {
  const { extractSignatures = true } = options
  const uint8Data = data instanceof Uint8Array ? data : new Uint8Array(data)

  let signatureFields: PdfSignatureField[] = []

  if (extractSignatures) {
    signatureFields = extractSignaturesFromRaw(uint8Data)
  }

  // Extract DSS (Document Security Store) for LTV verification
  const dssRevocationInfo = await extractDss(uint8Data)

  // Count pages by searching for /Type /Page
  const numPages = countPages(uint8Data)

  return {
    data: uint8Data,
    numPages,
    signatureFields,
    dssRevocationInfo,
  }
}

/**
 * Count pages in PDF by searching for page objects
 */
function countPages(data: Uint8Array): number {
  const text = new TextDecoder('latin1').decode(data)

  // Look for /Type /Page (not /Pages)
  const pageMatches = text.match(/\/Type\s*\/Page[^s]/g)

  if (pageMatches) {
    return pageMatches.length
  }

  // Fallback: look for /Count in /Pages object
  const countMatch = text.match(/\/Pages[^>]*\/Count\s+(\d+)/)
  if (countMatch) {
    return parseInt(countMatch[1], 10)
  }

  return 1
}
