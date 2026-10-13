import { describe, it, expect, vi } from 'vitest'
import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'

// Mock cert-utils to avoid real certificate parsing
vi.mock('@/core/certificate/cert-utils', () => ({
  parseCertificate: vi.fn(async (cert: unknown) => ({
    raw: cert,
    subject: 'CN=Test Signer',
    issuer: 'CN=Test CA',
    serialNumber: 'abc123',
    notBefore: new Date('2024-01-01'),
    notAfter: new Date('2025-12-31'),
    publicKey: null,
    fingerprint: 'deadbeef',
    isCA: false,
    isSelfSigned: false,
    keyUsage: {
      digitalSignature: true,
      nonRepudiation: false,
      keyEncipherment: false,
      dataEncipherment: false,
      keyAgreement: false,
      keyCertSign: false,
      crlSign: false,
      encipherOnly: false,
      decipherOnly: false,
    },
    extKeyUsage: [],
    authorityInfoAccess: null,
    crlDistributionPoints: [],
    subjectKeyIdentifier: null,
    authorityKeyIdentifier: null,
  })),
}))

// Mock i18n
vi.mock('@/i18n', () => ({
  t: (key: string) => key,
}))

describe('pkcs7-parser', () => {
  describe('parsePkcs7', () => {
    it('should throw for invalid ASN.1 data', async () => {
      const { parsePkcs7 } = await import('@/core/crypto/pkcs7-parser')
      const invalidData = new Uint8Array([0x00, 0x01, 0x02])

      await expect(parsePkcs7(invalidData)).rejects.toThrow()
    })

    it('should throw for non-SignedData content type', async () => {
      const { parsePkcs7 } = await import('@/core/crypto/pkcs7-parser')

      // Build a minimal ContentInfo with Data OID (not SignedData) using raw ASN.1
      // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
      const oid = new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }) // Data OID
      const content = new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [new asn1js.OctetString({ valueHex: new ArrayBuffer(4) })],
      })
      const seq = new asn1js.Sequence({ value: [oid, content] })
      const encoded = seq.toBER()
      const data = new Uint8Array(encoded)

      await expect(parsePkcs7(data)).rejects.toThrow('Expected SignedData OID')
    })

    it('should throw for empty/zero-length data', async () => {
      const { parsePkcs7 } = await import('@/core/crypto/pkcs7-parser')
      const emptyData = new Uint8Array(0)

      await expect(parsePkcs7(emptyData)).rejects.toThrow()
    })

    it('should throw for truncated ASN.1 data', async () => {
      const { parsePkcs7 } = await import('@/core/crypto/pkcs7-parser')
      // A valid DER tag+length prefix but truncated content
      const truncated = new Uint8Array([0x30, 0x80, 0x06, 0x09])

      await expect(parsePkcs7(truncated)).rejects.toThrow()
    })

    it('should throw for random noise data', async () => {
      const { parsePkcs7 } = await import('@/core/crypto/pkcs7-parser')
      const noise = new Uint8Array(256)
      for (let i = 0; i < noise.length; i++) {
        noise[i] = Math.floor(Math.random() * 256)
      }

      await expect(parsePkcs7(noise)).rejects.toThrow()
    })
  })

  describe('adbe-revocationInfoArchival', () => {
    // RevocationInfoArchival ::= SEQUENCE { crl [0] ..., ocsp [1] EXPLICIT SEQUENCE OF OCSPResponse, ... }
    const archivalAttribute = () =>
      new pkijs.Attribute({
        type: '1.2.840.113583.1.1.8',
        values: [
          new asn1js.Sequence({
            value: [
              new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 1 },
                value: [new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [new asn1js.Enumerated({ value: 0 })] })] })],
              }),
            ],
          }),
        ],
      })

    const encodeWith = (placement: 'signed' | 'unsigned') => {
      const contentType = new pkijs.Attribute({
        type: '1.2.840.113549.1.9.3',
        values: [new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' })],
      })
      const signerInfo = new pkijs.SignerInfo({
        version: 1,
        sid: new pkijs.IssuerAndSerialNumber({
          issuer: new pkijs.RelativeDistinguishedNames(),
          serialNumber: new asn1js.Integer({ value: 1 }),
        }),
        digestAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: '2.16.840.1.101.3.4.2.1' }),
        signatureAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.11' }),
        signature: new asn1js.OctetString({ valueHex: new ArrayBuffer(32) }),
        signedAttrs: new pkijs.SignedAndUnsignedAttributes({
          type: 0,
          attributes: placement === 'signed' ? [contentType, archivalAttribute()] : [contentType],
        }),
        ...(placement === 'unsigned'
          ? { unsignedAttrs: new pkijs.SignedAndUnsignedAttributes({ type: 1, attributes: [archivalAttribute()] }) }
          : {}),
      })
      const signedData = new pkijs.SignedData({
        version: 1,
        encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: '1.2.840.113549.1.7.1' }),
        signerInfos: [signerInfo],
      })
      const contentInfo = new pkijs.ContentInfo({
        contentType: '1.2.840.113549.1.7.2',
        content: signedData.toSchema(true),
      })
      return new Uint8Array(contentInfo.toSchema().toBER())
    }

    // Acrobat and TWCA signing services put it in the SIGNED attributes (ISO 32000-1 12.8.3.3.2)
    it.each(['signed', 'unsigned'] as const)('reads embedded OCSP responses from %s attributes', async (placement) => {
      const { parsePkcs7 } = await import('@/core/crypto/pkcs7-parser')
      const parsed = await parsePkcs7(encodeWith(placement))
      expect(parsed.embeddedRevocationInfo?.ocspResponses).toHaveLength(1)
    })
  })

  describe('getSignedAttributesData', () => {
    it('should return null when signer has no signed attributes', async () => {
      const { getSignedAttributesData } = await import('@/core/crypto/pkcs7-parser')

      const signedData = new pkijs.SignedData({
        version: 1,
        encapContentInfo: new pkijs.EncapsulatedContentInfo({
          eContentType: '1.2.840.113549.1.7.1',
        }),
        signerInfos: [
          new pkijs.SignerInfo({
            version: 1,
            sid: new pkijs.IssuerAndSerialNumber({
              issuer: new pkijs.RelativeDistinguishedNames(),
              serialNumber: new asn1js.Integer({ value: 1 }),
            }),
            digestAlgorithm: new pkijs.AlgorithmIdentifier({
              algorithmId: '2.16.840.1.101.3.4.2.1',
            }),
            signatureAlgorithm: new pkijs.AlgorithmIdentifier({
              algorithmId: '1.2.840.113549.1.1.11',
            }),
            signature: new asn1js.OctetString({ valueHex: new ArrayBuffer(32) }),
          }),
        ],
      })

      const result = getSignedAttributesData(signedData, 0)
      expect(result).toBeNull()
    })

    it('should return null for out-of-bounds signer index', async () => {
      const { getSignedAttributesData } = await import('@/core/crypto/pkcs7-parser')

      const signedData = new pkijs.SignedData({
        version: 1,
        encapContentInfo: new pkijs.EncapsulatedContentInfo({
          eContentType: '1.2.840.113549.1.7.1',
        }),
        signerInfos: [],
      })

      const result = getSignedAttributesData(signedData, 5)
      expect(result).toBeNull()
    })

    it('should return Uint8Array with SET tag (0x31) when signed attributes exist', async () => {
      const { getSignedAttributesData } = await import('@/core/crypto/pkcs7-parser')

      const signedAttrs = new pkijs.SignedAndUnsignedAttributes({
        type: 0,
        attributes: [
          new pkijs.Attribute({
            type: '1.2.840.113549.1.9.3', // contentType
            values: [new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' })],
          }),
        ],
      })

      const signerInfo = new pkijs.SignerInfo({
        version: 1,
        sid: new pkijs.IssuerAndSerialNumber({
          issuer: new pkijs.RelativeDistinguishedNames(),
          serialNumber: new asn1js.Integer({ value: 1 }),
        }),
        digestAlgorithm: new pkijs.AlgorithmIdentifier({
          algorithmId: '2.16.840.1.101.3.4.2.1',
        }),
        signatureAlgorithm: new pkijs.AlgorithmIdentifier({
          algorithmId: '1.2.840.113549.1.1.11',
        }),
        signature: new asn1js.OctetString({ valueHex: new ArrayBuffer(32) }),
        signedAttrs,
      })

      const signedData = new pkijs.SignedData({
        version: 1,
        encapContentInfo: new pkijs.EncapsulatedContentInfo({
          eContentType: '1.2.840.113549.1.7.1',
        }),
        signerInfos: [signerInfo],
      })

      const result = getSignedAttributesData(signedData, 0)
      expect(result).toBeInstanceOf(Uint8Array)
      expect(result![0]).toBe(0x31) // SET tag
    })

    it('should handle empty signerInfos array', async () => {
      const { getSignedAttributesData } = await import('@/core/crypto/pkcs7-parser')

      const signedData = new pkijs.SignedData({
        version: 1,
        encapContentInfo: new pkijs.EncapsulatedContentInfo({
          eContentType: '1.2.840.113549.1.7.1',
        }),
        signerInfos: [],
      })

      const result = getSignedAttributesData(signedData, 0)
      expect(result).toBeNull()
    })
  })
})
