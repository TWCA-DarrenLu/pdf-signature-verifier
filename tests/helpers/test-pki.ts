/**
 * Minimal test PKI: generates throw-away ECDSA P-256 certificates so path
 * building, trust anchoring and constraint checks can be unit-tested with
 * real signatures. Generic "Test …" names only.
 */
import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import type { ParsedCertificate } from '@/types'
import { parseCertificate, derToPem } from '@/core/certificate/cert-utils'
import { ensurePkijsEngine } from '@/core/crypto/pkijs-engine'

export interface TestKey {
  privateKey: CryptoKey
  publicKey: CryptoKey
}

export interface TestCertOptions {
  subjectCN: string
  issuerCN?: string
  /** CRL distribution point URL. */
  crlUrl?: string
  /** Defaults to the subject's own key (self-signed). */
  issuerKey?: TestKey
  serial?: number
  isCA?: boolean
  pathLen?: number
  keyCertSign?: boolean
  extKeyUsage?: string[]
  notBefore?: Date
  notAfter?: Date
}

export interface TestCert {
  key: TestKey
  cert: pkijs.Certificate
  parsed: ParsedCertificate
  pem: string
}

export async function generateKey(): Promise<TestKey> {
  ensurePkijsEngine()
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return { privateKey: pair.privateKey, publicKey: pair.publicKey }
}

function name(cn: string): pkijs.RelativeDistinguishedNames {
  return new pkijs.RelativeDistinguishedNames({
    typesAndValues: [
      new pkijs.AttributeTypeAndValue({ type: '2.5.4.6', value: new asn1js.PrintableString({ value: 'TW' }) }),
      new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.Utf8String({ value: cn }) }),
    ],
  })
}

export async function issueCertificate(opts: TestCertOptions, key?: TestKey): Promise<TestCert> {
  ensurePkijsEngine()
  const subjectKey = key ?? (await generateKey())
  const issuerKey = opts.issuerKey ?? subjectKey
  const cert = new pkijs.Certificate()
  cert.version = 2
  cert.serialNumber = new asn1js.Integer({ value: opts.serial ?? Math.floor(Math.random() * 1e9) })
  cert.subject = name(opts.subjectCN)
  cert.issuer = name(opts.issuerCN ?? opts.subjectCN)
  cert.notBefore.value = opts.notBefore ?? new Date(Date.now() - 86_400_000)
  cert.notAfter.value = opts.notAfter ?? new Date(Date.now() + 365 * 86_400_000)
  await cert.subjectPublicKeyInfo.importKey(subjectKey.publicKey)

  const extensions: pkijs.Extension[] = []
  const isCA = opts.isCA ?? false
  extensions.push(
    new pkijs.Extension({
      extnID: '2.5.29.19',
      critical: true,
      extnValue: new pkijs.BasicConstraints({ cA: isCA, pathLenConstraint: opts.pathLen }).toSchema().toBER(false),
    })
  )
  // keyUsage: digitalSignature (bit 0) for leaves, keyCertSign|cRLSign (bits 5,6) for CAs
  const keyCertSign = opts.keyCertSign ?? isCA
  const kuByte = (isCA ? 0 : 0x80) | (keyCertSign ? 0x04 : 0) | (isCA ? 0x02 : 0)
  extensions.push(
    new pkijs.Extension({
      extnID: '2.5.29.15',
      critical: true,
      extnValue: new asn1js.BitString({ valueHex: new Uint8Array([kuByte]).buffer, unusedBits: 1 }).toBER(false),
    })
  )
  if (opts.extKeyUsage?.length) {
    extensions.push(
      new pkijs.Extension({
        extnID: '2.5.29.37',
        critical: true,
        extnValue: new pkijs.ExtKeyUsage({ keyPurposes: opts.extKeyUsage }).toSchema().toBER(false),
      })
    )
  }
  if (opts.crlUrl) {
    const cdp = new pkijs.CRLDistributionPoints({
      distributionPoints: [
        new pkijs.DistributionPoint({ distributionPoint: [new pkijs.GeneralName({ type: 6, value: opts.crlUrl })] }),
      ],
    })
    extensions.push(new pkijs.Extension({ extnID: '2.5.29.31', extnValue: cdp.toSchema().toBER(false) }))
  }
  cert.extensions = extensions

  await cert.sign(issuerKey.privateKey, 'SHA-256')
  const parsed = await parseCertificate(cert)
  return { key: subjectKey, cert, parsed, pem: derToPem(new Uint8Array(cert.toSchema().toBER(false))) }
}

/**
 * CRL signed by `issuer`. `idpUri` adds a critical IssuingDistributionPoint,
 * `delta` a deltaCRLIndicator.
 */
export async function issueCrl(opts: {
  issuer: TestCert
  revokedSerials?: number[]
  revokedAt?: Date
  /** CRLReason code for revoked entries (e.g. 6 = certificateHold). */
  reason?: number
  thisUpdate?: Date
  nextUpdate?: Date | null
  idpUri?: string
  delta?: boolean
}): Promise<Uint8Array> {
  ensurePkijsEngine()
  const crl = new pkijs.CertificateRevocationList()
  crl.version = 1
  crl.issuer = opts.issuer.cert.subject
  crl.thisUpdate = new pkijs.Time({ type: 0, value: opts.thisUpdate ?? new Date(Date.now() - 3_600_000) })
  if (opts.nextUpdate !== null) {
    crl.nextUpdate = new pkijs.Time({ type: 0, value: opts.nextUpdate ?? new Date(Date.now() + 86_400_000) })
  }
  if (opts.revokedSerials?.length) {
    crl.revokedCertificates = opts.revokedSerials.map(
      (serial) =>
        new pkijs.RevokedCertificate({
          userCertificate: new asn1js.Integer({ value: serial }),
          revocationDate: new pkijs.Time({ type: 0, value: opts.revokedAt ?? new Date(Date.now() - 7_200_000) }),
          // pkijs serialises a present-but-undefined member, so only set it when used.
          ...(opts.reason === undefined
            ? {}
            : {
                crlEntryExtensions: new pkijs.Extensions({
                  extensions: [
                    new pkijs.Extension({
                      extnID: '2.5.29.21',
                      extnValue: new asn1js.Enumerated({ value: opts.reason }).toBER(false),
                    }),
                  ],
                }),
              }),
        })
    )
  }
  const extensions: pkijs.Extension[] = []
  if (opts.idpUri) {
    const idp = new pkijs.IssuingDistributionPoint({
      distributionPoint: [new pkijs.GeneralName({ type: 6, value: opts.idpUri })],
    })
    extensions.push(new pkijs.Extension({ extnID: '2.5.29.28', critical: true, extnValue: idp.toSchema().toBER(false) }))
  }
  if (opts.delta) {
    extensions.push(
      new pkijs.Extension({ extnID: '2.5.29.27', critical: true, extnValue: new asn1js.Integer({ value: 1 }).toBER(false) })
    )
  }
  if (extensions.length) crl.crlExtensions = new pkijs.Extensions({ extensions })
  await crl.sign(opts.issuer.key.privateKey, 'SHA-256')
  return new Uint8Array(crl.toSchema(true).toBER(false))
}

/**
 * RFC 3161 timestamp token over `imprint` (SHA-256), signed by `tsa`.
 * `tamperAfterSigning` swaps the TSTInfo after the signature was made.
 */
export async function issueTimestampToken(opts: {
  tsa: TestCert
  imprint: Uint8Array
  bag: pkijs.Certificate[]
  genTime?: Date
  tamperAfterSigning?: boolean
  /** messageImprint hash algorithm OID (default SHA-256). */
  hashOid?: string
}): Promise<Uint8Array> {
  ensurePkijsEngine()
  const tstInfo = (time: Date) =>
    new pkijs.TSTInfo({
      version: 1,
      policy: '1.2.3.4.1',
      messageImprint: new pkijs.MessageImprint({
        hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: opts.hashOid ?? '2.16.840.1.101.3.4.2.1' }),
        hashedMessage: new asn1js.OctetString({ valueHex: opts.imprint.slice().buffer }),
      }),
      serialNumber: new asn1js.Integer({ value: 1 }),
      genTime: time,
    })
  const genTime = opts.genTime ?? new Date()
  const content = tstInfo(genTime).toSchema().toBER(false)

  const signedData = new pkijs.SignedData({
    version: 3,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: '1.2.840.113549.1.9.16.1.4',
      eContent: new asn1js.OctetString({ valueHex: content }),
    }),
    signerInfos: [
      new pkijs.SignerInfo({
        version: 1,
        sid: new pkijs.IssuerAndSerialNumber({
          issuer: opts.tsa.cert.issuer,
          serialNumber: opts.tsa.cert.serialNumber,
        }),
      }),
    ],
    certificates: opts.bag,
  })
  const digest = await crypto.subtle.digest('SHA-256', content)
  signedData.signerInfos[0].signedAttrs = new pkijs.SignedAndUnsignedAttributes({
    type: 0,
    attributes: [
      new pkijs.Attribute({
        type: '1.2.840.113549.1.9.3',
        values: [new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.9.16.1.4' })],
      }),
      new pkijs.Attribute({ type: '1.2.840.113549.1.9.4', values: [new asn1js.OctetString({ valueHex: digest })] }),
    ],
  })
  await signedData.sign(opts.tsa.key.privateKey, 0, 'SHA-256')

  if (opts.tamperAfterSigning) {
    signedData.encapContentInfo.eContent = new asn1js.OctetString({
      valueHex: tstInfo(new Date(genTime.getTime() - 365 * 86_400_000)).toSchema().toBER(false),
    })
  }

  const contentInfo = new pkijs.ContentInfo({ contentType: '1.2.840.113549.1.7.2', content: signedData.toSchema(true) })
  return new Uint8Array(contentInfo.toSchema().toBER(false))
}
