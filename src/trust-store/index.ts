export {
  TAIWAN_ROOT_CERTIFICATES,
  TAIWAN_INTERMEDIATE_CERTIFICATES,
  getAllRootCertificates,
  getRootCertificateNames,
  hasAnyEmbeddedPem,
  getPopulatedEntries,
} from './taiwan-roots'
export type { TrustAnchorEntry, TrustCategory, TrustUsage } from './taiwan-roots'
export { INTERNATIONAL_ROOT_CERTIFICATES, getInternationalVendors } from './international-roots'

export {
  TAIWAN_TSA_ROOT_CERTIFICATES,
  getPopulatedTsaEntries,
  hasAnyEmbeddedTsaPem,
} from './taiwan-tsa-roots'

export {
  initializeTrustStore,
  getTrustAnchors,
  getTsaTrustAnchors,
  getKnownIntermediates,
  getKnownRoots,
  getAnchorVendor,
  isTrustAnchor,
  isTsaTrustAnchor,
  findTrustAnchor,
  getAnchorCategory,
  getTrustAnchorInfo,
  addCustomTrustAnchor,
  addCustomTsaTrustAnchor,
  clearTrustAnchors,
  getTrustStoreStats,
  getTrustStoreWarnings,
  isTrustStoreEmpty,
  isTsaTrustStoreEmpty,
} from './trust-manager'
