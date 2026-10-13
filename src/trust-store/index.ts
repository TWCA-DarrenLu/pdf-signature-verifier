export {
  TAIWAN_ROOT_CERTIFICATES,
  TAIWAN_INTERMEDIATE_CERTIFICATES,
  getAllRootCertificates,
  getRootCertificateNames,
  hasAnyEmbeddedPem,
  getPopulatedEntries,
} from './taiwan-roots'
export type { TrustAnchorEntry, TrustCategory } from './taiwan-roots'

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
