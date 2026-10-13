/**
 * Taiwan Time Stamp Authority (TSA) trust anchors.
 *
 * Taiwan TSAs (TWCA, Chunghwa Telecom, GRCA-based government TSAs) chain to
 * the same physical roots as the signing CAs, so the TSA store holds the same
 * Taiwan roots. Trust is still a separate decision: a timestamp is accepted
 * only when
 *   - the TSA certificate carries the id-kp-timeStamping extended key usage, and
 *   - its path is cryptographically verified up to an anchor in THIS store.
 */
import { TAIWAN_ROOT_CERTIFICATES, type TrustAnchorEntry } from './taiwan-roots'

export const TAIWAN_TSA_ROOT_CERTIFICATES: TrustAnchorEntry[] = TAIWAN_ROOT_CERTIFICATES.map(
  (entry) => ({ ...entry, name: `${entry.name} (TSA anchor)` })
)

export function getPopulatedTsaEntries(): TrustAnchorEntry[] {
  return TAIWAN_TSA_ROOT_CERTIFICATES.filter((entry) => entry.pem.trim().length > 0)
}

export function hasAnyEmbeddedTsaPem(): boolean {
  return TAIWAN_TSA_ROOT_CERTIFICATES.some((entry) => entry.pem.trim().length > 0)
}
