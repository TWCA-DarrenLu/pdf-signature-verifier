/**
 * Byte-buffer helpers.
 *
 * A Uint8Array may be a window into a larger (or shared) buffer, so passing
 * `view.buffer` to a parser reads the wrong bytes, and TypeScript ≥ 5.7 no
 * longer accepts Uint8Array<ArrayBufferLike> where Web Crypto expects a
 * BufferSource.
 */

/** Copy a view into a standalone ArrayBuffer. */
export function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(view.byteLength)
  new Uint8Array(out).set(view)
  return out
}

/** The view itself when it is ArrayBuffer-backed, otherwise a copy. */
export function asBufferSource(view: Uint8Array): Uint8Array<ArrayBuffer> {
  return view.buffer instanceof ArrayBuffer
    ? (view as Uint8Array<ArrayBuffer>)
    : new Uint8Array(toArrayBuffer(view))
}
