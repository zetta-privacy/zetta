import { Field } from '@noble/curves/abstract/modular';
import { keccak_256 } from '@noble/hashes/sha3.js';

// bn254 SCALAR field r == ark_bn254::Fr in the server
const FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const Fr = Field(FR_MODULUS);

function bytesToBigIntBE(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

function be32(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function randomScalar(): bigint {
  const buf = new Uint8Array(32);
  for (;;) {
    crypto.getRandomValues(buf); // polyfilled in index.ts
    const x = bytesToBigIntBE(buf);
    if (x >= 1n && x < FR_MODULUS) return x;
  }
}

// H1(x) = keccak256(x) mod r
function hashToField(x: Uint8Array): bigint {
  return bytesToBigIntBE(keccak_256(x)) % FR_MODULUS;
}

// H2(x, D) = keccak256(x || be32(D))
function finalizeHash(x: Uint8Array, d: bigint): Uint8Array {
  const out = new Uint8Array(x.length + 32);
  out.set(x, 0);
  out.set(be32(d), x.length);
  return keccak_256(out);
}

/** Build the (address, j) key the cuckoo table is keyed by: address[20] ‖ j[4 BE]. */
export function keyBytes(address: string, j: number): Uint8Array {
  const hex = address.toLowerCase().replace(/^0x/, '');
  const out = new Uint8Array(24);
  for (let i = 0; i < 20; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  new DataView(out.buffer).setUint32(20, j, false); // j big-endian
  return out;
}

/** Blind x: B = H1(x) * r. Returns the blinded element (decimal) + the secret r. */
export function blind(x: Uint8Array): { blinded: string; r: bigint } {
  const r = randomScalar();
  return { blinded: Fr.mul(hashToField(x), r).toString(10), r };
}

/** Unblind + finalize: PRF(k, x) = H2(x, C^(1/r)). `evaluated` is C from /oprf/evaluate. */
export function finalize(x: Uint8Array, r: bigint, evaluated: string): Uint8Array {
  const d = Fr.pow(BigInt(evaluated), Fr.inv(r));
  return finalizeHash(x, d);
}

/** Split a 32-byte PRF into two cuckoo slots, mod tableSize. */
export function positions(prf: Uint8Array, tableSize: number): [number, number] {
  const lo = bytesToBigIntBE(prf.slice(0, 16));
  const hi = bytesToBigIntBE(prf.slice(16));
  return [Number(lo % BigInt(tableSize)), Number(hi % BigInt(tableSize))];
}
