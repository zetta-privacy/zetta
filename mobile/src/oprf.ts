import { Field } from '@noble/curves/abstract/modular';
import { keccak_256 } from '@noble/hashes/sha3.js';

const FR_MODULUS =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const Fr = Field(FR_MODULUS);

function bytesToBigIntBE(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

function be32(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
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

function hashToField(x: Uint8Array): bigint {
  return bytesToBigIntBE(keccak_256(x)) % FR_MODULUS;
}

function finalizeHash(x: Uint8Array, d: bigint): Uint8Array {
  const out = new Uint8Array(x.length + 32);
  out.set(x, 0);
  out.set(be32(d), x.length);
  return keccak_256(out);
}

export function blind(x: Uint8Array): { blinded: string; r: bigint } {
  const r = randomScalar();
  return { blinded: Fr.mul(hashToField(x), r).toString(10), r };
}

export function finalize(x: Uint8Array, r: bigint, evaluated: string): Uint8Array {
  const d = Fr.pow(BigInt(evaluated), Fr.inv(r));
  return finalizeHash(x, d);
}

export function positions(prf: Uint8Array, tableSize: number): [number, number] {
  const lo = bytesToBigIntBE(prf.slice(0, 16));
  const hi = bytesToBigIntBE(prf.slice(16));
  return [Number(lo % BigInt(tableSize)), Number(hi % BigInt(tableSize))];
}
