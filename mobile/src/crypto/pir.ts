// polymath.ts — top of file:
import {
  MODULI, POLY_LEN, POLY_LEN_LOG2, NTT_TABLES, nttForward, nttInverse,
  invertMod, log2Ceil, div2Mod, getMinimalPrimitiveRoot, powersOfPrimitiveRoot, scalePowersU32, mulMod
} from "./nnt";

import {
  gaussSample, ChaCha20Rng,
} from "./chacha20";

// ---- modular arithmetic / CRT / barrett ----

const CR1 = [68736257792n, 73916747789n];          // barrett cr1 per modulus
const MODULUS = MODULI[0] * MODULI[1];
const MOD0_INV_MOD1 = MODULI[0] * invertMod(MODULI[0], MODULI[1]);
const MOD1_INV_MOD0 = MODULI[1] * invertMod(MODULI[1], MODULI[0]);

function barrettCoeff(a: bigint, c: number): bigint {
  const tmp = (a * CR1[c]) >> 64n;
  let res = a - tmp * MODULI[c];
  if (res >= MODULI[c]) res -= MODULI[c];
  return res;
}

function crtCompose(x: bigint, y: bigint): bigint {
  return (x * MOD1_INV_MOD0 + y * MOD0_INV_MOD1) % MODULUS;
}

// ---- PolyMatrix ----

export class PolyMatrixRaw {
  rows: number; cols: number; data: bigint[];
  constructor(rows: number, cols: number) {
    this.rows = rows; this.cols = cols;
    this.data = new Array<bigint>(rows * cols * POLY_LEN).fill(0n);
  }
  poly(r: number, c: number): bigint[] {
    return this.data.slice((r * this.cols + c) * POLY_LEN, (r * this.cols + c + 1) * POLY_LEN);
  }
  setPoly(r: number, c: number, p: bigint[]) {
    const off = (r * this.cols + c) * POLY_LEN;
    for (let i = 0; i < POLY_LEN; i++) this.data[off + i] = p[i];
  }
}

class PolyMatrixNTT {
  rows: number; cols: number; data: bigint[];
  constructor(rows: number, cols: number) {
    this.rows = rows; this.cols = cols;
    this.data = new Array<bigint>(rows * cols * POLY_LEN * 2).fill(0n);
  }
  poly(r: number, c: number): bigint[] {
    const off = (r * this.cols + c) * POLY_LEN * 2;
    return this.data.slice(off, off + POLY_LEN * 2);
  }
  setPoly(r: number, c: number, p: bigint[]) {
    const off = (r * this.cols + c) * POLY_LEN * 2;
    for (let i = 0; i < POLY_LEN * 2; i++) this.data[off + i] = p[i];
  }
}

export function copyInto(dst: PolyMatrixRaw | PolyMatrixNTT, src: PolyMatrixRaw | PolyMatrixNTT, tr: number, tc: number) {
  for (let r = 0; r < src.rows; r++)
    for (let c = 0; c < src.cols; c++)
      (dst as any).setPoly(tr + r, tc + c, (src as any).poly(r, c));
}

function toNtt(b: PolyMatrixRaw): PolyMatrixNTT {
  const a = new PolyMatrixNTT(b.rows, b.cols);
  for (let r = 0; r < b.rows; r++)
    for (let c = 0; c < b.cols; c++) {
      const src = b.poly(r, c);
      const dst = new Array<bigint>(POLY_LEN * 2).fill(0n);
      for (let n = 0; n < 2; n++)
        for (let z = 0; z < POLY_LEN; z++)
          dst[n * POLY_LEN + z] = barrettCoeff(src[z], n);
      nttForward(dst, NTT_TABLES[0], MODULI[0]);
      nttForward(dst, NTT_TABLES[1], MODULI[1]);
      a.setPoly(r, c, dst);
    }
  return a;
}

function fromNtt(b: PolyMatrixNTT): PolyMatrixRaw {
  const a = new PolyMatrixRaw(b.rows, b.cols);
  for (let r = 0; r < b.rows; r++)
    for (let c = 0; c < b.cols; c++) {
      const src = b.poly(r, c);
      const scratch = src.slice();
      nttInverse(scratch, NTT_TABLES[0], MODULI[0]);
      nttInverse(scratch, NTT_TABLES[1], MODULI[1]);
      const dst = new Array<bigint>(POLY_LEN).fill(0n);
      for (let z = 0; z < POLY_LEN; z++) dst[z] = crtCompose(scratch[z], scratch[POLY_LEN + z]);
      a.setPoly(r, c, dst);
    }
  return a;
}

function multiplyNtt(a: PolyMatrixNTT, b: PolyMatrixNTT): PolyMatrixNTT {
  const res = new PolyMatrixNTT(a.rows, b.cols);
  for (let i = 0; i < a.rows; i++)
    for (let j = 0; j < b.cols; j++)
      for (let k = 0; k < a.cols; k++) {
        const p1 = a.poly(i, k), p2 = b.poly(k, j), rp = res.poly(i, j);
        for (let c = 0; c < 2; c++)
          for (let z = 0; z < POLY_LEN; z++) {
            const idx = c * POLY_LEN + z;
            rp[idx] = barrettCoeff(rp[idx] + p1[idx] * p2[idx], c);
          }
        res.setPoly(i, j, rp);
      }
  return res;
}

function addNtt(a: PolyMatrixNTT, b: PolyMatrixNTT): PolyMatrixNTT {
  const res = new PolyMatrixNTT(a.rows, a.cols);
  for (let i = 0; i < a.rows; i++)
    for (let j = 0; j < a.cols; j++) {
      const p1 = a.poly(i, j), p2 = b.poly(i, j), rp = res.poly(i, j);
      for (let c = 0; c < 2; c++)
        for (let z = 0; z < POLY_LEN; z++) {
          const idx = c * POLY_LEN + z;
          rp[idx] = barrettCoeff(p1[idx] + p2[idx], c);
        }
      res.setPoly(i, j, rp);
    }
  return res;
}

function addInto(res: PolyMatrixNTT, a: PolyMatrixNTT) {
  for (let i = 0; i < res.rows; i++)
    for (let j = 0; j < res.cols; j++) {
      const p1 = a.poly(i, j), rp = res.poly(i, j);
      for (let c = 0; c < 2; c++)
        for (let z = 0; z < POLY_LEN; z++) {
          const idx = c * POLY_LEN + z;
          rp[idx] = barrettCoeff(rp[idx] + p1[idx], c);
        }
      res.setPoly(i, j, rp);
    }
}

function scalarMultiplyNtt(a: PolyMatrixNTT, b: PolyMatrixNTT): PolyMatrixNTT {
  // a is 1x1
  const res = new PolyMatrixNTT(b.rows, b.cols);
  const p2 = a.poly(0, 0);
  for (let i = 0; i < b.rows; i++)
    for (let j = 0; j < b.cols; j++) {
      const p1 = b.poly(i, j), rp = res.poly(i, j);
      for (let c = 0; c < 2; c++)
        for (let z = 0; z < POLY_LEN; z++) {
          const idx = c * POLY_LEN + z;
          rp[idx] = barrettCoeff(p1[idx] * p2[idx], c);
        }
      res.setPoly(i, j, rp);
    }
  return res;
}

function singleValue(v: bigint): PolyMatrixRaw {
  const m = new PolyMatrixRaw(1, 1);
  m.data[0] = v;
  return m;
}

export function identity(rows: number, cols: number): PolyMatrixRaw {
  const m = new PolyMatrixRaw(rows, cols);
  for (let r = 0; r < rows; r++) m.data[r * cols * POLY_LEN + r * POLY_LEN] = 1n;
  return m;
}

function negateRaw(a: PolyMatrixRaw): PolyMatrixRaw {
  const m = new PolyMatrixRaw(a.rows, a.cols);
  for (let i = 0; i < a.data.length; i++) m.data[i] = MODULUS - a.data[i];
  return m;
}

function padTop(a: PolyMatrixRaw, padRows: number): PolyMatrixRaw {
  const m = new PolyMatrixRaw(a.rows + padRows, a.cols);
  copyInto(m, a, padRows, 0);
  return m;
}

function noiseRaw(rows: number, cols: number, rng: ChaCha20Rng): PolyMatrixRaw {
  const m = new PolyMatrixRaw(rows, cols);
  for (let i = 0; i < m.data.length; i++) m.data[i] = gaussSample(MODULUS, rng);
  return m;
}

export function randomRaw(rows: number, cols: number, rng: ChaCha20Rng): PolyMatrixRaw {
  const m = new PolyMatrixRaw(rows, cols);
  for (let i = 0; i < m.data.length; i++) m.data[i] = rng.nextU64() % MODULUS;
  return m;
}

// ---- gadget ----

function getBitsPer(dim: number): number {
  const modulusLog2 = 56; // log2(MODULUS), for n=2 both moduli ~2^28 → modulus ~2^56
  if (dim === modulusLog2) return 1;
  return Math.floor(modulusLog2 / dim) + 1;
}

function buildGadget(rows: number, cols: number): PolyMatrixRaw {
  const g = new PolyMatrixRaw(rows, cols);
  const nx = rows, m = cols;
  const numElems = m / nx;
  const bitsPer = getBitsPer(numElems);
  for (let i = 0; i < nx; i++)
    for (let j = 0; j < numElems; j++) {
      if (bitsPer * j >= 64) continue;
      const p = g.poly(i, i + j * nx);
      p[0] = 1n << BigInt(bitsPer * j);
      g.setPoly(i, i + j * nx, p);
    }
  return g;
}

function gadgetInvert(inp: PolyMatrixRaw, mx: number): PolyMatrixRaw {
  const out = new PolyMatrixRaw(mx, inp.cols);
  const rdim = inp.rows;
  const numElems = mx / rdim;
  const bitsPer = getBitsPer(numElems);
  const mask = (1n << BigInt(bitsPer)) - 1n;
  for (let i = 0; i < inp.cols; i++)
    for (let j = 0; j < rdim; j++) {
      const p = inp.poly(j, i);
      for (let z = 0; z < POLY_LEN; z++) {
        const val = p[z];
        for (let k = 0; k < numElems; k++) {
          const bitOffs = Math.min(k * bitsPer, 64);
          const shifted = val >> BigInt(bitOffs);
          const piece = shifted & mask;
          const op = out.poly(j + k * rdim, i);
          op[z] = piece;
          out.setPoly(j + k * rdim, i, op);
        }
      }
    }
  return out;
}

// ---- client (setup / query / decode) ----

const N = 2;               // params.n
const DB_DIM_1 = 9;        // nu_1
const DB_DIM_2 = 6;        // nu_2
const T_GSW = 8;
const T_CONV = 4;
const T_EXP_LEFT = 8;
const T_EXP_RIGHT = 56;
const PT_MODULUS = 256n;   // p
const Q2_BITS = 20;
const INSTANCES = 1;
const DB_ITEM_SIZE = 32;
const HAMMING = 256;
const SEED_LENGTH = 32;

const MODULUS_LOG2 = 56   // log2(MODULUS)

function g(): number {
  return log2Ceil(BigInt(T_GSW * DB_DIM_2 + (1 << DB_DIM_1)));
}
function stopRound(): number {
  return log2Ceil(BigInt(T_GSW * DB_DIM_2));
}

function automorphPoly(a: bigint[], t: number): bigint[] {
  const res = new Array<bigint>(POLY_LEN).fill(0n);
  for (let i = 0; i < POLY_LEN; i++) {
    const num = Math.floor((i * t) / POLY_LEN);
    const rem = (i * t) % POLY_LEN;
    res[rem] = num % 2 === 0 ? a[i] : MODULUS - a[i];
  }
  return res;
}

function rngSeed32(rng: ChaCha20Rng): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let v = rng.nextU64();
    for (let j = 0; j < 8; j++) { out[i * 8 + j] = Number(v & 0xFFn); v >>= 8n; }
  }
  return out;
}

function stack(a: PolyMatrixRaw, b: PolyMatrixRaw): PolyMatrixRaw {
  const m = new PolyMatrixRaw(a.rows + b.rows, a.cols);
  copyInto(m, a, 0, 0);
  copyInto(m, b, a.rows, 0);
  return m;
}

function matrixWithIdentity(p: PolyMatrixRaw): PolyMatrixRaw {
  const r = new PolyMatrixRaw(p.rows, p.rows + 1);
  copyInto(r, p, 0, 0);
  copyInto(r, identity(p.rows, p.rows), 0, 1);
  return r;
}

function genTernaryMat(mat: PolyMatrixRaw, rng: ChaCha20Rng): void {
  for (let r = 0; r < mat.rows; r++)
    for (let c = 0; c < mat.cols; c++) {
      const pol = new Array<bigint>(POLY_LEN).fill(0n);
      for (let i = 0; i < HAMMING; i++) pol[i] = 1n;
      for (let i = HAMMING; i < 2 * HAMMING; i++) pol[i] = MODULUS - 1n;
      // Fisher-Yates shuffle (client's own entropy — need not match Rust)
      for (let i = POLY_LEN - 1; i > 0; i--) {
        const j = Number(rng.nextU64() % BigInt(i + 1));
        const tmp = pol[i]; pol[i] = pol[j]; pol[j] = tmp;
      }
      mat.setPoly(r, c, pol);
    }
}

// ---- full client ----
export class Client {
  skGsw: PolyMatrixRaw; skReg: PolyMatrixRaw;
  skGswFull: PolyMatrixRaw; skRegFull: PolyMatrixRaw;
  constructor() {
    this.skGsw = new PolyMatrixRaw(N, 1);
    this.skReg = new PolyMatrixRaw(1, 1);
    this.skGswFull = matrixWithIdentity(this.skGsw);
    this.skRegFull = matrixWithIdentity(this.skReg);
  }
  generateSecretKeys(rng: ChaCha20Rng) {
    genTernaryMat(this.skGsw, rng);
    genTernaryMat(this.skReg, rng);
    this.skGswFull = matrixWithIdentity(this.skGsw);
    this.skRegFull = matrixWithIdentity(this.skReg);
  }
  getFreshGswPublicKey(m: number, rng: ChaCha20Rng, rngPub: ChaCha20Rng): PolyMatrixRaw {
    const a = randomRaw(1, m, rngPub);
    const e = noiseRaw(N, m, rng);
    const aInv = negateRaw(a);
    const bP = multiplyNtt(toNtt(this.skGsw), toNtt(a));
    const b = addNtt(toNtt(e), bP);
    return stack(aInv, fromNtt(b));
  }
  getRegevSample(rng: ChaCha20Rng, rngPub: ChaCha20Rng): PolyMatrixNTT {
    const a = randomRaw(1, 1, rngPub);
    const e = noiseRaw(1, 1, rng);
    const b = addNtt(toNtt(e), multiplyNtt(toNtt(this.skReg), toNtt(a)));
    const p = new PolyMatrixNTT(2, 1);
    const na = toNtt(negateRaw(a));
    p.setPoly(0, 0, na.poly(0, 0));
    p.setPoly(1, 0, b.poly(0, 0));
    return p;
  }
  getFreshRegPublicKey(m: number, rng: ChaCha20Rng, rngPub: ChaCha20Rng): PolyMatrixNTT {
    const p = new PolyMatrixNTT(2, m);
    for (let i = 0; i < m; i++) {
      const s = this.getRegevSample(rng, rngPub);
      p.setPoly(0, i, s.poly(0, 0));
      p.setPoly(1, i, s.poly(1, 0));
    }
    return p;
  }
  encryptMatrixGsw(ag: PolyMatrixNTT, rng: ChaCha20Rng, rngPub: ChaCha20Rng): PolyMatrixNTT {
    const p = this.getFreshGswPublicKey(ag.cols, rng, rngPub);
    return addNtt(toNtt(p), padTopNtt(ag, 1));
  }
  encryptMatrixReg(a: PolyMatrixNTT, rng: ChaCha20Rng, rngPub: ChaCha20Rng): PolyMatrixNTT {
    return addNtt(this.getFreshRegPublicKey(a.cols, rng, rngPub), padTopNtt(a, 1));
  }
  generateExpansionParams(numExp: number, mExp: number, rng: ChaCha20Rng, rngPub: ChaCha20Rng): PolyMatrixNTT[] {
    const gExp = buildGadget(1, mExp);
    const gExpNtt = toNtt(gExp);
    const res: PolyMatrixNTT[] = [];
    for (let i = 0; i < numExp; i++) {
      const t = Math.floor(POLY_LEN / (1 << i)) + 1;
      const tau = new PolyMatrixRaw(1, 1);
      tau.setPoly(0, 0, automorphPoly(this.skReg.poly(0, 0), t));
      const prod = multiplyNtt(toNtt(tau), gExpNtt);
      res.push(this.encryptMatrixReg(prod, rng, rngPub));
    }
    return res;
  }
  /** Deterministically restore secret keys from a 32-byte seed. */
  initFromSeed(seed: Uint8Array): void {
    this.generateSecretKeys(new ChaCha20Rng(seed));
  }

  /** Public params from the already-initialized secret keys (public, not secret). */
  generatePublicParams(): Uint8Array {
    const rng = new ChaCha20Rng(crypto.getRandomValues(new Uint8Array(32)));
    const rng2 = new ChaCha20Rng(crypto.getRandomValues(new Uint8Array(32)));
    const ppSeed = rngSeed32(rng2);
    const rngPub = new ChaCha20Rng(ppSeed);

    const vPacking: PolyMatrixNTT[] = [];
    const gadgetConv = toNtt(buildGadget(1, T_CONV));
    const skRegNtt = toNtt(this.skReg);
    for (let i = 0; i < N; i++) {
      const scaled = scalarMultiplyNtt(skRegNtt, gadgetConv);
      const ag = new PolyMatrixNTT(N, T_CONV);
      copyInto(ag, scaled, i, 0);
      vPacking.push(this.encryptMatrixGsw(ag, rng, rngPub));
    }

    const vExpLeft = this.generateExpansionParams(g(), T_EXP_LEFT, rng, rngPub);
    const vExpRight = this.generateExpansionParams(stopRound() + 1, T_EXP_RIGHT, rng, rngPub);

    const gConv = buildGadget(2, 2 * T_CONV);
    const skRegNttSq = multiplyNtt(skRegNtt, skRegNtt);
    const vConv = new PolyMatrixNTT(2, 2 * T_CONV);
    for (let i = 0; i < 2 * T_CONV; i++) {
      const val = gConv.poly(i % 2, i)[0];
      const single = singleValue(val);
      const sigma = i % 2 === 0
        ? multiplyNtt(skRegNttSq, toNtt(single))
        : multiplyNtt(skRegNtt, toNtt(single));
      const ct = this.encryptMatrixReg(sigma, rng, rngPub);
      vConv.setPoly(0, i, ct.poly(0, 0));
      vConv.setPoly(1, i, ct.poly(1, 0));
    }

    return serializePublicParams(ppSeed, [vPacking, vExpLeft, vExpRight, [vConv]]);
  }
  generateQuery(idxTarget: number): Uint8Array {
    const rng = new ChaCha20Rng(crypto.getRandomValues(new Uint8Array(32)));
    const querySeed = rngSeed32(rng);
    const rngPub = new ChaCha20Rng(querySeed);

    const idxDim0 = Math.floor(idxTarget / (1 << DB_DIM_2));
    const idxFurther = idxTarget % (1 << DB_DIM_2);
    const scaleK = MODULUS / PT_MODULUS;
    const bitsPer = getBitsPer(T_GSW);

    const sigma = new PolyMatrixRaw(1, 1);
    const s = sigma.poly(0, 0);
    const inv2gFirst = invertMod(1n << BigInt(g()), MODULUS);
    const inv2gRest = invertMod(1n << BigInt(stopRound() + 1), MODULUS);

    for (let i = 0; i < (1 << DB_DIM_1); i++) {
      if (i === idxDim0) s[2 * i] = scaleK;
    }
    for (let i = 0; i < DB_DIM_2; i++) {
      const mask = 1 << i;
      const bit = ((idxFurther & mask) === mask) ? 1n : 0n;
      for (let j = 0; j < T_GSW; j++) {
        const val = bit * (1n << BigInt(bitsPer * j));
        s[2 * (i * T_GSW + j) + 1] = val;
      }
    }
    for (let i = 0; i < POLY_LEN / 2; i++) {
      s[2 * i] = mulMod(s[2 * i], inv2gFirst, MODULUS);
      s[2 * i + 1] = mulMod(s[2 * i + 1], inv2gRest, MODULUS);
    }
    sigma.setPoly(0, 0, s);

    const ct = this.encryptMatrixReg(toNtt(sigma), rng, rngPub);
    return serializeQuery(querySeed, fromNtt(ct));
  }
  decodeResponse(data: Uint8Array): Uint8Array {
    const p = PT_MODULUS;
    const pBits = log2Ceil(p);
    const q1 = 4n * p;
    const q1Bits = log2Ceil(q1);
    const q2 = Q2_VALUES[Q2_BITS];
    const q2Bits = Q2_BITS;

    // sk_gsw in q2
    const skGswQ2 = new PolyMatrixRaw(N, 1);
    for (let i = 0; i < POLY_LEN * N; i++) {
      skGswQ2.data[i] = recenter(this.skGsw.data[i], MODULUS, q2);
    }
    const skGswQ2Ntt = toNttQ2(skGswQ2, q2);

    const result = new PolyMatrixRaw(INSTANCES * N, N);
    let bitOffs = 0;
    for (let instance = 0; instance < INSTANCES; instance++) {
      const firstRow = new PolyMatrixRaw(1, N);
      const restRows = new PolyMatrixRaw(N, N);
      for (let i = 0; i < N * POLY_LEN; i++) { firstRow.data[i] = readBits(data, bitOffs, q2Bits); bitOffs += q2Bits; }
      for (let i = 0; i < N * N * POLY_LEN; i++) { restRows.data[i] = readBits(data, bitOffs, q1Bits); bitOffs += q1Bits; }

      const firstRowQ2 = toNttQ2(firstRow, q2);
      const skProd = fromNttQ2(multiplyNttQ2(skGswQ2Ntt, firstRowQ2, q2), q2);

      for (let i = 0; i < N * N * POLY_LEN; i++) {
        let valFirst = skProd.data[i];
        if (valFirst >= q2 / 2n) valFirst -= q2;
        let valRest = restRows.data[i];
        if (valRest >= q1 / 2n) valRest -= q1;

        const denom = q2 * (q1 / p);
        let r = valFirst * q1 + valRest * q2;
        const sign = r >= 0n ? 1n : -1n;
        let res = (r + sign * (denom / 2n)) / denom;
        res = (res + (denom / p) * p + 2n * p) % p;
        result.data[instance * N * N * POLY_LEN + i] = res;
      }
    }
    return packToBytes(result, pBits);
  }
}

function padTopNtt(a: PolyMatrixNTT, padRows: number): PolyMatrixNTT {
  const m = new PolyMatrixNTT(a.rows + padRows, a.cols);
  copyInto(m, a, padRows, 0);
  return m;
}

function shiftRowsByOne(inp: PolyMatrixNTT): PolyMatrixNTT {
  if (inp.rows === 1) return inp;
  const m = new PolyMatrixNTT(inp.rows, inp.cols);
  // last row becomes first, rest shift down by one
  for (let r = 0; r < inp.rows - 1; r++)
    for (let c = 0; c < inp.cols; c++) m.setPoly(r + 1, c, inp.poly(r, c));
  for (let c = 0; c < inp.cols; c++) m.setPoly(0, c, inp.poly(inp.rows - 1, c));
  return m;
}

function u64ToLeBytes(v: bigint): number[] {
  const out = new Array<number>(8).fill(0);
  let x = v;
  for (let i = 0; i < 8; i++) { out[i] = Number(x & 0xFFn); x >>= 8n; }
  return out;
}

function serializeMatrixSkipFirstRow(a: PolyMatrixRaw, out: number[]): void {
  const offs = a.cols * POLY_LEN;  // skip first row
  for (let i = offs; i < a.data.length; i++) out.push(...u64ToLeBytes(a.data[i]));
}

function serializePublicParams(seed: Uint8Array, matrices: PolyMatrixNTT[][]): Uint8Array {
  const out: number[] = Array.from(seed);
  for (const group of matrices)
    for (const m of group) serializeMatrixSkipFirstRow(fromNtt(m), out);
  return Uint8Array.from(out);
}

const Q2_VALUES: bigint[] = [
  0n,0n,0n,0n,0n,0n,0n,0n,0n,0n,0n,0n,0n,0n,
  12289n,12289n,61441n,65537n,65537n,520193n,786433n,786433n,
  3604481n,7340033n,16515073n,33292289n,67043329n,132120577n,
  268369921n,469762049n,1073479681n,2013265921n,4293918721n,
  8588886017n,17175674881n,34359214081n,68718428161n,
];

type Q2Table = { root: bigint[]; rootScaled: bigint[]; inv: bigint[]; invScaled: bigint[] };

function buildQ2Table(modulus: bigint): Q2Table {
  const root = getMinimalPrimitiveRoot(BigInt(2 * POLY_LEN), modulus);
  const invRoot = invertMod(root, modulus);
  const rootPowers = powersOfPrimitiveRoot(root, modulus, POLY_LEN_LOG2);
  const scaledRoot = scalePowersU32(modulus, POLY_LEN, rootPowers);
  let invPowers = powersOfPrimitiveRoot(invRoot, modulus, POLY_LEN_LOG2);
  invPowers = invPowers.map((v) => div2Mod(v, modulus));
  const scaledInv = scalePowersU32(modulus, POLY_LEN, invPowers);
  return { root: rootPowers, rootScaled: scaledRoot, inv: invPowers, invScaled: scaledInv };
}

const Q2_TABLE = buildQ2Table(Q2_VALUES[Q2_BITS]);

function barrettRaw(a: bigint, cr1: bigint, modulus: bigint): bigint {
  const tmp = (a * cr1) >> 64n;
  let res = a - tmp * modulus;
  if (res >= modulus) res -= modulus;
  return res;
}

function recenter(val: bigint, from: bigint, to: bigint): bigint {
  let a = val;
  if (val >= from / 2n) a -= from;
  a = a + (from / to) * to + 2n * to;
  a %= to;
  return a;
}

function readBits(data: Uint8Array, bitOffs: number, numBits: number): bigint {
  const wordOff = Math.floor(bitOffs / 64);
  const bitOff = bitOffs % 64;
  const nBytes = (bitOff + numBits <= 64) ? 8 : 16;
  let val = 0n;
  for (let i = 0; i < nBytes; i++) val |= BigInt(data[wordOff * 8 + i]) << BigInt(8 * i);
  return (val >> BigInt(bitOff)) & ((1n << BigInt(numBits)) - 1n);
}

function writeBits(data: Uint8Array, val: bigint, bitOffs: number, numBits: number): void {
  const wordOff = Math.floor(bitOffs / 64);
  const bitOff = bitOffs % 64;
  val &= (1n << BigInt(numBits)) - 1n;
  const nBytes = (bitOff + numBits <= 64) ? 8 : 16;
  let cur = 0n;
  for (let i = 0; i < nBytes; i++) cur |= BigInt(data[wordOff * 8 + i]) << BigInt(8 * i);
  const mask = ~(((1n << BigInt(numBits)) - 1n) << BigInt(bitOff));
  cur &= mask;
  cur |= val << BigInt(bitOff);
  for (let i = 0; i < nBytes; i++) data[wordOff * 8 + i] = Number((cur >> BigInt(8 * i)) & 0xFFn);
}

function modpWordsPerChunk(): number {
  const bytesPerChunk = Math.ceil(DB_ITEM_SIZE / (INSTANCES * N * N));
  return Math.ceil((bytesPerChunk * 8) / log2Ceil(PT_MODULUS));
}

function packToBytes(m: PolyMatrixRaw, modulusBits: number): Uint8Array {
  const numCoeffs = modpWordsPerChunk();
  const szBits = m.rows * m.cols * numCoeffs * modulusBits;
  const szBytes = Math.ceil(szBits / 8) + 32;
  const data = new Uint8Array(Math.ceil(szBytes / 16) * 16);
  let bitOffs = 0;
  for (let r = 0; r < m.rows; r++)
    for (let c = 0; c < m.cols; c++) {
      const base = (r * m.cols + c) * POLY_LEN;
      for (let z = 0; z < numCoeffs; z++) {
        writeBits(data, m.data[base + z], bitOffs, modulusBits);
        bitOffs += modulusBits;
      }
      bitOffs = Math.floor(bitOffs / 8) * 8;
    }
  return data;
}

function toNttQ2(m: PolyMatrixRaw, q2: bigint): PolyMatrixRaw {
  const cr1 = (1n << 128n) / q2 >> 64n;
  const out = new PolyMatrixRaw(m.rows, m.cols);
  for (let r = 0; r < m.rows; r++)
    for (let c = 0; c < m.cols; c++) {
      const poly = m.poly(r, c).map((v) => barrettRaw(v, cr1, q2));
      nttForward(poly, Q2_TABLE, q2);
      out.setPoly(r, c, poly);
    }
  return out;
}

function fromNttQ2(m: PolyMatrixRaw, q2: bigint): PolyMatrixRaw {
  const out = new PolyMatrixRaw(m.rows, m.cols);
  for (let r = 0; r < m.rows; r++)
    for (let c = 0; c < m.cols; c++) {
      const poly = m.poly(r, c).slice();
      nttInverse(poly, Q2_TABLE, q2);
      out.setPoly(r, c, poly);
    }
  return out;
}

function multiplyNttQ2(a: PolyMatrixRaw, b: PolyMatrixRaw, q2: bigint): PolyMatrixRaw {
  const cr1 = (1n << 128n) / q2 >> 64n;
  const res = new PolyMatrixRaw(a.rows, b.cols);
  for (let i = 0; i < a.rows; i++)
    for (let j = 0; j < b.cols; j++) {
      const rp = new Array<bigint>(POLY_LEN).fill(0n);
      for (let k = 0; k < a.cols; k++) {
        const p1 = a.poly(i, k), p2 = b.poly(k, j);
        for (let z = 0; z < POLY_LEN; z++) rp[z] = barrettRaw(rp[z] + p1[z] * p2[z], cr1, q2);
      }
      res.setPoly(i, j, rp);
    }
  return res;
}

function serializeQuery(seed: Uint8Array, ct: PolyMatrixRaw): Uint8Array {
  const out: number[] = Array.from(seed);
  serializeMatrixSkipFirstRow(ct, out);
  return Uint8Array.from(out);
}
