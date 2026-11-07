// pir.ts — part 1: field + modular arithmetic + NTT (BigInt)

export const MODULI = [268369921n, 249561089n];
export const POLY_LEN = 2048;
export const POLY_LEN_LOG2 = 11;

interface NttTable {
  root: bigint[];
  rootScaled: bigint[];
  inv: bigint[];
  invScaled: bigint[];
}

function log2(a: bigint): number {
  let r = -1;
  while (a > 0n) {
    a >>= 1n;
    r++;
  }
  return r;
}

export function log2Ceil(a: bigint): number {
  let r = 0;
  while ((1n << BigInt(r)) < a) r++;
  return r;
}

function reverseBits(x: bigint, bitCount: number): bigint {
  let r = 0n;
  for (let i = 0; i < bitCount; i++) {
    r = (r << 1n) | (x & 1n);
    x >>= 1n;
  }
  return r;
}

export function mulMod(a: bigint, b: bigint, m: bigint): bigint {
  return (a * b) % m;
}

function expMod(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  let b = base % m;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = mulMod(result, b, m);
    b = mulMod(b, b, m);
    e >>= 1n;
  }
  return result;
}

function extendedGcd(x: bigint, y: bigint): [bigint, bigint, bigint] {
  let prevA = 1n;
  let a = 0n;
  let prevB = 0n;
  let b = 1n;
  while (y !== 0n) {
    const q = x / y;
    const tmp = x % y;
    x = y;
    y = tmp;
    let t = a;
    a = prevA - q * a;
    prevA = t;
    t = b;
    b = prevB - q * b;
    prevB = t;
  }
  return [x, prevA, prevB];
}

export function invertMod(value: bigint, modulus: bigint): bigint {
  const [g, a] = extendedGcd(value, modulus);
  if (g !== 1n) throw new Error("not invertible");
  return a < 0n ? a + modulus : a;
}

export function div2Mod(operand: bigint, modulus: bigint): bigint {
  if (operand & 1n) return (operand + modulus) >> 1n;
  return operand >> 1n;
}

function isPrimitiveRoot(root: bigint, degree: bigint, modulus: bigint): boolean {
  return root !== 0n && expMod(root, degree >> 1n, modulus) === modulus - 1n;
}

export function getMinimalPrimitiveRoot(degree: bigint, modulus: bigint): bigint {
  const sizeQuotient = (modulus - 1n) / degree;
  let root = 0n;
  for (let trial = 0; trial < 100; trial++) {
    const hi = BigInt(Math.floor(Math.random() * 2 ** 32));
    const lo = BigInt(Math.floor(Math.random() * 2 ** 32));
    const r3 = ((hi << 32n) | lo) % modulus;
    root = expMod(r3, sizeQuotient, modulus);
    if (isPrimitiveRoot(root, degree, modulus)) break;
  }
  const generatorSq = mulMod(root, root, modulus);
  let current = root;
  let minimal = root;
  for (let i = 0n; i < degree; i++) {
    if (current < minimal) minimal = current;
    current = mulMod(current, generatorSq, modulus);
  }
  return minimal;
}

export function powersOfPrimitiveRoot(root: bigint, modulus: bigint, log2Len: number): bigint[] {
  const len = 1 << log2Len;
  const powers = new Array<bigint>(len).fill(0n);
  let power = root;
  for (let i = 1; i < len; i++) {
    powers[Number(reverseBits(BigInt(i), log2Len))] = power;
    power = mulMod(power, root, modulus);
  }
  powers[0] = 1n;
  return powers;
}

export function scalePowersU32(modulus: bigint, len: number, inp: bigint[]): bigint[] {
  const out = new Array<bigint>(len).fill(0n);
  for (let i = 0; i < len; i++) {
    out[i] = ((inp[i] << 32n) / modulus) & 0xFFFFFFFFn;
  }
  return out;
}

export const NTT_TABLES: NttTable[] = MODULI.map((modulus) => {
  const root = getMinimalPrimitiveRoot(BigInt(2 * POLY_LEN), modulus);
  const invRoot = invertMod(root, modulus);
  const rootPowers = powersOfPrimitiveRoot(root, modulus, POLY_LEN_LOG2);
  const scaledRoot = scalePowersU32(modulus, POLY_LEN, rootPowers);
  let invPowers = powersOfPrimitiveRoot(invRoot, modulus, POLY_LEN_LOG2);
  invPowers = invPowers.map((v) => div2Mod(v, modulus));
  const scaledInv = scalePowersU32(modulus, POLY_LEN, invPowers);
  return { root: rootPowers, rootScaled: scaledRoot, inv: invPowers, invScaled: scaledInv };
});

export function nttForward(operand: bigint[], table: NttTable, modulus: bigint): void {
  const polyLen = POLY_LEN;
  const twoMod = 2n * modulus;
  for (let mm = 0; mm < POLY_LEN_LOG2; mm++) {
    const m = 1 << mm;
    const t = polyLen >> (mm + 1);
    for (let i = 0; i < m; i++) {
      const w = table.root[m + i];
      const wPrime = table.rootScaled[m + i];
      for (let j = 0; j < t; j++) {
        const x = operand[i * 2 * t + j];
        const y = operand[i * 2 * t + t + j];
        const currX = x - twoMod * (x >= twoMod ? 1n : 0n);
        const qTmp = (y * wPrime) >> 32n;
        const qNew = w * y - qTmp * modulus;
        operand[i * 2 * t + j] = currX + qNew;
        operand[i * 2 * t + t + j] = currX + (twoMod - qNew);
      }
    }
  }
  for (let i = 0; i < polyLen; i++) {
    operand[i] -= (operand[i] >= twoMod ? 1n : 0n) * twoMod;
    operand[i] -= (operand[i] >= modulus ? 1n : 0n) * modulus;
  }
}

export function nttInverse(operand: bigint[], table: NttTable, modulus: bigint): void {
  const polyLen = POLY_LEN;
  const twoMod = 2n * modulus;
  for (let mm = POLY_LEN_LOG2 - 1; mm >= 0; mm--) {
    const h = 1 << mm;
    const t = polyLen >> (mm + 1);
    for (let i = 0; i < h; i++) {
      const w = table.inv[h + i];
      const wPrime = table.invScaled[h + i];
      for (let j = 0; j < t; j++) {
        const x = operand[i * 2 * t + j];
        const y = operand[i * 2 * t + t + j];
        const tTmp = twoMod - y + x;
        const currX = x + y - twoMod * ((x << 1n) >= tTmp ? 1n : 0n);
        const hTmp = (tTmp * wPrime) >> 32n;
        operand[i * 2 * t + j] = (currX + modulus * (tTmp & 1n)) >> 1n;
        operand[i * 2 * t + t + j] = w * tTmp - hTmp * modulus;
      }
    }
  }
  for (let i = 0; i < polyLen; i++) {
    operand[i] -= (operand[i] >= twoMod ? 1n : 0n) * twoMod;
    operand[i] -= (operand[i] >= modulus ? 1n : 0n) * modulus;
  }
}
