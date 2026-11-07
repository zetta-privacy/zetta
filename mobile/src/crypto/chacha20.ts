// ---- ChaCha20 RNG (matches rand_chacha::ChaCha20Rng) ----

function rotl(x: number, b: number): number {
  return ((x << b) | (x >>> (32 - b))) >>> 0;
}

function quarterRound(x: Uint32Array, a: number, b: number, c: number, d: number): void {
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 7);
}

export class ChaCha20Rng {
  private key: Uint32Array;
  private counter = 0n;
  private stream = 0n;
  private buf: bigint[] = [];
  private idx = 0;

  constructor(seed: Uint8Array) {
    this.key = new Uint32Array(8);
    for (let i = 0; i < 8; i++) {
      this.key[i] = (seed[4*i] | (seed[4*i+1] << 8) | (seed[4*i+2] << 16) | (seed[4*i+3] << 24)) >>> 0;
    }
  }

  private block(): Uint32Array {
    const st = new Uint32Array(16);
    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
    for (let i = 0; i < 8; i++) st[4 + i] = this.key[i];
    st[12] = Number(this.counter & 0xFFFFFFFFn);
    st[13] = Number((this.counter >> 32n) & 0xFFFFFFFFn);
    st[14] = Number(this.stream & 0xFFFFFFFFn);
    st[15] = Number((this.stream >> 32n) & 0xFFFFFFFFn);
    const x = new Uint32Array(st);
    for (let r = 0; r < 10; r++) {
      quarterRound(x, 0, 4, 8, 12); quarterRound(x, 1, 5, 9, 13);
      quarterRound(x, 2, 6, 10, 14); quarterRound(x, 3, 7, 11, 15);
      quarterRound(x, 0, 5, 10, 15); quarterRound(x, 1, 6, 11, 12);
      quarterRound(x, 2, 7, 8, 13); quarterRound(x, 3, 4, 9, 14);
    }
    const out = new Uint32Array(16);
    for (let i = 0; i < 16; i++) out[i] = (x[i] + st[i]) >>> 0;
    this.counter += 1n;
    return out;
  }

  nextU64(): bigint {
    if (this.idx >= this.buf.length) {
      const b = this.block();
      this.buf = [];
      for (let i = 0; i < 16; i += 2) {
        this.buf.push(BigInt(b[i + 1]) << 32n | BigInt(b[i]));
      }
      this.idx = 0;
    }
    return this.buf[this.idx++];
  }
}

// ---- Discrete Gaussian (width 6.4, CDF hardcoded from Rust reference) ----

const CDF_TABLE: bigint[] = [
  0n, 0n, 0n, 7n, 225n, 6114n, 142809n, 2864512n, 49349166n, 730367088n,
  9288667698n, 101545086850n, 954617134063n, 7720973857474n, 53757667977838n,
  322436486442815n, 1667499996257361n, 7443566871362048n, 28720140744863884n,
  95948302954529081n, 278161926109627739n, 701795634139702303n, 1546646853635104741n,
  2991920295851131431n, 5112721055115151939n, 7782220156096217088n,
  10664523917613334528n, 13334023018594399677n, 15454823777858420185n,
  16900097220074446875n, 17744948439569849313n, 18168582147599923877n,
  18350795770755022535n, 18418023932964687732n, 18439300506838189568n,
  18445076573713294255n, 18446421637223108801n, 18446690316041573778n,
  18446736352735694142n, 18446743119092417553n, 18446743972164464766n,
  18446744064420883918n, 18446744072979184528n, 18446744073660202450n,
  18446744073706687104n, 18446744073709408807n, 18446744073709545502n,
  18446744073709551391n, 18446744073709551609n, 18446744073709551615n,
  18446744073709551615n, 18446744073709551615n, 18446744073709551615n,
];

const GAUSS_MAX = 26; // ceil(6.4 * 4)

export function gaussSample(modulus: bigint, rng: ChaCha20Rng): bigint {
  const sampled = rng.nextU64();
  let out = 0n;
  for (let i = CDF_TABLE.length - 1; i >= 0; i--) {
    if (sampled <= CDF_TABLE[i]) {
      let v = BigInt(i) - BigInt(GAUSS_MAX);
      if (v < 0n) v += modulus;
      out = v;
    }
  }
  return out;
}
