import { poseidon2 } from 'poseidon-lite';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { pirRead } from './pirClient';
import { allLeafIndices } from './discovery';
import { burnAddress, deriveSecret, recipient } from './burn';
import { RPC_URL } from './tokens';

const VALUES_LEVEL = 33; // values DB index
const LEVELS = 32;       // merkle depth
const N = 4;            // withdraw.circom batch size
const VERIFIER = '0x…';  // TODO: deployed Verifier address

function bytesToBigIntBE(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

function zeroHash(h: number): bigint {
  let z = poseidon2([0n, 0n]);
  for (let i = 0; i < h; i++) z = poseidon2([z, z]);
  return z;
}

/** sibling at level h for leaf i, given current leaf count n. */
async function sibling(i: number, h: number, n: number): Promise<bigint> {
  const x = (i >> (h + 1)) ^ 1;
  const start = x * (1 << h);
  if (start < n) {
    const lmax = Math.min(n - 1, (x + 1) * (1 << h) - 1);
    return bytesToBigIntBE(await pirRead(lmax, h));
  }
  return zeroHash(h);
}

function selector(sig: string): string {
  return '0x' + [...keccak_256(new TextEncoder().encode(sig)).slice(0, 4)]
    .map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function readUint256(calldata: string): Promise<bigint> {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'eth_call',
      params: [{ to: VERIFIER, data: calldata }, 'latest'],
    }),
  });
  const { result } = await res.json();
  return BigInt(result);
}

export interface Transfer {
  index: number;     // burn address index i
  leafIndex: number; // tree position
}

/** Assemble withdraw.circom's input.json from a list of transfers (any addresses). */
export async function buildWithdrawInput(
  chainId: number,
  address: string,
  secretKey: bigint,
  transfers: Transfer[],
): Promise<Record<string, unknown>> {
  const rec = recipient(chainId, address);

  // public inputs from the chain
  const root = await readUint256(selector('transferRoot()'));
  const currentIndex = Number(await readUint256(selector('transferIndex()')));
  const prevIndex = await readUint256(
    selector('withdrawnIndex(uint256)') + rec.toString(16).padStart(64, '0'),
  );
  const prevSum = await readUint256(
    selector('totalWithdrawn(uint256)') + rec.toString(16).padStart(64, '0'),
  );

  // fresh deposits (index > I), sorted by leaf index, first N
  const fresh = transfers
    .filter((t) => BigInt(t.leafIndex) > prevIndex)
    .sort((a, b) => a.leafIndex - b.leafIndex)
    .slice(0, N);

  // per-slot data
  const indices: number[] = [];
  const secrets: bigint[] = [];
  const values: bigint[] = [];
  const siblings: bigint[][] = [];
  const pathIndices: bigint[][] = [];

  for (const t of fresh) {
    indices.push(t.leafIndex);
    secrets.push(deriveSecret(secretKey, t.index));   // per-slot secret
    values.push(bytesToBigIntBE(await pirRead(t.leafIndex, VALUES_LEVEL)));
    const sib: bigint[] = [];
    const path: bigint[] = [];
    for (let h = 0; h < LEVELS; h++) {
      sib.push(await sibling(t.leafIndex, h, currentIndex));
      path.push(BigInt((t.leafIndex >> h) & 1));
    }
    siblings.push(sib);
    pathIndices.push(path);
  }

  // pad to N
  const real = fresh.length;
  for (let k = real; k < N; k++) {
    indices.push(0);
    secrets.push(0n);
    values.push(0n);
    siblings.push(Array(LEVELS).fill(0n));
    pathIndices.push(Array(LEVELS).fill(0n));
  }
  const isPadding = indices.map((_, k) => (k < real ? 0n : 1n));

  const currentSum = prevSum + values.slice(0, real).reduce((a, b) => a + b, 0n);

  return {
    root: root.toString(),
    recipient: rec.toString(),
    prevIndex: prevIndex.toString(),
    currentIndex: currentIndex.toString(),
    secret: secrets.map(String),
    isPadding: isPadding.map(String),
    values: values.map(String),
    indices: indices.map(String),
    pathIndices: pathIndices.map((p) => p.map(String)),
    siblings: siblings.map((s) => s.map(String)),
    currentSum: currentSum.toString(),
    prevSum: prevSum.toString(),
  };
}
