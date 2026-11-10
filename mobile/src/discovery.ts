import { blind, finalize, keyBytes, positions } from './oprf';
import { pirRead } from './pirClient';

const SERVER = process.env.EXPO_PUBLIC_SERVER_URL;
const TABLE_SIZE = 1 << 16; // server's cuckoo table size
const CUCKOO_LEVEL = 32;    // cuckoo DB index in the server's dbs

function readU64BE(bytes: Uint8Array, off: number): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(bytes[off + i]);
  return v;
}

/** Find the leaf index for the (address, j)-th deposit. null if it doesn't exist. */
export async function leafIndexFor(address: string, j: number): Promise<number | null> {
  const x = keyBytes(address, j); // address[20] ‖ j[4 BE]

  // 1. blind
  const { blinded, r } = blind(x);

  // 2. server evaluate
  const res = await fetch(`${SERVER}/oprf/evaluate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ blinded }),
  });
  if (!res.ok) throw new Error(`oprf/evaluate failed: ${res.status}`);
  const { evaluated } = await res.json();

  // 3. finalize -> PRF
  const prf = finalize(x, r, evaluated);

  // 4. two cuckoo slots
  const [h1, h2] = positions(prf, TABLE_SIZE);

  // 5. PIR-read both, match on the key (first 24 bytes = address + j)
  for (const h of [h1, h2]) {
    const slot = await pirRead(h, CUCKOO_LEVEL);
    if (slot.length === 32 && slot.slice(0, 24).every((b, i) => b === x[i])) {
      return Number(readU64BE(slot, 24)); // leaf index at [24..32]
    }
  }
  return null;
}

/** Enumerate all deposits for an address: j = 1, 2, 3, … until empty. */
export async function allLeafIndices(address: string): Promise<number[]> {
  const out: number[] = [];
  for (let j = 1; ; j++) {
    const idx = await leafIndexFor(address, j);
    if (idx === null) break;
    out.push(idx);
  }
  return out;
}
