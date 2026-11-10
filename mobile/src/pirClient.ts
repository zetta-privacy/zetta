import * as SecureStore from 'expo-secure-store';
import { Client } from './crypto/pir';

const SEED_KEY = 'zetta.pir.seed';
const SERVER = process.env.EXPO_PUBLIC_SERVER_URL;
const PP_LEN = 8_126_496;
const QUERY_LEN = 16_416;

function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function getOrCreateSeed(): Promise<Uint8Array> {
  const existing = await SecureStore.getItemAsync(SEED_KEY);
  if (existing) return hexToBytes(existing);
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed); // polyfilled in index.ts
  await SecureStore.setItemAsync(SEED_KEY, bytesToHex(seed));
  return seed;
}

/** PIR-read the 32-byte item at `index` in `level`'s DB. */
export async function pirRead(index: number, level: number): Promise<Uint8Array> {
  const seed = await getOrCreateSeed();
  const client = new Client();
  client.initFromSeed(seed);

  const pp = client.generatePublicParams();   // ~8 MB — cache this per session
  const query = client.generateQuery(index);

  // request = pp ‖ num_queries(1) ‖ level(1) ‖ query
  const body = new Uint8Array(PP_LEN + 1 + 1 + QUERY_LEN);
  body.set(pp, 0);
  body[PP_LEN] = 1;
  body[PP_LEN + 1] = level;
  body.set(query, PP_LEN + 2);

  const res = await fetch(`${SERVER}/pir`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body,
  });
  const resp = new Uint8Array(await res.arrayBuffer());
  // response = [len(u32 LE)] ‖ [bytes]
  const len = new DataView(resp.buffer, 0, 4).getUint32(0, true);
  return client.decodeResponse(resp.slice(4, 4 + len));
}
