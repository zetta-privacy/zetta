// Persistent self-custodial PIR client. The secret seed lives in the OS
// keystore; secret keys, public params, and queries are derived from it. The
// server answers each query without learning which leaf was requested.

import * as SecureStore from 'expo-secure-store';
import { ChaCha20Rng } from './crypto/chacha20';
import { Client } from './crypto/pir';

const PIR_SEED_KEY = 'zetta.pir.seed';
const PIR_PP_KEY = 'zetta.pir.pp';

function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function getOrCreateSeed(): Promise<Uint8Array> {
  const existing = await SecureStore.getItemAsync(PIR_SEED_KEY);
  if (existing) return hexToBytes(existing);
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  await SecureStore.setItemAsync(PIR_SEED_KEY, bytesToHex(seed));
  return seed;
}

/** Public params are public but ~8 MB and slow to build — cache to a file in
 *  production; regenerating here keeps the first version dependency-free. */
async function publicParams(client: Client): Promise<Uint8Array> {
  const cached = await SecureStore.getItemAsync(PIR_PP_KEY);
  if (cached) return hexToBytes(cached);
  const pp = client.generatePublicParams();
  return pp; // NOTE: SecureStore has a ~2 KB/entry limit — do NOT persist pp there
}

export async function pirRetrieveLeaf(index: number): Promise<Uint8Array> {
  const seed = await getOrCreateSeed();
  const client = new Client();
  client.initFromSeed(seed);
  const pp = await publicParams(client);
  const query = client.generateQuery(index);

  const body = new Uint8Array(pp.length + query.length);
  body.set(pp, 0);
  body.set(query, pp.length);

  const res = await fetch(`${process.env.EXPO_PUBLIC_SERVER_URL}/pir`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body,
  });
  if (!res.ok) throw new Error(`pir failed: ${res.status}`);
  const response = new Uint8Array(await res.arrayBuffer());
  return client.decodeResponse(response); // 32-byte leaf

}
