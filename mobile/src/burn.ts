// Burn address derivation (regular-wallet product):
//   burnAddress = low 160 bits of keccak256(recipient ‖ secret_key)
// `recipient` is the wallet's default EVM address (20 bytes); `secret_key` is a
// random 256-bit number held in storage. A fresh secret_key mints a fresh address.

import { keccak_256 } from '@noble/hashes/sha3.js';

function be32(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function addressBytes(recipient: string): Uint8Array {
  const hex = recipient.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(hex)) throw new Error('recipient must be 0x + 40 hex');
  const out = new Uint8Array(20);
  for (let i = 0; i < 20; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** keccak256(recipient_20 ‖ secret_key_32), as a bigint. */
export function burnHash(recipient: string, secretKey: bigint): bigint {
  const data = new Uint8Array(52);
  data.set(addressBytes(recipient), 0);
  data.set(be32(secretKey), 20);
  const h = keccak_256(data);
  let v = 0n;
  for (const b of h) v = (v << 8n) | BigInt(b);
  return v;
}

/** Burn address = low 160 bits of the hash, 0x-prefixed. */
export function burnAddress(recipient: string, secretKey: bigint): `0x${string}` {
  const h = burnHash(recipient, secretKey);
  return `0x${h.toString(16).padStart(64, '0').slice(24)}`;
}

// Persisted list of created burn addresses (secret + address + timestamp).

import * as SecureStore from 'expo-secure-store';

export interface BurnAddressEntry {
  address: string;   // 0x…
  secretKey: string; // decimal
  createdAt: number; // unix ms
}

const BURN_KEY = 'zetta.burn.addresses';

/** Fresh random 256-bit secret. */
export function randomSecretKey(): bigint {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf); // polyfilled in index.ts (RN)
  let v = 0n;
  for (const b of buf) v = (v << 8n) | BigInt(b);
  return v;
}

export async function listBurnAddresses(): Promise<BurnAddressEntry[]> {
  const v = await SecureStore.getItemAsync(BURN_KEY);
  return v ? (JSON.parse(v) as BurnAddressEntry[]) : [];
}

export async function addBurnAddress(entry: BurnAddressEntry): Promise<void> {
  const list = await listBurnAddresses();
  list.unshift(entry);
  await SecureStore.setItemAsync(BURN_KEY, JSON.stringify(list));
}
