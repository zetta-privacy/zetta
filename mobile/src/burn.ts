import { poseidon2 } from 'poseidon-lite';
import * as SecureStore from 'expo-secure-store';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3'

// bn254 scalar field r (== poseidon-lite's field)
const R =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const SECRET_KEY_STORAGE = 'zetta.burn.secretKey';
const BURN_KEY = 'zetta.burn.addresses';
const HASH_CHAIN_MASK = (1n << 246n) - 1n;

export interface BurnAddressEntry {
  address: string;   // 0x…
  index: number;     // the address index i (0, 1, 2, …)
  createdAt: number; // unix ms
}

function randomSecretKey(): bigint {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf); // polyfilled in index.ts
  let v = 0n;
  for (const b of buf) v = (v << 8n) | BigInt(b);
  return v % R;
}

/** The single master secret key, created once, persisted. */
export async function getOrCreateSecretKey(): Promise<bigint> {
  const existing = await SecureStore.getItemAsync(SECRET_KEY_STORAGE);
  if (existing) return BigInt(existing);
  const key = randomSecretKey();
  await SecureStore.setItemAsync(SECRET_KEY_STORAGE, key.toString(10));
  return key;
}

/** Deterministic secret for address index i: secret_i = poseidon2(secret_key, i). */
export function deriveSecret(secretKey: bigint, i: number): bigint {
  return poseidon2([secretKey, BigInt(i)]);
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

function bytesToBigIntBE(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

function addressToFr(addr: string): bigint {
  return BigInt(addr.replace(/^0x/, '').toLowerCase() || '0');
}

/** recipient = trim246( keccak256(chain_id ‖ addr) ). */
export function recipient(chainId: number, addr: string): bigint {
  const buf = new Uint8Array(8 + 20);
  for (let i = 0; i < 8; i++) buf[i] = Number((BigInt(chainId) >> BigInt(8 * (7 - i))) & 0xffn);
  const hex = addr.replace(/^0x/, '').toLowerCase();
  for (let i = 0; i < 20; i++) buf[8 + i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytesToBigIntBE(keccak_256(buf)) & HASH_CHAIN_MASK;
}

/** burn address = trim160( poseidon2(recipient, secret_i) ). */
export function burnAddress(chainId: number, addr: string, secretKey: bigint, i: number): `0x${string}` {
  const rec = recipient(chainId, addr);
  const secret = deriveSecret(secretKey, i);
  const burn = poseidon2([rec, secret]);
  return `0x${burn.toString(16).padStart(64, '0').slice(24)}`;
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
