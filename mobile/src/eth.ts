// Self-custodial EVM wallet: a BIP-39 mnemonic held in the OS keystore, the
// secp256k1 key derived from it at m/44'/60'/0'/0/0, balances read on-chain.

import * as SecureStore from 'expo-secure-store';
import { HDKey } from '@scure/bip32';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

const MNEMONIC_KEY = 'zetta.evm.mnemonic';
const DERIVATION_PATH = "m/44'/60'/0'/0/0";

export function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

/** 12-word BIP-39 mnemonic, created on first use, persisted across launches. */
export async function getOrCreateMnemonic(): Promise<string> {
  const existing = await SecureStore.getItemAsync(MNEMONIC_KEY);
  if (existing) return existing;
  const mnemonic = generateMnemonic(wordlist); // 128-bit entropy → 12 words
  await SecureStore.setItemAsync(MNEMONIC_KEY, mnemonic);
  return mnemonic;
}

/** Overwrite the mnemonic (restore from backup). Throws if invalid. */
export async function setMnemonic(mnemonic: string): Promise<void> {
  const normalized = mnemonic.trim().toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) throw new Error('Invalid mnemonic');
  await SecureStore.setItemAsync(MNEMONIC_KEY, normalized);
}

/** 32-byte secp256k1 private key derived at m/44'/60'/0'/0/0. */
export function privateKeyFromMnemonic(mnemonic: string): Uint8Array {
  const seed = mnemonicToSeedSync(mnemonic);
  const child = HDKey.fromMasterSeed(seed).derive(DERIVATION_PATH);
  const key = child.privateKey; // Uint8Array(32)
  if (!key) throw new Error('HD derivation produced no private key');
  return key;
}

/** 0x + 40-hex address from a 32-byte private key. */
export function evmAddress(secret: Uint8Array): `0x${string}` {
  const pub = secp256k1.getPublicKey(secret, false); // 65 bytes, 0x04-prefixed
  const h = keccak_256(pub.subarray(1));             // hash the 64-byte point
  const addr = h.subarray(12);                       // low 20 bytes
  return `0x${[...addr].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
}

export interface Wallet {
  mnemonic: string;
  privateKey: Uint8Array;
  address: `0x${string}`;
}

export async function getOrCreateWallet(): Promise<Wallet> {
  const mnemonic = await getOrCreateMnemonic();
  const privateKey = privateKeyFromMnemonic(mnemonic);
  return { mnemonic, privateKey, address: evmAddress(privateKey) };
}

/** ERC-20 balanceOf(owner) via eth_call. Returns raw base units (6-dec for USDC/zUSDC). */
export async function tokenBalance(
  rpc: string,
  token: `0x${string}`,
  owner: `0x${string}`,
): Promise<bigint> {
  const data = '0x70a08231' + owner.slice(2).padStart(64, '0'); // balanceOf(address)
  const res = await fetch(rpc, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'eth_call',
      params: [{ to: token, data }, 'latest'],
    }),
  });
  if (!res.ok) throw new Error(`eth_call failed: ${res.status}`);
  const { result, error } = (await res.json()) as {
    result?: string;
    error?: { message: string };
  };
  if (!result) throw new Error(error?.message ?? 'eth_call error');
  return BigInt(result);
}
