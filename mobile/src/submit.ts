import { createWalletClient, defineChain, encodeFunctionData, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { RPC_URL } from './tokens';

const VERIFIER = '0x…';

const chain = defineChain({
  id: 84532,
  name: 'Base Sepolia',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
});

const withdrawAbi = {
  type: 'function',
  name: 'withdraw',
  inputs: [
    { type: 'uint256', name: 'chainId' },
    { type: 'address', name: 'addr' },
    { type: 'uint256[2]', name: 'a' },
    { type: 'uint256[2][2]', name: 'b' },
    { type: 'uint256[2]', name: 'c' },
    { type: 'uint256[6]', name: 'input' },
  ],
  outputs: [],
  stateMutability: 'nonpayable',
} as const;

function toHex(b: Uint8Array): `0x${string}` {
  return `0x${[...b].map((x) => x.toString(16).padStart(2, '0')).join('')}`;
}

export async function submitWithdraw(
  privateKey: Uint8Array,
  chainId: number,
  addr: string,
  proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[] },
  publicSignals: string[],
): Promise<`0x${string}`> {
  const account = privateKeyToAccount(toHex(privateKey));
  const client = createWalletClient({ account, chain, transport: http(RPC_URL) });

  const a = [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])] as [bigint, bigint];
  const b = [
    [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
    [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
  ] as [[bigint, bigint], [bigint, bigint]];
  const c = [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])] as [bigint, bigint];
  const input = publicSignals.map((s) => BigInt(s)) as [bigint, bigint, bigint, bigint, bigint, bigint];

  const data = encodeFunctionData({
    abi: [withdrawAbi],
    functionName: 'withdraw',
    args: [BigInt(chainId), addr as `0x${string}`, a, b, c, input],
  });

  return await client.sendTransaction({ to: VERIFIER, data });
}
