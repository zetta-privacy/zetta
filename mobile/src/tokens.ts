/** zUSDC + USDC on Base Sepolia (contracts in web/data/addresses.json). */
export const RPC_URL = process.env.EXPO_PUBLIC_RPC_URL ?? 'https://sepolia.base.org';

export interface Token {
  id: string;
  name: string;
  symbol: string;
  address: `0x${string}`;
  decimals: number;
}

export const TOKENS: Token[] = [
  {
    id: 'zusdc',
    name: 'Zetta USD',
    symbol: 'zUSDC',
    address: '0x51d9B745C3c4A18987517C61428051629A13ccdd',
    decimals: 6,
  },
  {
    id: 'usdc',
    name: 'USD Coin',
    symbol: 'USDC',
    address: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    decimals: 6,
  },
];
