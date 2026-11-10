import { groth16 } from 'snarkjs';
import { Asset } from 'expo-asset';

export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

export async function proveWithdraw(
  input: Record<string, unknown>,
): Promise<{ proof: Groth16Proof; publicSignals: string[] }> {
  const wasm = Asset.fromModule(require('../assets/withdraw.wasm'));
  const zkey = Asset.fromModule(require('../assets/withdraw_final.zkey'));
  await Promise.all([wasm.downloadAsync(), zkey.downloadAsync()]);

  const { proof, publicSignals } = await groth16.fullProve(
    input,
    wasm.localUri ?? wasm.uri,
    zkey.localUri ?? zkey.uri,
  );
  return { proof: proof as Groth16Proof, publicSignals };
}
