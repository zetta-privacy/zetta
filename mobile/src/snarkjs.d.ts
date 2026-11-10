declare module 'snarkjs' {
  export const groth16: {
    fullProve(
      input: unknown,
      wasmFile: string,
      zkeyFile: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    verify(
      vk: unknown,
      publicSignals: string[],
      proof: unknown,
    ): Promise<boolean>;
  };
}
