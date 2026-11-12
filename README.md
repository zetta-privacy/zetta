# zetta

Private ERC-20 transfers via ZK proof-of-burn.

A private "transfer" is a **burn + mint**. Money goes into a dead-looking address; the rightful owner later proves ownership in zero knowledge and the contract mints the same amount back to a public withdrawal address. There is no on-chain link between the deposit and the withdrawal — the deposit address has no owner, and the proof reveals nothing about *which* deposits it redeems.

## Core idea

**Burn addresses.** The burn address is derived from a single master secret, not registered:

```
secret_i     = poseidon2( secret_key, i )          // per-address secret
burn_address = low160( poseidon2( recipient, secret_i ) )
```

- `recipient` is a namespace the exchange publishes: `trim246( keccak(chain_id ‖ exchange_addr) )`.
- `secret_key` is the user's single master secret, held only in the phone's secure enclave. Each address index `i` derives a fresh per-address `secret_i`, so every top-up lands at a brand-new address with no history and no on-chain owner — yet the whole set is recoverable from one secret.

Depositing is a plain ERC-20 `transfer`: no special contract call, no UI fingerprint. A deposit is cryptographically indistinguishable from burning the tokens (plausible deniability).

**On-chain trail.** `zERC20._update` appends every non-mint transfer to a Poseidon hash chain (`burnHashChain`, `burnIndex`); a `VALUE_LIMIT < 2²⁴⁸` keeps values inside the field. The server mirrors the chain and inserts `poseidon2(address, value)` leaves into a depth-32 Poseidon Merkle tree, publishing the new `transferRoot`.

**Claim.** The user proves ownership of their deposits on-device and redeems them: for each leaf, the circuit enforces the address derivation (`poseidon2(recipient, secret)`), Merkle membership against `transferRoot`, a strictly increasing index, and range checks. The contract recomputes `recipient`, verifies the proof, and mints `sum − totalWithdrawn[recipient]` to the withdrawal address — cumulative per-recipient accounting, so top-ups and partial withdrawals compose and no spend registry exists.

## How the cryptography enables privacy

**Poseidon everywhere.** The same ZK-friendly hash runs natively in the contract, the Rust server, the circuits, and the mobile client — byte-identical results. This is what lets the contract, prover, and client agree without trusting each other's representation.

**Nova + Groth16 (folding schemes).** A "root transition" proves that, given the previous `(index, hashChain, root)` and a batch of transfers, the new state is correct. Rather than one SNARK per transfer (verified `N` times on-chain), Nova IVC *folds* the `N` step circuits into one running instance, and a single Groth16 "decider" proof is produced for the whole batch. The contract verifies that one constant-size proof, so the per-transfer gas cost trends toward a constant.

**Circom proof on the phone.** The withdrawal circuit (`zkp/circom/withdraw.circom`) is executed entirely on-device with `groth16.fullProve`. Secrets never leave the phone; the proof is the only thing sent to the chain.

**PIR (Spiral).** To build the proof the client needs Merkle sibling paths, but asking the server for them would leak which deposits are being redeemed. Instead the client sends an encrypted query and the server responds without learning the index — it sees only ciphertexts.

**OPRF + Cuckoo hashing.** The server holds a keyed index (`address, j → leaf index`), but can only be navigated by the legitimate key-holder: the client blind-hashes the lookup key (OPRF), derives two Cuckoo bucket positions, and PIR-reads them. A passive server cannot correlate or enumerate a user's deposits.

**Privy server wallet.** The operator's signing keys live in Privy's TEE; the process only holds API credentials, so `updateRoot` / `reserveHashChain` / `setVerifiers` are signed without ever holding raw key material.

The operator is a **prover, not a trusted party** — the worst a malicious operator can do is stall, not forge a root or mint unbacked value.

Full detail: `DOC.md`.
