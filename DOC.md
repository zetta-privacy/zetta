# How Zetta works

Zetta is a **private ERC-20** built on top of the `zERC20` token, an exchange operator (the "server"), and a **mobile wallet**. The headline feature is that a user can move value *into* the system and later pull it *back out* without any on-chain link between the deposit and the withdrawal — there is no owner on the deposit address, and the withdrawal proof reveals nothing about *which* deposits it redeems.

The whole thing is a composition of several cryptographic primitives, each solving one concrete privacy problem. This document walks through the end-to-end flow and, for each step, explains **why that primitive is there and what it buys you in practice**.

---

## 1. The core idea: a transfer is a *burn + mint*

A normal ERC-20 transfer leaves a public trail: `0xAlice → 0xBob, 100 USDC`. Zetta makes the private "transfer" two disjoint on-chain facts:

1. **Burn** — Alice sends tokens to a one-use address that looks like a dead address. On-chain this is indistinguishable from actually destroying the tokens.
2. **Mint** — later, someone proves in zero knowledge that *they* are the rightful owner of some burned tokens, and the contract mints the same total back to a fresh (public) withdrawal address.

The trick that makes this private is that the burn address is **derived from a single master secret**, not registered:

```
secret_i     = poseidon2( secret_key, i )          // per-address secret
burn_address = low160( poseidon2( recipient, secret_i ) )
```

- `recipient` is a namespace the exchange publishes: `trim246( keccak(chain_id ‖ exchange_addr) )`.
- `secret_key` is the user's single master secret, held only in the phone's secure enclave. Each address index `i` derives a fresh per-address `secret_i`, so **every top-up lands at a brand-new address with no history and no on-chain owner** — but the whole set is recoverable from one secret.

Depositing is just a plain ERC-20 `transfer`. There is no special contract call and no UI fingerprint — a deposit is *cryptographically indistinguishable from burning the tokens* (plausible deniability).

**Practical benefit:** the deposit side of privacy is free. You don't need a mixer, a relayer, or a special transaction. A standard `transfer` to a derived address *is* the private deposit.

---

## 2. On-chain state: the hash chain and the Merkle tree

The operator (server) needs to later *prove* that a set of deposits really happened, without the contract having to store every deposit. Two append-only structures carry that state.

### 2.1 `zERC20` hash chain

Every non-mint `transfer` is appended to a Poseidon hash chain inside the token contract itself (`zERC20._update`):

```solidity
burnHashChain = PoseidonT4.hash([burnHashChain, uint256(uint160(to)), value]);
```

This is a single 256-bit accumulator. The server mirrors it off-chain, so it can **detect any divergence or reorg** by comparing its local chain value against the on-chain one (see `worker.rs::sync_chain`). A `VALUE_LIMIT < 2²⁴⁸` keeps every value inside the field, so hashing is lossless.

### 2.2 The depth-32 Poseidon Merkle tree

Each transfer becomes a leaf `poseidon2(address, value)`, inserted into a **depth-32** tree. The server keeps the full history of every level (append-only), so it can serve Merkle proofs for any historical leaf. The current root (`transferRoot`) is the single public commitment that summarizes *all* deposits ever.

**Practical benefit of Poseidon everywhere:** Poseidon is a ZK-friendly hash. The exact same hash runs (a) natively in the contract, (b) natively in the Rust server, (c) in the Circom/R1CS circuits, and (d) in the mobile client — all producing identical outputs. That "one hash, four backends, byte-identical results" property is what lets the contract, the prover, and the client agree without trusting each other's representation. (Verified by `poseidon_var_matches_native`, `hash_chain_step_var_matches_native`, etc.)

---

## 3. Proving the deposits moved: Nova + Groth16 (folding schemes)

The contract can't verify "10,000 deposits happened" by replaying 10,000 hashes — that would be absurdly expensive on-chain. This is where **folding schemes** come in.

### What Nova folding buys you

A "root transition" is the statement: *given the previous `(index, hashChain, root)` and a batch of transfers, the new `(index, hashChain, root)` is correct*. Each transfer is a single step circuit (`RootTransitionCircuit`) that:

- increments the index,
- advances the hash chain by one Poseidon step,
- proves the new Merkle leaf was inserted correctly against the sibling path.

Naively you'd need one SNARK per transfer and then verify *N* SNARKs on-chain. Instead, Zetta uses **Nova IVC**: the `N` step circuits are *folded* into a single running instance, and only **one Groth16 "decider" proof** is produced for the whole batch. The contract verifies *that one proof*.

```rust
// zkp/src/lib.rs — the type aliases
pub type RootN = Nova<G1, G2, RootTransitionCircuit, KZG<'static, Bn254>, Pedersen<G2>, false>;
pub type RootD  = DeciderEth<G1, G2, RootTransitionCircuit, ... Groth16<Bn254>, RootN>;
```

The worker (`worker.rs`) folds a whole epoch of transfers and submits a single `updateRoot(uint256[32] proof)` call:

```
proof = [i, z0[0..3], zi[0..3], 25 decider elements]
```

**Practical benefit:** the *per-transfer* cost of proving is amortized to almost zero. Whether an epoch has 1 transfer or 10,000, the on-chain verification cost is a single constant-size proof (`verifyOpaqueNovaProof`). This is what makes the "always-growing tree" design affordable: the operator can keep proving *every* transfer forever, and the gas cost per transfer trends toward a constant.

### Why the decider is Groth16 (and the ceremony caveat)

The folded Nova proof is wrapped in a **Groth16 decider** because Groth16 has tiny, constant-size proofs and a very cheap on-chain verifier. The trade-off is a trusted setup: the Groth16 keys are per-circuit, and the repo notes these are **single-party setup for development** — a proper ceremony must happen before production (see the `[patch.crates-io]` notes in `Cargo.toml` about the vendored `ark-groth16`).

The whole proving pipeline lives in `zkp/src/lib.rs` behind macros (`nova_artifact_set!`, `prove_for!`, `setup_struct!`) so the same pattern can be re-used for additional circuits (e.g. a future `withdraw` transition).

---

## 4. Withdrawing: a Circom proof computed *on the phone*

The withdrawal is the privacy-critical moment, and it is done **entirely on the user's device**. The user proves they own a set of deposits and redeems them, without revealing which deposits.

### The circuit (`zkp/circom/withdraw.circom`)

`Withdraw(levels=32, N=4)` proves, for up to `N=4` deposit slots:

- **Address derivation** — for each slot, `burnAddr = low160(poseidon2(recipient, secret))` reconstructs the burn address from the recipient namespace and a per-slot secret. The prover must know the `secret` that produced each address (knowledge of the private key).
- **Merkle membership** — each deposit leaf `poseidon2(burnAddr, value)` is proven to be in the tree against `root` (the public `transferRoot`).
- **Freshness** — each real slot's `index` is `> I` (the `withdrawnIndex` frontier), and indices are strictly increasing, so the same deposit can't be spent twice.
- **Padding** — `isPadding` flags are constrained to be real-first-then-padded, monotonic, and value-zero, so a user with fewer than 4 deposits can pad without weakening the proof.
- **Sum binding** — the total `sum` of values is bound to the public `sum` input, and `currentSum = prevSum + sum`.

The public inputs are exactly `[root, recipient, prevIndex, currentIndex, currentSum, prevSum]`. Everything else (the secrets, the actual addresses, the Merkle paths) stays private.

### Generating the proof on-device

The mobile app runs the whole proof client-side (`mobile/src/prove.ts`):

```tsx
const { proof, publicSignals } = await groth16.fullProve(input, wasm.localUri, zkey.localUri);
```

The `withdraw.wasm` circuit and `withdraw_final.zkey` proving key ship as bundled assets. The proof is then submitted to the `Verifier.withdraw(...)` contract call (`mobile/src/submit.ts`).

**Practical benefit — "secrets never leave the device":** the private key and the derived secrets are stored only in the phone's secure enclave (`expo-secure-store`), and the zero-knowledge proof is the *only* thing that leaves the device. The server and the contract learn nothing that lets them link the withdrawal to the deposits. The Groth16 proof is a compact, constant-size attestation that "I control some deposits worth `delta`", no more and no less.

The contract (`Verifier.withdraw`) then:

1. recomputes `recipient` from `(chainid, addr)` and checks it matches the proof,
2. checks `root == transferRoot` and the `prevIndex/prevSum` frontiers,
3. verifies the Groth16 proof,
4. mints `delta = currentSum - prevSum` to the withdrawal address, and records `totalWithdrawn[recipient]` / `withdrawnIndex[recipient]` **cumulatively per-recipient**.

Cumulative per-recipient accounting (rather than a per-deposit nullifier/spend registry) is what lets top-ups and partial withdrawals compose cleanly, with no on-chain set of "spent" leaves.

---

## 5. Private Merkle-path lookup: PIR (private information retrieval)

To build the withdrawal proof, the client needs the **Merkle sibling path** for each of its deposit leaves. The obvious way — asking the server "give me the siblings for index `i`" — would leak *which* deposits the user is redeeming, defeating the privacy.

### What PIR buys you

Instead, the client uses **single-server PIR (Spiral)**. The server holds one database per tree level (32 levels) plus a Cuckoo-index DB and a values DB (`pir.rs`). The client sends an **encrypted query** for "give me item at index `i`" and the server computes the response **without learning `i`**:

```rust
// main.rs — the PIR endpoint
async fn pir_handler(.., body: Bytes) -> Vec<u8> {
    // body = pp ‖ num_queries ‖ [ level ‖ query ]*
    // response = [ len ‖ bytes ]*   for each query
}
```

The query is a lattice-based (Regev/GSW) homomorphic encryption ciphertext. The server runs `process_query` over the DB and returns an encrypted answer that only the client can decrypt. The server sees *ciphertexts*, never *which index was requested*.

The client implements the full PIR stack in TypeScript (`mobile/src/crypto/pir.ts` — a hand-ported Spiral client with NTT, CRT, and GSW gadgets) and reads the Merkle siblings via `pirRead(index, level)`.

### Why the index is still derivable

The user knows their own deposits' leaf indices, but they discover them privately too:

1. The server builds a **Cuckoo hash table** keyed by `(address, j)` (address + deposit ordinal) → leaf index (`cuckoo.rs`).
2. To find the leaf index for their `j`th deposit, the client computes the **OPRF** of `(address, j)` (see below), which yields the two Cuckoo slot positions, then PIR-reads both slots and matches on the key.

So neither the *identity* of the deposits nor the *indices* are ever revealed to the server.

**Practical benefit:** the server can host the entire ever-growing Merkle history *and* a lookup index, and the user can still query it with **cryptographic privacy** — the server is functionally blind to what any user is looking at. This is the piece that lets a centralized operator provide "convenience" (fast lookups, always-fresh state) without being a privacy liability.

---

## 6. Private index discovery: OPRF + Cuckoo hashing

The Cuckoo table positions are computed from a **PRF**, but the server must not learn the PRF key *or* be able to compute the positions itself (else it could learn which deposits a user is checking).

### Oblivious PRF (OPRF)

The client and server run a **2HashDH-style OPRF** over the bn254 scalar field (`oprf.rs` / `mobile/src/oprf.ts`):

1. Client hashes `x = address ‖ j` into the field: `H1(x)`, blinds it with a random `r`, and sends `B = H1(x)·r`.
2. Server evaluates with its secret key `k`: `C = B^k` (the `/oprf/evaluate` endpoint).
3. Client unblinds `C^(1/r) = H1(x)^k` and finalizes `PRF(k, x) = H2(x, H1(x)^k)`.

The client learns the PRF output; the server learns nothing about `x` (it only sees a blinded group element). The PRF output splits into **two Cuckoo bucket positions** (`positions()`), and the client PIR-reads exactly those two buckets.

**Practical benefit:** the server holds a *keyed* index that only the legitimate key-holder can navigate. A passive server (or anyone observing the traffic) cannot correlate a user's lookups to a deposit, because (a) the lookup key is hidden by the OPRF and (b) the bucket read is hidden by PIR. It also prevents enumeration: the server cannot precompute "which deposits belong to which address" without the user's blinding.

---

## 7. The worker: keeping the mirror honest

The Rust `worker.rs` runs the operator side in a loop with three phases per tick:

1. **Prepare** — catch the local mirror up to the proven on-chain prefix, checking that the locally-derived hash chain and tree root **exactly match** the contract's `transferHashChain` / `transferRoot`. Any divergence aborts (reorg / gap detection).
2. **Reserve** — call `reserveHashChain()` to pin an epoch target (`reservedIndex`, `reservedHashChain`) so the upcoming proof races cleanly against new transfers.
3. **Process** — fold the fresh transfers with Nova, produce the Groth16 decider proof, and submit `updateRoot`.

The design guarantees the operator can't *forge* a root: the contract re-derives and re-checks the starting and ending `(index, hashChain, root)` and only accepts a root transition if a valid ZK proof certifies it. The operator is a *prover*, not a *trusted* party — the worst a malicious operator can do is stall (denial), not mint unbacked value.

---

## 8. Putting it together: a full private round-trip

```
Deposit (private in):
  user: burn_address = low160(poseidon2(recipient, secret_i))
        plain ERC-20 transfer → burn_address          (looks like a burn)

Operator (continuously):
  mirrors zERC20 hash chain + Poseidon Merkle tree
  folds each epoch with Nova → Groth16 decider → updateRoot(root)

Withdraw (private out):
  user: discovers own leaf indices via OPRF + PIR (server blind)
        reads Merkle siblings via PIR                    (server blind)
        builds withdraw.circom input on-device
        groth16.fullProve → proof (only thing that leaves device)

  contract: verifies proof, recomputes recipient, mints sum − totalWithdrawn
```

At no point is there an on-chain or server-side link between the deposit and the withdrawal.
