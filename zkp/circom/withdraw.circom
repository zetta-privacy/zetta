pragma circom 2.1.0;
include "./poseidon.circom";
include "./merkle.circom";
include "../circomlib/circuits/comparators.circom";

template Withdraw(levels, N) {
    signal input root;
    signal input recipient;
    signal input I;
    signal input currentIndex;
    signal input secret;
    signal input isPadding[N];
    signal input values[N];
    signal input indices[N];
    signal input pathIndices[N][levels];
    signal input siblings[N][levels];

    component burnAddr = Poseidon2();
    burnAddr.a <== recipient;
    burnAddr.b <== secret;

    component leaf[N];
    component m[N];
    for (var k = 0; k < N; k++) {
        // real: leaf = poseidon2(burnAddr, value); padding: value forced 0
        leaf[k] = Poseidon2();
        leaf[k].a <== burnAddr.out;
        leaf[k].b <== values[k];
        // padding slot must have zero value
        values[k] * isPadding[k] === 0;

        m[k] = MerkleRoot(levels);
        m[k].leaf <== leaf[k].out;
        for (var i = 0; i < levels; i++) {
            m[k].pathIndices[i] <== pathIndices[k][i];
            m[k].siblings[i] <== siblings[k][i];
        }
        m[k].root === root;
    }

    // real indices > I
    component gt[N];
    for (var k = 0; k < N; k++) {
        gt[k] = GreaterThan(40);
        gt[k].in[0] <== indices[k];
        gt[k].in[1] <== I;
        // for real slots: gt == 1
        gt[k].out === 1 - isPadding[k];
    }

    // strictly increasing (real slots; padding follows the same order)
    component inc[N - 1];
    for (var k = 0; k < N - 1; k++) {
        inc[k] = LessThan(40);
        inc[k].in[0] <== indices[k];
        inc[k].in[1] <== indices[k + 1];
        inc[k].out === 1;
    }

    // isPadding must be monotonic: 0..0 1..1 (no real slot after a padding slot)
    for (var k = 0; k < N; k++) {
        isPadding[k] * (1 - isPadding[k]) === 0;   // flag is a bit
        values[k] * isPadding[k] === 0;            // padding ⇒ value 0
    }

    for (var k = 0; k < N - 1; k++) {
        isPadding[k] * (1 - isPadding[k + 1]) === 0; // real entries first, then padding
    }

    // (A) freshness guard — CONFIRM semantics:
    max_real_index + padding_count == currentIndex
}

component main { public [root, recipient, I, currentIndex] } = Withdraw(32, 16);
