pragma circom 2.1.0;
include "./poseidon.circom";
include "./merkle.circom";
include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/bitify.circom";

template Withdraw(levels, N) {
    signal input root;
    signal input recipient;
    signal input I;
    signal input currentIndex;
    signal input secret[N];
    signal input isPadding[N];
    signal input values[N];
    signal input indices[N];
    signal input pathIndices[N][levels];
    signal input siblings[N][levels];
    signal input sum;

    component leaf[N];
    component m[N];
    for (var k = 0; k < N; k++) {
        // per-slot burn address: low 160 bits of poseidon2(recipient, secret[k])
        component burnAddrFull = Poseidon2();
        burnAddrFull.a <== recipient;
        burnAddrFull.b <== secret[k];
        component burnBits = Num2Bits(254);
        burnBits.in <== burnAddrFull.out;
        component burnAddrNum = Bits2Num(160);
        for (var i = 0; i < 160; i++) {
            burnAddrNum.in[i] <== burnBits.out[i];
        }

        leaf[k] = Poseidon2();
        leaf[k].a <== burnAddrNum.out;
        leaf[k].b <== values[k];
        values[k] * isPadding[k] === 0;

        m[k] = MerkleRoot(levels);
        m[k].leaf <== leaf[k].out;
        for (var i = 0; i < levels; i++) {
            m[k].pathIndices[i] <== pathIndices[k][i];
            m[k].siblings[i] <== siblings[k][i];
        }
        (1 - isPadding[k]) * (m[k].root - root) === 0;
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
    signal realPair[N - 1];
    for (var k = 0; k < N - 1; k++) {
        inc[k] = LessThan(40);
        inc[k].in[0] <== indices[k];
        inc[k].in[1] <== indices[k + 1];
        realPair[k] <== (1 - isPadding[k]) * (1 - isPadding[k + 1]); // quadratic
        realPair[k] * (1 - inc[k].out) === 0;                         // quadratic
    }

    // isPadding must be monotonic: 0..0 1..1 (no real slot after a padding slot)
    for (var k = 0; k < N; k++) {
        isPadding[k] * (1 - isPadding[k]) === 0;   // flag is a bit
        values[k] * isPadding[k] === 0;            // padding ⇒ value 0
    }

    for (var k = 0; k < N - 1; k++) {
        isPadding[k] * (1 - isPadding[k + 1]) === 0; // real entries first, then padding
    }

    // total value carried by the (real) deposits, bound to the public input `sum`
    signal acc[N];
    acc[0] <== values[0];
    for (var k = 1; k < N; k++) {
        acc[k] <== acc[k-1] + values[k];
    }
    sum === acc[N-1];

    // freshness: currentIndex > every index (real and padding)
    component fresh[N];
    for (var k = 0; k < N; k++) {
        fresh[k] = LessThan(40);
        fresh[k].in[0] <== indices[k];
        fresh[k].in[1] <== currentIndex;
        fresh[k].out === 1;
    }
}

component main { public [root, recipient, I, currentIndex, sum] } = Withdraw(32, 4);
