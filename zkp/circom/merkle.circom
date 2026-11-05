pragma circom 2.1.0;
include "./poseidon.circom";

template MerkleRoot(levels) {
    signal input leaf;
    signal input pathIndices[levels];
    signal input siblings[levels];
    signal output root;

    component h[levels];
    signal acc[levels + 1];
    acc[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // pathIndices[i] must be a bit (0 or 1)
        pathIndices[i] * pathIndices[i] === pathIndices[i];

        h[i] = Poseidon2();

        // left = (bit==0) ? acc[i] : siblings[i]
        //      = (siblings[i] - acc[i]) * bit + acc[i]
        h[i].a <== (siblings[i] - acc[i]) * pathIndices[i] + acc[i];

        // right = acc[i] + siblings[i] - left
        //       = (bit==0) ? siblings[i] : acc[i]
        h[i].b <== acc[i] + siblings[i] - h[i].a;

        acc[i + 1] <== h[i].out;
    }

    root <== acc[levels];
}
