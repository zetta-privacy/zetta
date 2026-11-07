pragma circom 2.1.0;
include "./poseidon.circom";
include "./merkle.circom";

// Batched root transition: fold N transfers (to, value) into the tree + hash
// chain, from (startIndex, startHashChain, startRoot) to (endIndex, endHashChain, endRoot).
//
//   emptyLeaf = poseidon2(0, 0)
//   for each transfer k:
//     verify  root_k            == merkleRoot(pathIndices_k, emptyLeaf, siblings_k)  // slot empty
//     leaf_k = poseidon2(to_k, value_k)
//     root_{k+1}      = merkleRoot(pathIndices_k, leaf_k, siblings_k)
//     hashChain_{k+1} = poseidon3(hashChain_k, to_k, value_k)   // == PoseidonT4 on-chain
//     index_{k+1}     = index_k + 1
//
// Public: [startIndex, startHashChain, startRoot, endIndex, endHashChain, endRoot]

template RootTransition(levels, N) {
    signal input startIndex;
    signal input startHashChain;
    signal input startRoot;
    signal input to[N];
    signal input value[N];
    signal input pathIndices[N][levels];
    signal input siblings[N][levels];

    signal input endIndex;
    signal input endHashChain;
    signal input endRoot;

    component emptyLeaf = Poseidon2();
    emptyLeaf.a <== 0;
    emptyLeaf.b <== 0;

    signal index[N + 1];
    signal hashChain[N + 1];
    signal root[N + 1];
    index[0] <== startIndex;
    hashChain[0] <== startHashChain;
    root[0] <== startRoot;

    component leaf[N];
    component mEmpty[N];
    component mNew[N];
    component hc[N];
    for (var k = 0; k < N; k++) {
        // leaf = poseidon2(to, value)
        leaf[k] = Poseidon2();
        leaf[k].a <== to[k];
        leaf[k].b <== value[k];

        // the slot at pathIndices[k] must currently hold the empty leaf
        mEmpty[k] = MerkleRoot(levels);
        mEmpty[k].leaf <== emptyLeaf.out;
        for (var i = 0; i < levels; i++) {
            mEmpty[k].pathIndices[i] <== pathIndices[k][i];
            mEmpty[k].siblings[i] <== siblings[k][i];
        }
        mEmpty[k].root === root[k];

        // new root after inserting leaf[k]
        mNew[k] = MerkleRoot(levels);
        mNew[k].leaf <== leaf[k].out;
        for (var i = 0; i < levels; i++) {
            mNew[k].pathIndices[i] <== pathIndices[k][i];
            mNew[k].siblings[i] <== siblings[k][i];
        }
        root[k + 1] <== mNew[k].root;

        // hash-chain step (poseidon3 == PoseidonT4.hash([hc, to, value]))
        hc[k] = Poseidon3();
        hc[k].a <== hashChain[k];
        hc[k].b <== to[k];
        hc[k].c <== value[k];
        hashChain[k + 1] <== hc[k].out;

        index[k + 1] <== index[k] + 1;
    }

    endIndex === index[N];
    endHashChain === hashChain[N];
    endRoot === root[N];
}

component main { public [startIndex, startHashChain, startRoot, endIndex, endHashChain, endRoot] } = RootTransition(32, 16);
