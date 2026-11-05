pragma circom 2.1.0;
include "../circomlib/circuits/poseidon.circom";

template Poseidon2() {
    signal input a;
    signal input b;
    signal output out;
    component p = Poseidon(2);
    p.inputs[0] <== a;
    p.inputs[1] <== b;
    out <== p.out;
}

template Poseidon3() {
    signal input a;
    signal input b;
    signal input c;
    signal output out;
    component p = Poseidon(3);
    p.inputs[0] <== a;
    p.inputs[1] <== b;
    p.inputs[2] <== c;
    out <== p.out;
}
