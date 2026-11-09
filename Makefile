# zetta/Makefile
withdraw:
	circom zkp/circom/withdraw.circom --r1cs --wasm --sym -o zkp/build

.PHONY: artifacts
withdraw-artifacts:
	mkdir -p artifacts
	circom zkp/circom/withdraw.circom --r1cs --wasm --sym -o artifacts
	snarkjs powersoftau new bn128 19 artifacts/pot19_0000.ptau
	snarkjs powersoftau prepare phase2 artifacts/pot19_0000.ptau artifacts/pot19_final.ptau
	snarkjs groth16 setup artifacts/withdraw.r1cs artifacts/pot20_final.ptau artifacts/withdraw_final.zkey
