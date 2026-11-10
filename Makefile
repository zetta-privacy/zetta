# zetta/Makefile
withdraw:
	circom zkp/circom/withdraw.circom --r1cs --wasm --sym -o zkp/build

.PHONY: artifacts
withdraw-artifacts:
	mkdir -p artifacts mobile/assets
	circom zkp/circom/withdraw.circom --r1cs --wasm --sym -o artifacts
	snarkjs powersoftau new bn128 17 artifacts/pot17_0000.ptau
	snarkjs powersoftau prepare phase2 artifacts/pot17_0000.ptau artifacts/pot17_final.ptau
	snarkjs groth16 setup artifacts/withdraw.r1cs artifacts/pot17_final.ptau artifacts/withdraw_final.zkey
	cp artifacts/withdraw_js/withdraw.wasm mobile/assets/withdraw.wasm
	cp artifacts/withdraw_final.zkey mobile/assets/withdraw_final.zkey

withdraw-verifiers:
	snarkjs zkey export solidityverifier artifacts/withdraw_final.zkey artifacts/withdraw_verifier.sol
	snarkjs zkey export verificationkey artifacts/withdraw_final.zkey artifacts/withdraw_vkey.json
	cp artifacts/withdraw_verifier.sol contracts/src/verifiers/WithdrawVerifier.sol
