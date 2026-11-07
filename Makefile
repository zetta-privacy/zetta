# zetta/Makefile
withdraw:
	circom zkp/circom/withdraw.circom --r1cs --wasm --sym -o zkp/build

root:
	circom zkp/circom/root.circom --r1cs --wasm --sym -o zkp/build
