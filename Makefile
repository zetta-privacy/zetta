# zetta/Makefile
circom:
	cd zkp/circom && circom withdraw.circom --r1cs --wasm --sym -o build
