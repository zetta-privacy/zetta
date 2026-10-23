// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {zERC20} from "./zERC20.sol";

interface IRootTransitionVerifier {
    function verifyOpaqueNovaProof(uint256[32] calldata proof) external view returns (bool);
}

interface IWithdrawVerifier {
    function verifyOpaqueNovaProof(uint256[34] calldata proof) external view returns (bool);
}

contract Verifier {
    zERC20 public token;

    // Single ever-growing tree (depth 32). Frontier = state proven on-chain.
    uint256 public transferRoot;
    uint256 public transferIndex;      // leaves folded into transferRoot
    uint256 public transferHashChain;

    uint256 public reservedIndex;
    uint256 public reservedHashChain;

    uint256 public startingRoot;
    uint256 public startingIndex;
    uint256 public startingHashChain;

    mapping(uint256 => uint256) public totalWithdrawn; // recipient => lifetime sum already minted
    mapping(uint256 => uint256) public withdrawnIndex;

    IRootTransitionVerifier public rootTransitionVerifier;
    IWithdrawVerifier public withdrawVerifier;

    address public owner;

    uint256 private constant HASH_CHAIN_MASK = (1 << 246) - 1;
    uint256 private constant TREE_CAPACITY = 1 << 32;

    constructor(zERC20 token_, uint256 initialRoot_) {
        token = token_;
        transferRoot = initialRoot_;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        require(msg.sender == owner, "not owner");
    }

    function setVerifiers(
        IRootTransitionVerifier root_,
        IWithdrawVerifier withdraw_
    ) external onlyOwner {
        rootTransitionVerifier = root_;
        withdrawVerifier = withdraw_;
    }

    /// Snapshot the token's burn hash chain so updateRoot proofs have a stable target.
    function reserveHashChain() external onlyOwner {
        uint256 index = token.burnIndex();
        require(index <= TREE_CAPACITY, "tree full");
        reservedIndex = index;
        reservedHashChain = token.burnHashChain();
    }

    function updateStartingHashChain() external onlyOwner {
        require(reservedIndex - transferIndex >= 2, "reserved not advanced enough");
        startingIndex = transferIndex;
        startingHashChain = transferHashChain;
        startingRoot = transferRoot;
    }

    /// proof = [i, z0[0..3], zi[0..3], 25 decider elements]
    /// z0 = [prevIndex, prevHashChain, prevRoot], zi = [newIndex, newHashChain, newRoot]
    function updateRoot(uint256[32] calldata proof) external {
        uint256 prevIndex = proof[1];
        uint256 prevHashChain = proof[2];
        uint256 prevRoot = proof[3];
        uint256 newIndex = proof[4];
        uint256 newHashChain = proof[5];
        uint256 newRoot = proof[6];

        // starting index is updated manually
        require(prevIndex == startingIndex, "stale index");
        require(prevHashChain == startingHashChain, "stale hash chain");
        require(prevRoot == startingRoot, "stale root");

        // newly computed params check
        require(newIndex > prevIndex, "no progress");
        require(newHashChain == reservedHashChain, "hash chain mismatch");
        require(newIndex == reservedIndex, "hash index mismatch");

        require(rootTransitionVerifier.verifyOpaqueNovaProof(proof), "invalid proof");

        transferRoot = newRoot;
        transferIndex = newIndex;
        transferHashChain = newHashChain;
    }

    /// proof = [i, z0[0..4], zi[0..4], 25 decider elements]
    /// z0[0] is the fold's start index — ordering token only, not checked here.
    function withdraw(uint256 chainId, address addr, bytes32 tweak, uint256[34] calldata proof) external {
        require(chainId == block.chainid, "wrong chain");

        uint256 recipient = computeRecipient(chainId, addr, tweak);

        uint256 prevIndex = proof[1];
        uint256 prevSum = proof[2];
        uint256 root = proof[3];
        uint256 proofRecipient = proof[4];
        uint256 newIndex = proof[5];
        uint256 sum = proof[6];

        require(root == transferRoot, "unknown root");
        require(proofRecipient == recipient, "recipient mismatch");
        require(prevSum == 0, "invalid sum base");
        require(prevIndex == 0, "invalid frontier");

        require(withdrawVerifier.verifyOpaqueNovaProof(proof), "invalid proof");

        uint256 delta = sum - totalWithdrawn[recipient];
        require(delta > 0, "nothing to withdraw");
        totalWithdrawn[recipient] = sum;
        withdrawnIndex[recipient] = newIndex;

        token.teleport(addr, delta);
    }

    function computeRecipient(uint256 chainId, address addr, bytes32 tweak)
        public
        pure
        returns (uint256)
    {
        require(chainId <= type(uint64).max, "chain id too large");
        // casting to 'uint64' is safe because chain ids are bounded by EIP-2294
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 cid = uint64(chainId);
        // forge-lint: disable-next-line(asm-keccak256)
        bytes32 h = keccak256(abi.encodePacked(cid, addr, tweak));
        return uint256(h) & HASH_CHAIN_MASK;
    }
}
