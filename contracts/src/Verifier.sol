// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {zERC20} from "./zERC20.sol";

interface IRootTransitionVerifier {
    function verifyOpaqueNovaProof(uint256[32] calldata proof) external view returns (bool);
}

interface IWithdrawVerifier {
    function verifyProof(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[6] calldata input
    ) external view returns (bool);
}

contract Verifier {
    zERC20 public token;

    // Single ever-growing tree (depth 32). Frontier = state proven on-chain.
    uint256 public transferRoot;
    uint256 public transferIndex;      // leaves folded into transferRoot
    uint256 public transferHashChain;

    uint256 public reservedIndex;
    uint256 public reservedHashChain;

    uint256 public startRoot;
    uint256 public startIndex;
    uint256 public startHashChain;

    mapping(uint256 => uint256) public totalWithdrawn; // recipient => lifetime sum already minted
    mapping(uint256 => uint256) public withdrawnIndex;

    IRootTransitionVerifier public rootTransitionVerifier;
    IWithdrawVerifier public withdrawVerifier;

    address public owner;
    uint256 public tweak;

    uint256 private constant HASH_CHAIN_MASK = (1 << 246) - 1;
    uint256 private constant TREE_CAPACITY = 1 << 32;

    constructor(zERC20 token_, uint256 initialRoot_) {
        token = token_;
        transferRoot = initialRoot_;
        startRoot = initialRoot_;
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

    function updateStartHashChain() external onlyOwner {
        require(reservedIndex - transferIndex >= 2, "reserved not advanced enough");
        startIndex = transferIndex;
        startHashChain = transferHashChain;
        startRoot = transferRoot;
    }

    function rotateTweak() external onlyOwner {
        tweak += 1;
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
        require(prevIndex == startIndex, "stale index");
        require(prevHashChain == startHashChain, "stale hash chain");
        require(prevRoot == startRoot, "stale root");

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
    function withdraw(
        address addr,
        uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c,
        uint[6] calldata input
    ) external {
        uint256 root         = input[0];
        uint256 recipient    = input[1];
        uint256 prevIndex    = input[2];
        uint256 currentIndex = input[3];
        uint256 currentSum   = input[4];
        uint256 prevSum      = input[5];

        require(recipient == computeRecipient(block.chainid, addr), "recipient mismatch");
        require(root == transferRoot, "unknown root");
        require(prevIndex == withdrawnIndex[recipient], "invalid frontier");
        require(prevSum == totalWithdrawn[recipient], "invalid sum base");

        require(withdrawVerifier.verifyProof(a, b, c, input), "invalid proof");

        uint256 delta = currentSum - prevSum;
        require(delta > 0, "nothing to withdraw");
        totalWithdrawn[recipient] = currentSum;
        withdrawnIndex[recipient] = currentIndex;

        token.teleport(addr, delta);
    }


    function computeRecipient(uint256 chain_id, address addr) public pure returns (uint256) {
        bytes32 h = keccak256(abi.encodePacked(uint64(chain_id), addr));
        return uint256(h) & HASH_CHAIN_MASK;
    }
}
