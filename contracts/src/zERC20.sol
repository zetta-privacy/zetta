// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {PoseidonT4} from "poseidon-solidity/PoseidonT4.sol";
import {IBlacklist} from "./interfaces/Blacklist.sol";

contract zERC20 is ERC20 {
    uint256 public burnHashChain;
    uint256 public burnIndex;

    uint256 private constant VALUE_LIMIT = 1 << 248;

    address public minter;   // the Vault (wrap/unwrap)
    address public verifier; // the Verifier (teleport)

    address public owner; // Cold wallet / multisig
    address public blacklist;

    event BurnStep(address indexed from, address indexed to, uint256 value, uint256 hashChain);
    event MinterRotated(address indexed oldMinter, address indexed newMinter);
    event VerifierRotated(address indexed oldVerifier, address indexed newVerifier);
    event BlacklistRotated(address indexed oldBlacklist, address indexed newBlacklist);

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        require(msg.sender == owner, "not owner");
    }

    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {
        minter = msg.sender;
        verifier = msg.sender;
        owner = msg.sender;
    }

    function setBlacklist(address b) external onlyOwner {
        emit BlacklistRotated(blacklist, b);
        blacklist = b;
    }

    function setMinter(address m) external onlyOwner {
        emit MinterRotated(minter, m);
        minter = m;
    }

    function setVerifier(address v) external onlyOwner {
        emit VerifierRotated(verifier, v);
        verifier = v;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "not minter");
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        require(msg.sender == minter, "not minter");
        _burn(from, amount);
    }

    function teleport(address to, uint256 amount) external {
        require(msg.sender == verifier, "not verifier");
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        require(value < VALUE_LIMIT, "value too large");
        if (from != address(0) && blacklist != address(0)) {
            require(!IBlacklist(blacklist).isBlacklisted(from), "blacklisted sender");
        }
        if (to != address(0) && blacklist != address(0)) {
            require(!IBlacklist(blacklist).isBlacklisted(to), "blacklisted recipient");
        }
        super._update(from, to, value);
        if (from != address(0) && to != address(0)) {
            burnHashChain = PoseidonT4.hash([burnHashChain, uint256(uint160(to)), value]);
            burnIndex += 1;
            emit BurnStep(from, to, value, burnHashChain);
        }
    }

    function decimals() public view virtual override returns (uint8) {
        return 6;
    }
}
