// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/Ownable.sol";

// This is a mocked ERC-4337 Paymaster interface for the MVP
contract MockPaymaster is Ownable {
    mapping(address => bool) public approvedTargets;

    event GasSubsidized(address indexed user, address indexed target, uint256 amount);

    constructor() Ownable(msg.sender) {}

    function approveTarget(address target) external onlyOwner {
        approvedTargets[target] = true;
    }

    function subsidize(address user, address target, uint256 amount) external onlyOwner {
        require(approvedTargets[target], "Target not approved for subsidy");
        // Mock logic for subsidizing L2 gas fees using ITK
        emit GasSubsidized(user, target, amount);
    }
}
