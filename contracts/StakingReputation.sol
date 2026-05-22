// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract StakingReputation is Ownable {
    IERC20 public itkToken;
    mapping(address => uint256) public stakes;

    event Staked(address indexed agent, uint256 amount);
    event Slashed(address indexed agent, uint256 amount, string reason);

    constructor(address _itkToken) Ownable(msg.sender) {
        itkToken = IERC20(_itkToken);
    }

    function stake(uint256 amount) external {
        require(itkToken.transferFrom(msg.sender, address(this), amount), "Stake failed");
        stakes[msg.sender] += amount;
        emit Staked(msg.sender, amount);
    }

    function slash(address agent, uint256 amount, string memory reason) external onlyOwner {
        require(stakes[agent] >= amount, "Insufficient stake to slash");
        stakes[agent] -= amount;
        // Burn or re-distribute slashed tokens logic
        emit Slashed(agent, amount, reason);
    }
}
