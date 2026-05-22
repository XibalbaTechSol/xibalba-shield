// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/Ownable.sol";

contract SovereignAgent is Ownable {
    string public agentMetadataURI;
    address public linkedReputationSBT;

    event AgentInitialized(address indexed owner, string metadataURI);

    constructor(string memory _metadataURI) Ownable(msg.sender) {
        agentMetadataURI = _metadataURI;
        emit AgentInitialized(msg.sender, _metadataURI);
    }

    function setReputationSBT(address _sbt) external onlyOwner {
        linkedReputationSBT = _sbt;
    }
}
