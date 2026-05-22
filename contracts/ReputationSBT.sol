// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract ReputationSBT is ERC721, Ownable {
    uint256 private _nextTokenId;

    struct ReputationMetrics {
        uint8 accuracy;    // Cognitive clinical precision (0-100)
        uint8 privacy;     // ZK edge boundary compliance (0-100)
        uint8 reliability; // Latency and uptime operational verification (0-100)
        uint32 lastUpdated;
    }

    mapping(uint256 => ReputationMetrics) public agentMetrics;

    event MetricsUpdated(uint256 indexed tokenId, uint8 accuracy, uint8 privacy, uint8 reliability, uint32 lastUpdated);

    constructor() ERC721("ReputationSBT", "RSBT") Ownable(msg.sender) {}

    function mint(address to, uint8 accuracy, uint8 privacy, uint8 reliability) external onlyOwner {
        uint256 tokenId = _nextTokenId++;
        _safeMint(to, tokenId);
        agentMetrics[tokenId] = ReputationMetrics({
            accuracy: accuracy,
            privacy: privacy,
            reliability: reliability,
            lastUpdated: uint32(block.timestamp)
        });
        emit MetricsUpdated(tokenId, accuracy, privacy, reliability, uint32(block.timestamp));
    }

    function updateMetrics(uint256 tokenId, uint8 accuracy, uint8 privacy, uint8 reliability) external onlyOwner {
        require(_ownerOf(tokenId) != address(0), "Nonexistent token");
        agentMetrics[tokenId] = ReputationMetrics({
            accuracy: accuracy,
            privacy: privacy,
            reliability: reliability,
            lastUpdated: uint32(block.timestamp)
        });
        emit MetricsUpdated(tokenId, accuracy, privacy, reliability, uint32(block.timestamp));
    }

    // SBT logic: Non-transferable
    function _update(address to, uint256 tokenId, address auth) internal virtual override returns (address) {
        address from = _ownerOf(tokenId);
        require(from == address(0) || to == address(0), "SBT: Transfer not allowed");
        return super._update(to, tokenId, auth);
    }
}
