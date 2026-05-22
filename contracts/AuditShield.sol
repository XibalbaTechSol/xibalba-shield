// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract AuditShield {
    struct LogEntry {
        bytes32 dataHash;
        address agent;
        uint256 timestamp;
    }

    mapping(bytes32 => LogEntry) public auditLogs;

    event LogAnchored(bytes32 indexed dataHash, address indexed agent, uint256 timestamp);

    function anchorLog(bytes32 _dataHash) external {
        require(auditLogs[_dataHash].timestamp == 0, "Log already anchored");
        
        auditLogs[_dataHash] = LogEntry({
            dataHash: _dataHash,
            agent: msg.sender,
            timestamp: block.timestamp
        });

        emit LogAnchored(_dataHash, msg.sender, block.timestamp);
    }
}
