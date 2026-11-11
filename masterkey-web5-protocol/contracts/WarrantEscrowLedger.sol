// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title WarrantEscrowLedger
 * @notice Enforces transparent, user-notified judicial disclosure requests.
 *         Prevents silent mass surveillance while maintaining legal compliance.
 */
contract WarrantEscrowLedger {
    enum RequestStatus {
        PendingUserConsent,
        ApprovedByUser,
        ContestedJudicialReview,
        RejectedExpired
    }

    struct DisclosureRequest {
        bytes32 requestId;
        address judicialAuthority;
        bytes32 pairwiseTokenHash;
        string warrantIpfsCid; // Encrypted warrant details readable by target user
        uint256 createdAt;
        uint256 expiresAt;
        RequestStatus status;
        bytes userConsentSignature;
    }

    mapping(bytes32 => DisclosureRequest) public requests;
    mapping(address => bool) public authorizedCourts;
    address public protocolGovernance;

    event WarrantSubmitted(
        bytes32 indexed requestId,
        bytes32 indexed pairwiseTokenHash,
        address indexed judicialAuthority,
        string warrantIpfsCid
    );

    event UserConsentRecorded(
        bytes32 indexed requestId,
        RequestStatus newStatus
    );

    modifier onlyAuthorizedCourt() {
        require(authorizedCourts[msg.sender], "Caller is not a verified judicial authority");
        _;
    }

    constructor() {
        protocolGovernance = msg.sender;
    }

    function registerCourt(address courtAddress, bool status) external {
        require(msg.sender == protocolGovernance, "Only governance");
        authorizedCourts[courtAddress] = status;
    }

    /**
     * @notice Court submits a signed warrant targeting a specific anonymous app token.
     *         Emits an event that triggers an immediate push alert in the user's Super-App.
     */
    function submitWarrantRequest(
        bytes32 requestId,
        bytes32 pairwiseTokenHash,
        string calldata warrantIpfsCid,
        uint256 validityDuration
    ) external onlyAuthorizedCourt {
        require(requests[requestId].createdAt == 0, "Request ID already exists");

        requests[requestId] = DisclosureRequest({
            requestId: requestId,
            judicialAuthority: msg.sender,
            pairwiseTokenHash: pairwiseTokenHash,
            warrantIpfsCid: warrantIpfsCid,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + validityDuration,
            status: RequestStatus.PendingUserConsent,
            userConsentSignature: ""
        });

        emit WarrantSubmitted(requestId, pairwiseTokenHash, msg.sender, warrantIpfsCid);
    }

    /**
     * @notice User responds directly from their hardware-enclave Super-App after reviewing the warrant.
     */
    function respondToWarrant(
        bytes32 requestId,
        bool grantConsent,
        bytes calldata postQuantumConsentSig
    ) external {
        DisclosureRequest storage req = requests[requestId];
        require(req.createdAt != 0, "Request not found");
        require(block.timestamp <= req.expiresAt, "Warrant request expired");
        require(req.status == RequestStatus.PendingUserConsent, "Already resolved");

        if (grantConsent) {
            req.status = RequestStatus.ApprovedByUser;
            req.userConsentSignature = postQuantumConsentSig;
        } else {
            // Places dispute into transparent judicial review without silent data leakage
            req.status = RequestStatus.ContestedJudicialReview;
        }

        emit UserConsentRecorded(requestId, req.status);
    }
}
