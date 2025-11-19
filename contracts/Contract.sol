// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title IncognitoEscrow
 * @notice Privacy-focused escrow with basic safety controls
 * @dev Protected by reentrancy guard and pausable controls
 */
contract IncognitoEscrow is Ownable2Step, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    uint256 public constant LOCK_PERIOD = 7 days;
    uint256 public constant FEE_BPS = 50;

    enum TxStatus { None, Locked, Released, RefundRequested, Refunded, Forwarded }

    struct Transaction {
        IERC20 token;
        bytes commitment;
        uint256 grossAmount;
        uint256 netAmount;
        uint256 feeAmount;
        uint256 timestamp;
        TxStatus status;
    }

    mapping(bytes32 => Transaction) private transactions;

    constructor() {}

    /**
     * @title Create escrow transaction
     * @notice Deposit token + commitment (64 bytes) and lock funds
     * @dev Fee auto-sent to owner; commitment must be unique
     */
    function transact(
        IERC20 tokenAddress,
        bytes calldata commitment,
        uint256 grossAmount
    ) external whenNotPaused nonReentrant {
        require(grossAmount > 0, "Amount > 0");
        require(commitment.length == 64, "Commitment 64 bytes");
        require(address(tokenAddress) != address(0), "Invalid token");

        require(bytes32(commitment) != bytes32(0), "Invalid commitment zero");

        uint256 feeAmount = (grossAmount * FEE_BPS) / 10_000;
        uint256 netAmount = grossAmount - feeAmount;
        require(netAmount > 0, "Net > 0");

        bytes32 commitmentHash = keccak256(commitment);

        require(transactions[commitmentHash].status == TxStatus.None, "Tx exists");

        tokenAddress.safeTransferFrom(msg.sender, address(this), grossAmount);

        if (feeAmount > 0) {
            tokenAddress.safeTransfer(owner(), feeAmount);
        }

        transactions[commitmentHash] = Transaction({
            token: tokenAddress,
            commitment: commitment,
            grossAmount: grossAmount,
            netAmount: netAmount,
            feeAmount: feeAmount,
            timestamp: block.timestamp,
            status: TxStatus.Locked
        });
    }

    /**
     * @title Release funds
     * @notice Owner decrypts and releases net amount to receiver
     * @dev Only owner; requires Locked status
     */
    function release(bytes32 commitmentHash, bytes memory key)
        external
        onlyOwner
        nonReentrant
    {
        Transaction storage txData = transactions[commitmentHash];
        require(txData.status == TxStatus.Locked, "Not releasable");
        require(txData.commitment.length == 64, "Invalid commitment");

        (, address receiver) = _decryptAndExtract(txData.commitment, key);
        require(receiver != address(0), "Receiver zero");

        uint256 sendAmount = txData.netAmount;
        txData.status = TxStatus.Released;

        txData.token.safeTransfer(receiver, sendAmount);
    }

    /**
     * @title Request refund
     * @notice Sender decrypts and proves ownership to request refund
     * @dev Moves status to RefundRequested
     */
    function requestRefund(bytes32 commitmentHash, bytes memory key)
        external
        nonReentrant
    {
        Transaction storage txData = transactions[commitmentHash];
        require(txData.status == TxStatus.Locked, "Not refundable");
        require(txData.commitment.length == 64, "Invalid commitment");

        (address sender, ) = _decryptAndExtract(txData.commitment, key);
        require(sender != address(0), "Sender zero");
        require(msg.sender == sender, "Not sender");

        txData.status = TxStatus.RefundRequested;
    }

    /**
     * @title Approve refund
     * @notice Owner refunds net amount back to sender
     * @dev Only owner; requires RefundRequested status
     */
    function approveRefund(bytes32 commitmentHash, bytes memory key)
        external
        onlyOwner
        nonReentrant
    {
        Transaction storage txData = transactions[commitmentHash];
        require(txData.status == TxStatus.RefundRequested, "No refund req");
        require(txData.commitment.length == 64, "Invalid commitment");

        (address sender, ) = _decryptAndExtract(txData.commitment, key);
        require(sender != address(0), "Sender zero");

        uint256 refundAmount = txData.netAmount;
        txData.status = TxStatus.Refunded;

        txData.token.safeTransfer(sender, refundAmount);
    }

    /**
     * @title Forward funds after timeout
     * @notice Sender can forward funds to receiver after LOCK_PERIOD
     * @dev Bypasses owner; requires Locked status
     */
    function forward(bytes32 commitmentHash, bytes memory key)
        external
        nonReentrant
    {
        Transaction storage txData = transactions[commitmentHash];
        require(txData.status == TxStatus.Locked, "Not forwardable");
        require(txData.commitment.length == 64, "Invalid commitment");
        require(block.timestamp >= txData.timestamp + LOCK_PERIOD, "Lock not passed");

        (address sender, address receiver) = _decryptAndExtract(txData.commitment, key);
        require(sender != address(0), "Sender zero");
        require(msg.sender == sender, "Not sender");
        require(receiver != address(0), "Receiver zero");

        uint256 sendAmount = txData.netAmount;
        txData.status = TxStatus.Forwarded;

        txData.token.safeTransfer(receiver, sendAmount);
    }

    /**
     * @title Peek sender & receiver
     * @notice View decrypted participants
     * @dev Read of decrypted commitment
     */
    function peekParticipants(bytes32 commitmentHash, bytes memory key)
        external
        view
        returns (address sender, address receiver)
    {
        Transaction storage txData = transactions[commitmentHash];
        require(txData.commitment.length == 64, "Invalid commitment");
        return _decryptAndExtract(txData.commitment, key);
    }

    /**
     * @title Read transaction data
     * @notice Returns escrow information without decrypt
     * @dev Status and transaction info only
     */
    function getTransaction(bytes32 commitmentHash)
        external
        view
        returns (
            IERC20 token,
            uint256 grossAmount,
            uint256 netAmount,
            uint256 feeAmount,
            uint256 timestamp,
            TxStatus status
        )
    {
        Transaction storage txData = transactions[commitmentHash];
        return (
            txData.token,
            txData.grossAmount,
            txData.netAmount,
            txData.feeAmount,
            txData.timestamp,
            txData.status
        );
    }

    /**
     * @title Decrypt commitment
     * @notice XOR decrypt commitment to (sender, receiver)
     * @dev Expects 64-byte cipher
     */
    function _decryptAndExtract(bytes memory cipher, bytes memory key)
        internal
        pure
        returns (address sender, address receiver)
    {
        require(cipher.length == 64, "Cipher 64 bytes");
        bytes32 ks = keccak256(key);
        bytes memory keystream = abi.encodePacked(ks, ks);
        bytes memory plain = new bytes(64);

        for (uint256 i = 0; i < 64; i++) {
            plain[i] = bytes1(uint8(cipher[i]) ^ uint8(keystream[i]));
        }

        bytes32 w1;
        bytes32 w2;
        assembly {
            w1 := mload(add(plain, 32))
            w2 := mload(add(plain, 64))
        }
        sender = address(uint160(uint256(w1)));
        receiver = address(uint160(uint256(w2)));
    }

    /**
     * @title Pause contract
     * @notice Freeze all sensitive functions
     * @dev Only owner
     */
    function pause() external onlyOwner { _pause(); }
    
    /**
     * @title Unpause contract
     * @notice Restore normal operations
     * @dev Only owner
     */
    function unpause() external onlyOwner { _unpause(); }

    /**
     * @title Rescue stray tokens
     * @notice Withdraw mistakenly sent tokens to owner
     * @dev Does not affect active escrow balances
     */
    function rescueToken(IERC20 token, uint256 amount) external onlyOwner {
        require(address(token) != address(0), "Invalid token");
        token.safeTransfer(owner(), amount);
    }
}
