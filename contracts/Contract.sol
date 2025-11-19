// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract Escrow is Ownable2Step, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    uint256 public constant LOCK_PERIOD = 7 days;

    enum TxStatus { None, Locked, Released, RefundRequested, Refunded, Forwarded }

    struct Transaction {
        bytes commitment;
        uint256 amount;
        uint256 timestamp;
        TxStatus status;
    }

    mapping(bytes32 => Transaction) private transactions;

    event Transact(bytes32 indexed commitmentHash, uint256 amount);
    event Release(bytes32 indexed commitmentHash, uint256 amount);
    event RequestRefund(bytes32 indexed commitmentHash);
    event ApproveRefund(bytes32 indexed commitmentHash, uint256 amount);
    event Forward(bytes32 indexed commitmentHash, uint256 amount);

    constructor(IERC20 _token) {
        token = _token;
    }

    function transact(bytes calldata commitment, uint256 amount)
        external
        whenNotPaused
        nonReentrant
    {
        require(amount > 0, "Amount must > 0");
        require(commitment.length == 64, "Commitment must be 64 bytes");

        bytes32 commitmentHash = keccak256(commitment);
        require(transactions[commitmentHash].status == TxStatus.None, "Transaction exists");

        token.safeTransferFrom(msg.sender, address(this), amount);

        transactions[commitmentHash] = Transaction({
            commitment: commitment,
            amount: amount,
            timestamp: block.timestamp,
            status: TxStatus.Locked
        });

        emit Transact(commitmentHash, amount);
    }

    function release(bytes32 commitmentHash, bytes memory key)
        external
        onlyOwner
        nonReentrant
    {
        Transaction storage txData = transactions[commitmentHash];

        // Status allowed: Locked + RefundRequested
        require(
            txData.status == TxStatus.Locked || 
            txData.status == TxStatus.RefundRequested,
            "Not releasable"
        );

        require(txData.commitment.length == 64, "Invalid commitment");

        (, address receiver) = _decryptAndExtract(txData.commitment, key);
        require(receiver != address(0), "Receiver zero address");

        txData.status = TxStatus.Released;
        token.safeTransfer(receiver, txData.amount);

        emit Release(commitmentHash, txData.amount);
    }

    function requestRefund(bytes32 commitmentHash, bytes memory key) 
        external 
        nonReentrant 
    {
        Transaction storage txData = transactions[commitmentHash];

        require(txData.status == TxStatus.Locked, "Not refundable");
        require(txData.commitment.length == 64, "Invalid commitment");

        (address sender, ) = _decryptAndExtract(txData.commitment, key);
        require(msg.sender == sender, "Not sender");

        txData.status = TxStatus.RefundRequested;

        emit RequestRefund(commitmentHash);
    }

    function approveRefund(bytes32 commitmentHash, bytes memory key)
        external
        onlyOwner
        nonReentrant
    {
        Transaction storage txData = transactions[commitmentHash];

        require(txData.status == TxStatus.RefundRequested, "No refund request");
        require(txData.commitment.length == 64, "Invalid commitment");

        (address sender, ) = _decryptAndExtract(txData.commitment, key);
        require(sender != address(0), "Sender zero address");

        txData.status = TxStatus.Refunded;
        token.safeTransfer(sender, txData.amount);

        emit ApproveRefund(commitmentHash, txData.amount);
    }

    function forward(bytes32 commitmentHash, bytes memory key)
        external
        nonReentrant
    {
        Transaction storage txData = transactions[commitmentHash];

        require(txData.status == TxStatus.Locked, "Not forwardable");
        require(txData.commitment.length == 64, "Invalid commitment stored");
        require(
            block.timestamp >= txData.timestamp + LOCK_PERIOD,
            "Lock not passed"
        );

        (address sender, address receiver) = _decryptAndExtract(txData.commitment, key);
        require(msg.sender == sender, "Not sender");
        require(receiver != address(0), "Receiver zero");

        txData.status = TxStatus.Forwarded;
        token.safeTransfer(receiver, txData.amount);

        emit Forward(commitmentHash, txData.amount);
    }

    function peekParticipants(bytes32 commitmentHash, bytes memory key)
        external
        view
        returns (address sender, address receiver)
    {
        Transaction storage txData = transactions[commitmentHash];
        require(txData.commitment.length == 64, "Invalid stored commitment");
        return _decryptAndExtract(txData.commitment, key);
    }

    function getTransaction(bytes32 commitmentHash)
        external
        view
        returns (uint256 amount, uint256 timestamp, TxStatus status, uint256 cipherLen)
    {
        Transaction storage txData = transactions[commitmentHash];
        return (txData.amount, txData.timestamp, txData.status, txData.commitment.length);
    }

    function _decryptAndExtract(bytes memory cipher, bytes memory key)
        internal
        pure
        returns (address sender, address receiver)
    {
        require(cipher.length == 64, "Cipher must be 64 bytes");

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

        sender   = address(uint160(uint256(w1)));
        receiver = address(uint160(uint256(w2)));
    }
}
