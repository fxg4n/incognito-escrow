// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

interface IZkVerifier {
    function verify(bytes calldata proof)
        external
        view
        returns (
            bytes32 commitment,
            uint256 action,
            uint256 extra0,
            uint256 extra1,
            bytes32 root
        );
}

contract IncognitoEscrow is Ownable2Step, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    enum TxStatus { None, Ongoing, Released, Done, Canceled, Forwarded }

    struct TxData {
        IERC20 token;
        uint256 amount;
        TxStatus status;
        uint256 timestamp;
    }

    mapping(bytes32 => TxData) public txs;

    IZkVerifier public verifier;
    bytes32 public merkleRoot;

    uint256 public forwardWait = 7 days;
    uint256 public feeBps = 50;
    address public feeRecipient;

    event Transacted(address indexed token, uint256 amount);
    event Released();
    event Claimed(address indexed receiver, uint256 netAmount, uint256 fee);
    event Canceled();
    event Forwarded();

    // FIXED: Panggil constructor Ownable2Step (yang mewarisi Ownable) dengan initialOwner
    constructor(
        address initialOwner,
        address _verifier,
        bytes32 _root,
        address _feeRecipient
    ) Ownable(initialOwner) {
        require(initialOwner != address(0), "owner 0");
        require(_verifier != address(0), "verifier 0");
        require(_feeRecipient != address(0), "feeRecipient 0");

        verifier = IZkVerifier(_verifier);
        merkleRoot = _root;
        feeRecipient = _feeRecipient;
    }

    // --- ADMIN ---
    function setMerkleRoot(bytes32 r) external onlyOwner { 
        merkleRoot = r; 
    }
    
    function setVerifier(address v) external onlyOwner { 
        require(v != address(0), "verifier 0"); 
        verifier = IZkVerifier(v); 
    }
    
    function setFeeRecipient(address r) external onlyOwner { 
        require(r != address(0), "feeRecipient 0"); 
        feeRecipient = r; 
    }

    function setForwardWait(uint256 w) external onlyOwner {
        require(w >= 1 days && w <= 30 days, "invalid wait");
        forwardWait = w;
    }

    function setFeeBps(uint256 bps) external onlyOwner {
        require(bps <= 500, "fee too high");
        feeBps = bps;
    }

    function pause() external onlyOwner { 
        _pause(); 
    }
    
    function unpause() external onlyOwner { 
        _unpause(); 
    }

    // --- DEPOSIT ---
    function transact(IERC20 token, bytes32 commitment, uint256 amount)
        external 
        whenNotPaused 
        nonReentrant
    {
        require(amount > 0, "amount 0");
        require(commitment != bytes32(0), "commit 0");
        require(txs[commitment].status == TxStatus.None, "exists");

        token.safeTransferFrom(msg.sender, address(this), amount);

        txs[commitment] = TxData({
            token: token,
            amount: amount,
            status: TxStatus.Ongoing,
            timestamp: block.timestamp
        });

        emit Transacted(address(token), amount);
    }

    // --- OWNER RELEASE ---
    function release(bytes calldata proof) external onlyOwner nonReentrant {
        (bytes32 commitment, uint256 action, , , bytes32 root) = verifier.verify(proof);
        require(root == merkleRoot, "root mismatch");
        require(action == 1, "invalid action");

        TxData storage t = txs[commitment];
        require(t.status == TxStatus.Ongoing, "not ongoing");

        t.status = TxStatus.Released;
        emit Released();
    }

    // --- CLAIM ---
    function claim(bytes calldata proof) external nonReentrant {
        (bytes32 commitment, uint256 action, uint256 extra0, , bytes32 root)
            = verifier.verify(proof);

        require(root == merkleRoot, "root mismatch");
        require(action == 2, "invalid action");

        address receiver = address(uint160(extra0));
        require(receiver == msg.sender, "not receiver");

        TxData storage t = txs[commitment];
        require(t.status == TxStatus.Released, "not released");

        uint256 fee = (t.amount * feeBps) / 10_000;
        uint256 net = t.amount - fee;

        t.status = TxStatus.Done;

        if (fee > 0) t.token.safeTransfer(feeRecipient, fee);
        t.token.safeTransfer(receiver, net);

        emit Claimed(receiver, net, fee);
    }

    // --- CANCEL ---
    function cancel(bytes calldata proof) external nonReentrant {
        (bytes32 commitment, uint256 action, uint256 extra0, , bytes32 root)
            = verifier.verify(proof);

        require(root == merkleRoot, "root mismatch");
        require(action == 3, "invalid action");

        address sender = address(uint160(extra0));
        require(sender == msg.sender, "not sender");

        TxData storage t = txs[commitment];
        require(t.status == TxStatus.Ongoing, "not ongoing");

        uint256 amt = t.amount;
        t.status = TxStatus.Canceled;
        t.token.safeTransfer(sender, amt);

        emit Canceled();
    }

    // --- FORWARD ---
    function forward(bytes calldata proof) external nonReentrant {
        (bytes32 commitment, uint256 action, uint256 extra0, , bytes32 root)
            = verifier.verify(proof);

        require(root == merkleRoot, "root mismatch");
        require(action == 4, "invalid action");

        address sender = address(uint160(extra0));
        require(sender == msg.sender, "not sender");

        TxData storage t = txs[commitment];
        require(t.status == TxStatus.Ongoing, "not ongoing");
        require(block.timestamp >= t.timestamp + forwardWait, "wait period");

        t.status = TxStatus.Released;
        emit Forwarded();
    }

    // --- VIEW ---
    function getTxStatus(bytes calldata proof) external view returns (TxStatus) {
        (bytes32 commitment, uint256 action, , , bytes32 root)
            = verifier.verify(proof);

        require(root == merkleRoot, "root mismatch");
        require(action == 5, "invalid action");

        return txs[commitment].status;
    }

    // --- RESCUE ---
    function rescueToken(IERC20 token, uint256 amount) external onlyOwner {
        token.safeTransfer(owner(), amount);
    }
}