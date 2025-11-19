// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
address constant POSEIDON_T2 = 0x9e9Db545Ba56930D0d8e0c2823e9e4d5F19d0D0d;
address constant VERIFIER = 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

interface IVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[8] calldata input
    ) external view returns (bool);
}

interface IHasher {
    function poseidon(bytes32[2] calldata inputs) external pure returns (bytes32);
}

/// @title EscrowPrivacyPool — adapted from NuclearPrivacyPool for escrow:
/// buyer -> deposit, platform(relayer) -> release to seller using zk proof,
/// buyer can force release to seller after unlock + FORCE_GRACE days.
contract EscrowPrivacyPool is Ownable2Step, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    IVerifier public immutable verifier = IVerifier(VERIFIER);
    IERC20    public immutable token    = IERC20(USDC);
    IHasher   public immutable hasher   = IHasher(POSEIDON_T2);

    uint256 public constant TREE_LEVELS       = 20;
    uint256 public constant ROOT_HISTORY_SIZE = 30;

    uint256 public constant MIN_DELAY = 3 days;
    uint256 public constant MAX_DELAY = 30 days;
    uint256 public constant MAX_FEE   = 5_000_000;

    uint256 public constant FORCE_GRACE = 7 days;

    uint256 public constant DEN_10  = 10_000_000;
    uint256 public constant DEN_100 = 100_000_000;
    uint256 public constant DEN_500 = 500_000_000;

    address public platform;

    mapping(bytes32 => bool) public nullifierHashes;
    mapping(bytes32 => bool) public commitmentExists;
    mapping(address => bool) public bannedDepositors;
    mapping(bytes32 => Note) public notes;

    mapping(bytes32 => address) public commitmentSeller;   
    mapping(bytes32 => address) public commitmentDepositor;
    mapping(bytes32 => bytes32) public commitmentOrder;     

    struct Note {
        uint128 unlockTime; 
        uint8   denomIndex; 
        bool    spent;   
    }

    uint256 public nextLeafIndex;
    bytes32[TREE_LEVELS]       public zeros;
    bytes32[TREE_LEVELS]       public filledSubtrees;
    bytes32[ROOT_HISTORY_SIZE] public roots;
    uint256 public currentRootIndex;
    mapping(bytes32 => bool) private rootExists;

    event Deposit(bytes32 indexed commitment, uint256 amount, uint256 unlockTime, uint32 leafIndex, address indexed depositor, address indexed seller, bytes32 orderId);
    event Withdrawal(address indexed to, bytes32 nullifierHash, uint256 amount, uint256 fee);
    event InternalTransfer(bytes32 indexed oldCommitment, bytes32 indexed newCommitment);
    event DepositorBanned(address indexed depositor);
    event DepositorUnbanned(address indexed depositor);
    event EmergencyTokenRescue(address indexed token, address indexed to, uint256 amount);
    event ContractPaused(address indexed by);
    event ContractUnpaused(address indexed by);
    event PlatformUpdated(address indexed oldPlatform, address indexed newPlatform);
    event ForceRelease(bytes32 indexed commitment, address indexed seller, uint256 amount);

    constructor(address _platform) {
        require(_platform != address(0), "Platform zero");
        platform = _platform;

        zeros[0] = bytes32(0);
        for (uint256 i = 1; i < TREE_LEVELS; ) {
            zeros[i] = _hashLeftRight(zeros[i-1], zeros[i-1]);
            unchecked { i++; }
        }
        for (uint256 i = 0; i < TREE_LEVELS; ) {
            filledSubtrees[i] = zeros[i];
            unchecked { i++; }
        }

        bytes32 initRoot = _hashLeftRight(zeros[TREE_LEVELS-1], zeros[TREE_LEVELS-1]);
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; ) {
            roots[i] = initRoot;
            rootExists[initRoot] = true;
            unchecked { i++; }
        }
    }

    function setPlatform(address _platform) external onlyOwner {
        require(_platform != address(0), "zero addr");
        address old = platform;
        platform = _platform;
        emit PlatformUpdated(old, _platform);
    }

    function pause() external onlyOwner {
        _pause();
        emit ContractPaused(msg.sender);
    }

    function unpause() external onlyOwner {
        _unpause();
        emit ContractUnpaused(msg.sender);
    }

    function banDepositor(address a) external onlyOwner {
        bannedDepositors[a] = true;
        emit DepositorBanned(a);
    }

    function unbanDepositor(address a) external onlyOwner {
        bannedDepositors[a] = false;
        emit DepositorUnbanned(a);
    }

    /// @notice rescue non-deposit tokens only
    function rescueERC20(IERC20 _token, address to, uint256 amount) external onlyOwner {
        require(address(_token) != address(token), "Cannot rescue deposit token");
        _token.safeTransfer(to, amount);
        emit EmergencyTokenRescue(address(_token), to, amount);
    }

    function _hashLeftRight(bytes32 l, bytes32 r) private view returns (bytes32) {
        bytes32[2] memory inp = [l, r];
        return hasher.poseidon(inp);
    }

    function _insert(bytes32 leaf) private {
        require(nextLeafIndex < (1 << TREE_LEVELS), "Tree full");
        uint256 i = nextLeafIndex;
        unchecked { nextLeafIndex = i + 1; }

        bytes32 node = leaf;
        for (uint256 h = 0; h < TREE_LEVELS; ) {
            if ((i & 1) == 0) {
                filledSubtrees[h] = node;
                node = _hashLeftRight(node, zeros[h]);
            } else {
                node = _hashLeftRight(filledSubtrees[h], node);
            }
            i >>= 1;
            unchecked { h++; }
        }

        bytes32 oldRoot = roots[currentRootIndex];
        if (rootExists[oldRoot]) delete rootExists[oldRoot];

        currentRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        roots[currentRootIndex] = node;
        rootExists[node] = true;
    }

    function _getDenomIndex(uint256 amount) private pure returns (uint8) {
        if (amount == DEN_10) return 0;
        if (amount == DEN_100) return 1;
        if (amount == DEN_500) return 2;
        revert("Unsupported denom");
    }

    function _denomByIndex(uint8 idx) private pure returns (uint256) {
        if (idx == 0) return DEN_10;
        if (idx == 1) return DEN_100;
        if (idx == 2) return DEN_500;
        revert("Bad index");
    }

    // ----- user actions -----

    /// @notice Deposit and register seller/order metadata. Buyer deposits supported denom and records seller & orderIdHash on-chain.
    /// commitment: poseidon(nullifierPreimage, secret, maybe seller encoded off-chain) - must match prover design
    function depositWithOrder(bytes32 commitment, uint256 amount, uint256 delayDays, address seller, bytes32 orderIdHash) external whenNotPaused nonReentrant {
        require(!bannedDepositors[msg.sender], "Banned");
        require(delayDays >= MIN_DELAY / 1 days && delayDays <= MAX_DELAY / 1 days, "Delay 3-30d");
        require(!commitmentExists[commitment], "Exists");
        require(seller != address(0), "Bad seller");

        uint8 idx = _getDenomIndex(amount);

        token.safeTransferFrom(msg.sender, address(this), amount);

        uint128 unlock = uint128(block.timestamp + delayDays * 1 days);
        notes[commitment] = Note(unlock, idx, false);
        commitmentExists[commitment] = true;

        commitmentSeller[commitment] = seller;
        commitmentDepositor[commitment] = msg.sender;
        commitmentOrder[commitment] = orderIdHash;

        _insert(commitment);

        emit Deposit(commitment, amount, unlock, uint32(nextLeafIndex - 1), msg.sender, seller, orderIdHash);
    }

    /// @notice Withdraw via platform relayer with zk-proof.
    /// PUBLIC INPUT LAYOUT expected by contract:
    /// input[0] = root
    /// input[1] = nullifier
    /// input[2] = uint160(recipient)
    /// input[3] = uint160(relayer)   (must equal platform)
    /// input[4] = fee
    /// input[5] = denomIdx
    /// input[6] = unlockTime
    /// input[7] = uint256(commitment)
    function withdraw(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[8] calldata input,
        address payable recipient,
        address payable relayer
    ) external whenNotPaused nonReentrant {
        require(msg.sender == platform, "Only platform caller");
        require(relayer == platform, "Relayer must equal platform");

        require(uint256(uint160(recipient)) == input[2], "Recipient mismatch");
        require(uint256(uint160(relayer))   == input[3], "Relayer mismatch");

        bytes32 root = bytes32(input[0]);
        bytes32 nullifier = bytes32(input[1]);
        uint256 fee = input[4];
        uint8 denomIdx = uint8(input[5]);
        uint256 unlockTime = input[6];

        bytes32 commitment = bytes32(input[7]);

        require(isKnownRoot(root), "Bad root");
        require(!nullifierHashes[nullifier], "Spent");
        require(commitmentExists[commitment], "Unknown commitment");
        Note memory note = notes[commitment];
        require(note.unlockTime > 0 && !note.spent, "Invalid/used");
        require(block.timestamp >= unlockTime, "Locked");
        require(note.unlockTime == unlockTime, "Unlock mismatch");
        require(denomIdx == note.denomIndex, "Denom mismatch");
        require(denomIdx < 3, "Bad denom");
        require(fee <= MAX_FEE, "Fee high");

        address recordedSeller = commitmentSeller[commitment];
        require(recordedSeller == recipient, "Recipient not seller");

        require(verifier.verifyProof(a, b, c, input), "Bad proof");

        nullifierHashes[nullifier] = true;

        note.spent = true;
        notes[commitment] = note;

        uint256 amount = _denomByIndex(denomIdx);

        if (fee > 0) token.safeTransfer(relayer, fee);
        token.safeTransfer(recipient, amount - fee);

        emit Withdrawal(recipient, nullifier, amount, fee);
    }

    /// @notice Internal re-randomization of a note. Requires zk proof linking old note -> new commitment.
    /// For internalTransfer we keep original behavior; input[7] is newCommitment
    function internalTransfer(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[8] calldata input,
        bytes32 newCommitment
    ) external whenNotPaused nonReentrant {
        require(input[7] == uint256(newCommitment), "New mismatch");
        require(input[2] == 0 && input[3] == 0 && input[4] == 0 && input[5] == 0 && input[6] == 0, "Bad inputs");

        bytes32 root = bytes32(input[0]);
        bytes32 oldCommitment = bytes32(input[1]);

        require(isKnownRoot(root), "Bad root");
        require(!nullifierHashes[oldCommitment], "Already nullified");
        require(!commitmentExists[newCommitment], "New exists");

        Note memory note = notes[oldCommitment];
        require(note.unlockTime > 0 && !note.spent, "Invalid/used");

        require(verifier.verifyProof(a, b, c, input), "Bad proof");

        note.spent = true;
        notes[oldCommitment] = note; 
        nullifierHashes[oldCommitment] = true;

        commitmentSeller[newCommitment] = commitmentSeller[oldCommitment];
        commitmentDepositor[newCommitment] = commitmentDepositor[oldCommitment];
        commitmentOrder[newCommitment] = commitmentOrder[oldCommitment];

        notes[newCommitment] = Note(note.unlockTime, note.denomIndex, false);
        commitmentExists[newCommitment] = true;

        _insert(newCommitment);
        emit InternalTransfer(oldCommitment, newCommitment);
    }

    // ----- buyer force-release fallback -----
    /// @notice Allow depositor (buyer) to force-release to seller after unlockTime + FORCE_GRACE.
    /// This is the optional fallback if platform doesn't act.
    function forceRelease(bytes32 commitment) external whenNotPaused nonReentrant {
        require(commitmentExists[commitment], "Unknown commitment");
        Note memory note = notes[commitment];
        require(note.unlockTime > 0 && !note.spent, "Invalid/used");
        require(commitmentDepositor[commitment] == msg.sender, "Only depositor");
        require(block.timestamp >= uint256(note.unlockTime) + FORCE_GRACE, "Too early for forceRelease");

        note.spent = true;
        notes[commitment] = note;
        nullifierHashes[commitment] = true;

        address payable seller = payable(commitmentSeller[commitment]);
        require(seller != address(0), "No seller");

        uint256 amount = _denomByIndex(note.denomIndex);
        token.safeTransfer(seller, amount);

        emit ForceRelease(commitment, seller, amount);
        emit Withdrawal(seller, commitment, amount, 0);
    }

    function isKnownRoot(bytes32 r) public view returns (bool) {
        return rootExists[r];
    }
}
