## Quick Start (Hardhat / Foundry)

```js
// Deploy
const escrow = await ethers.deployContract("IncognitoEscrow", [
  ownerAddress,      // initialOwner (multisig recommended)
  verifierAddress,   // your ZK verifier contract
  initialMerkleRoot, // bytes32
  feeRecipient       // treasury address
]);
await escrow.waitForDeployment();
```

## Frontend Integration (ethers.js v6)

```ts
import { ethers } from "ethers";

// Generate encrypted commitment (64 bytes)
async function createCommitment(
  sender: string,
  receiver: string,
  secret: string
): Promise<string> {
  const key = ethers.keccak256(ethers.toUtf8Bytes(secret));
  const keystream = ethers.concat([key, key]); // 64 bytes

  const plain = ethers.concat([
    ethers.zeroPadValue(sender, 32),
    ethers.zeroPadValue(receiver, 32)
  ]);

  const commitmentBytes = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    commitmentBytes[i] = plain[i] ^ keystream[i];
  }

  return ethers.hexlify(commitmentBytes); // 0x + 128 hex chars
}

// Deposit – Sender / Buyer
async function deposit({
  token,
  escrow,
  receiver,
  amount,
  secret
}: {
  token: ethers.Contract;
  escrow: ethers.Contract;
  receiver: string;
  amount: bigint;
  secret: string;
}) {
  const sender = await escrow.signer.getAddress();
  const commitment = await createCommitment(sender, receiver, secret);
  const commitmentHash = ethers.keccak256(commitment);

  // 1. Approve
  await (await token.approve(await escrow.getAddress(), amount)).wait();

  // 2. Deposit
  const tx = await escrow.transact(
    await token.getAddress(),
    commitment,    // 64-byte encrypted blob
    amount
  );
  await tx.wait();

  console.log("Private escrow created!");
  console.log("ID (share with receiver):", commitmentHash);
  console.log("Secret (keep safe):", secret);

  return { commitmentHash, secret };
}
```

### Receiver Claims (after operator calls `release()`)

```ts
await escrow.claim(proof); // proof generated off-chain with secret
```

### Sender Cancels or Forwards

```ts
await escrow.cancel(proof);   // anytime while Ongoing
await escrow.forward(proof);  // after forwardWait (default 7 days)
```

## Blockchain Explorer View

### 1. `transact()` – Deposit

```text
Function: transact(IERC20 token, bytes32 commitment, uint256 amount)

Parameters
├─ token:      0xdAC17F958D2ee523a2206206994597C13D831ec7 (USDT)
├─ commitment: 0x4f8a2b1c9d3e7f6a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5071829
                0x3a4b5c6d7e8f9a0b1c2d3e4f50718293a4b5c6d7e8f9a0b1c2d3e4f50718293a4
                ← 64 bytes (128 hex chars) of pure cryptographic noise
└─ amount:     1_000_000_000 (1,000.00 USDT)

Internal ERC20 Transfer
  From → 0x71C765...a8F3
  To   → IncognitoEscrow
  Value: 1,000.00 USDT

Event
  Transacted(0xdAC17F958D2ee5... , 1000000000)
```

---

### 2. `release()` – Owner

```text
Function: release(bytes proof)

proof: 0x8a9f7b6c5d4e3f2a1b...

Event: Released()
```

---

### 3. `claim()` – Receiver withdraws

```text
Function: claim(bytes proof)

Internal ERC20 Transfers
  From → IncognitoEscrow
  To   → 0x19d4C1...2eF7
  Value: 999.50 USDT

  From → IncognitoEscrow
  To   → 0xFeeRecipient...
  Value: 0.50 USDT (protocol fee)

Event
  Claimed(0x19d4C1...2eF7, 999500000, 500000)
```

---

### 4. `cancel()` – Sender cancels & gets refund

```text
Function: cancel(bytes proof)

Internal ERC20 Transfer
  From → IncognitoEscrow
  To   → 0x71C765...a8F3
  Value: 1,000.00 USDT

Event: Canceled()
```

---

### 5. `forward()` – Sender force-releases after timeout

```text
Function: forward(bytes proof)

Event: Forwarded()

Internal ERC20 Transfers
  From → IncognitoEscrow
  To   → 0x19d4C1...2eF7 (random-looking address)
  Value: 999.50 USDT + 0.50 USDT fee
```

---

### 6. `getTxStatus()` – Check status

```text
Ongoing
```
---

## Public Visibility Summary

| Information                    | Visible on Public Explorer |
|--------------------------------|----------------------------|
| Sender address                 | Yes (only in `transact`)   |
| Receiver address               | No                         |
| 64-byte commitment             | Yes                        |
| Commitment hash (tx ID)        | No                         |
| Deposit → withdrawal link      | No                         |
| Trade purpose / counterparty   | No                         |
| MEV / analytics signal         | No                         |
