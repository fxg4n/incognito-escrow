# IncognitoEscrow – Privacy-Preserving ERC20 Escrow  

![Architecture Overview](https://github.com/fxg4n/incognito-escrow/blob/main/docs/images/architecture.png)

Lightweight escrow contract hides both sender and receiver addresses from the public blockchain.

## Frontend Integration Example

```js
import { ethers } from "ethers";

// Generate 64-byte encrypted commitment (sender + receiver hidden)
async function createCommitment(sender, receiver, secret) {
  const key = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes(secret)));
  const keystream = ethers.concat([key, key]); // 64 bytes

  const plain = ethers.concat([
    ethers.zeroPadValue(sender, 32),
    ethers.zeroPadValue(receiver, 32)
  ]);

  const commitment = ethers.concat(
    Array.from({ length: 64 }, (_, i) => plain[i] ^ keystream[i])
  );

  return commitment; // 64 raw bytes
}

// Deposit into escrow (buyer / sender side)
async function depositEscrow({ token, escrow, receiver, amount, secret }) {
  const sender = await ethers.provider.getSigner().getAddress();
  const commitment = await createCommitment(sender, receiver, secret);
  const commitmentHash = ethers.keccak256(commitment);

  // 1. Approve
  await (await token.approve(escrow.target, amount)).wait();

  // 2. Deposit
  const tx = await escrow.transact(token.target, commitment, amount);
  await tx.wait();

  console.log("Private escrow created!");
  console.log("Transaction ID:", commitmentHash);
  console.log("Secret (share securely with counterparty):", secret);

  return { commitmentHash, secret };
}
```

## On-Chain Explorer View – What the Public Actually Sees

### Phase 1: Deposit (Standard Block Explorer – Etherscan, Basescan, etc.)

```text
Method called: transact(IERC20, bytes, uint256)

Parameters:
  tokenAddress:   0xdAC17F958D2ee523a2206206994597C13D831ec7 (USDT)
  commitment:     0x4f8a2b1c9d3e7f6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4
                  0x11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff
                  ← 64 random-looking bytes (132 hex chars total)
  grossAmount:    1,000,000,000 (1,000.00 USDT)

ERC20 Transfers triggered:
  From: 0x71C7…a8F3 (Alice – only visible because she submitted the tx)
  To:   IncognitoEscrow
  Amount: 1,000.00 USDT
```

**Critical point:** No receiver address appears anywhere.  
Bots, MEV searchers, and public dashboards cannot link this deposit to Bob.

### Phase 2: While Funds Are Locked (Your Private Dashboard / Explorer Plugin)

Query via `getTransaction(commitmentHash)` → shows clean readable view:

```text
╔══════════════════════════════════════════════════════════════╗
║                     IncognitoEscrow Transaction              ║
╠══════════════════════════════════════════════════════════════╣
║ Transaction ID   0x8f71d1c0f7e3b9a2c6d5e4f3a2b1c0d9e8f7g6h5i4j3k2l1m0n9o8p7q6r5  
║ Token            USDT (Tether)                                       
║ Amount           1,000.00 USDT                                           
║ Status           Locked      (7-day sender bypass in 6d 18h 24m)         
║ Created          November 20, 2025 14:32:18 GMT+7                        
║ Commitment Blob  0x4f8a2b1c… (64 bytes – encrypted)                    
╚══════════════════════════════════════════════════════════════╝
```

### Phase 3: Settlement (Release / Refund / Forward)

Standard explorer only sees:

```text
ERC20 Transfer:
  From: IncognitoEscrow
  To:   0x19d4…e3F7   ← looks like a random address to the public
  Amount: 1,000.00 USDT
```

Your private dashboard updates to:

```text
Status           Released
Settled          November 21, 2025 09:11:05 GMT+7
Recipient        0xBob…1234   (only visible to operator or parties with the secret)
```

### Privacy Comparison Table (Public vs Private View)

| Information              | Public Explorer (Etherscan etc.) | Your Private Dashboard / Operator |
|--------------------------|----------------------------------|------------------------------------|
| Original sender          | Only visible in deposit tx       | Yes (after decryption)            |
| Final receiver           | Never visible                    | Yes (after decryption)            |
| Commitment (encrypted)   | Visible (looks random)           | Visible + decryptable             |
| Transaction purpose      | Unknown                          | Fully known                       |
| Linkability to trade     | Impossible without secret        | 1:1 mapping                       |