## ERC20 Anonymous Escrow 

[![]()](https://github.com/fxg4n/incognito-escrow/docs/images/architecture.png)

A simple ERC20 escrow service that maintains the confidentiality of transacting parties.
The sender and recipient addresses never appear on-chain, as they are stored as 64-byte encrypted commitments.
The public can only see the number of locked tokens and the transaction status, while the identities of the participants can only be revealed by the key holder (the escrow service or the sender after a timeout).

The result: the escrow process remains transparent to audit, but the sender-recipient relationship remains hidden until settlement.

## On-Chain Explorer View (Public)

From the moment a trade is created until it is settled, **zero real participant addresses are exposed**.

### 1. Deposit Phase (what Etherscan/Polygonscan/etc shows)

- Only visible transaction:
  ```
  ERC20 Transfer: 1,000.00 USDT  
  From: 0xAlice... (visible only because she sent the tx)  
  To:   IncognitoEscrow contract
  ```
- Input data contains a 64-byte blob (`commitment`) that looks completely random:
  ```
  commitment: 0xa1f3...92c4 (132 hex chars = 64 bytes)
  ```
- No receiver address anywhere
- No way for bots or watchers to know who will ultimately receive the funds

### 2. Escrow Dashboard / Explorer Page (your dApp or block explorer plugin)

You can query the contract with `getTransaction(commitmentHash)` and display:

```text
Transaction ID       0x8f71d1c0...a6f3b2e9   (keccak256(commitment))
Token                USDT
Amount               1,000.00 USDT
Status               Locked
Created              Nov 20, 2025 14:32:18
Time until sender can auto-forward   6 days 23h 41m
```

After settlement (release / refund / forward):

```text
Status               Released    (or Refunded / Forwarded)
Settled              Nov 21, 2025 09:11:05
```

Still **no sender or receiver address is ever revealed** publicly.  
The only outgoing transfer visible on standard explorers is:

```
ERC20 Transfer: 1,000.00 USDT  
From: IncognitoEscrow contract  
To:   0xSomeAddress... (still looks unrelated to the original trade)
```

### 3. Summary

| Information          | Visible on standard explorers? | Visible in your private dashboard? |
|----------------------|-------------------------------|------------------------------------|
| Sender address       | Only during deposit tx        | Yes (after decryption)            |
| Receiver address     | Never                         | Yes (after decryption)            |
| Commitment blob      | Yes (looks random)            | Yes                               |
| Final recipient      | Never linked publicly         | Yes                               |


## Frontend Integration Example

```js
import { ethers } from "ethers";

// Generate the 64-byte encrypted commitment off-chain
async function createCommitment(sender, receiver, secret) {
  const key = ethers.utils.toUtf8Bytes(secret);
  const ks = ethers.utils.keccak256(key);                 // 32 bytes
  const keystream = ethers.utils.concat([ks, ks]);         // 64 bytes

  const plain = ethers.utils.concat([
    ethers.utils.zeroPadValue(sender, 32),
    ethers.utils.zeroPadValue(receiver, 32)
  ]);

  const commitment = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    commitment[i] = plain[i] ^ keystream[i];
  }
  return ethers.utils.hexlify(commitment); // "0x..."
}

// Deposit funds (buyer/sender side)
async function depositEscrow({ tokenContract, escrowContract, receiver, amount, secret }) {
  const sender = await ethers.provider.getSigner().getAddress();

  const commitment = await createCommitment(sender, receiver, secret);
  const commitmentHash = ethers.utils.keccak256(commitment);

  // Approve exact amount
  await (await tokenContract.approve(escrowContract.address, amount)).wait();

  // Deposit
  const tx = await escrowContract.transact(
    tokenContract.address,
    commitment,
    amount
  );
  await tx.wait();

  console.log("Escrow created!");
  console.log("Commitment Hash (use as ID):", commitmentHash);
  console.log("Share this secret securely with the counterparty →", secret);

  return { commitmentHash, secret };
}

// Example usage in React / wagmi
const handlePrivatePayment = async () => {
  const secret = `private-${Date.now()}-${Math.random().toString(36)}`;
  await depositEscrow({
    tokenContract: usdtContract,
    escrowContract: escrow,
    receiver: "0xBob...1234",
    amount: ethers.utils.parseUnits("1000", 6), // 1000 USDT
    secret
  });
};
```