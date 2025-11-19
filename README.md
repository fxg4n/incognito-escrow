sequenceDiagram
    autonumber

    participant U as Sender
    participant O as Owner
    participant C as Contract (Escrow)
    participant R as Receiver

    Note over U: Off-chain:<br/>plaintext = abi.encode(sender, receiver)<br/>cipher = XOR(plaintext, keccak256(key))

    U->>C: transact(commitment, amount)<br/>deposit ERC20
    C->>C: store Transaction{Locked}

    alt Sender wants refund
        U->>C: requestRefund(commitmentHash, key)
        C->>C: decrypt(cipher)<br/>extract sender
        C->>C: status = RefundRequested

        O->>C: approveRefund(commitmentHash, key)
        C->>C: decrypt(...) → sender
        C->>U: transfer(amount)
        C->>C: status = Refunded
    else Owner releases to receiver
        O->>C: release(commitmentHash, key)
        C->>C: decrypt(cipher)<br/>extract receiver
        C->>R: transfer(amount)
        C->>C: status = Released
    end

    opt Forward after lock period
        U->>C: forward(commitmentHash, key)
        C->>C: require now >= timestamp + lock
        C->>C: decrypt(...) → sender, receiver
        C->>R: transfer(amount)
        C->>C: status = Forwarded
    end
