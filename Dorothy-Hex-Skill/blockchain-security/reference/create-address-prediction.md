# CREATE Address Prediction

## CREATE (EIP-161)
Address = `keccak256(rlp([sender, nonce]))[12:]`

- `sender`: 20-byte address of deployer (EOA or contract)
- `nonce`: transaction count of deployer at deployment time
- For EOA nonce 0: RLP encodes nonce as empty bytes `b''`
- For nonce > 0: RLP encodes nonce as integer

## CREATE2 (EIP-1014)
Address = `keccak256(0xff ++ deployer ++ salt ++ keccak256(init_code))[12:]`
- Deterministic regardless of nonce
- Used by factory contracts

## Python: Compute CREATE Address
```python
from web3 import Web3
import rlp

def create_address(sender_hex: str, nonce: int) -> str:
    sender = bytes.fromhex(sender_hex.replace("0x", ""))
    if nonce == 0:
        encoded = rlp.encode([sender, b''])
    else:
        encoded = rlp.encode([sender, nonce])
    addr = Web3.keccak(encoded)[-20:]
    return Web3.to_checksum_address("0x" + addr.hex())
```

## Brute-Force Nonce to Match Target Address
```python
def find_nonce_for_target(sender_hex: str, target_hex: str, max_nonce=200000) -> int:
    """Find which nonce produces the target address."""
    sender = bytes.fromhex(sender_hex.replace("0x", ""))
    target = target_hex.lower().replace("0x", "")
    for nonce in range(max_nonce):
        encoded = rlp.encode([sender, b'' if nonce == 0 else nonce])
        addr = Web3.keccak(encoded)[-20:].hex()
        if addr == target:
            return nonce
    return -1
```

## Nonce Bumping Technique
When you need to deploy at a specific nonce:
```python
# Send self-transfers to increment nonce
for i in range(target_nonce):
    tx = {'to': player_addr, 'value': 0, 'gas': 21000,
          'gasPrice': gas_price, 'nonce': i, 'chainId': chain_id}
    signed = acct.sign_transaction(tx)
    w3.eth.send_raw_transaction(signed.raw_transaction)
# Wait for last tx
w3.eth.wait_for_transaction_receipt(tx_hash)
# Now deploy at target_nonce
```

**Cost**: Each self-transfer costs 21000 gas. For nonce 130 at 20 gwei = ~0.055 ETH total.

## Multi-Level Nonce Search
Check if player -> factory -> child matches:
```python
for player_nonce in range(300):
    factory = create_address(player, player_nonce)
    for factory_nonce in range(10):
        child = create_address(factory, factory_nonce)
        if child.lower() == target.lower():
            print(f"Player nonce {player_nonce} -> Factory -> nonce {factory_nonce} = target")
```

## Common CTF Pattern: "Noncense"
1. Hardcoded addresses in contract with no deployed code
2. Brute-force which account + nonce produces those addresses
3. Bump nonce with dummy transactions
4. Deploy exploit contract at the matching nonce
5. Trigger the contract interaction (delegatecall, call, etc.)
