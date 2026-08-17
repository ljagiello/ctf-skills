# Solidity Storage Layout

## Basic Rules
- Each state variable occupies sequential 32-byte slots starting at slot 0
- Small types (bool, uint8, address) are packed into a single slot when possible
- Mappings and dynamic arrays use keccak256-derived slots

## Slot Assignment
```solidity
contract Example {
    uint256 a;           // slot 0
    uint256 b;           // slot 1
    mapping(k => v) m;   // slot 2 (base slot; actual data at derived slots)
    bool flag;           // slot 3
}
```

## Mapping Storage Slots
For `mapping` at base slot `p`, value for key `k`:

**Value-type keys** (uint, address, bool, bytesN):
```
slot = keccak256(abi.encode(k, p))
     = keccak256(leftPad32(k) || leftPad32(p))
```

**String/bytes keys**:
```
slot = keccak256(keccak256(bytes(k)) || leftPad32(p))
```

## Python: Compute Mapping Slot
```python
from web3 import Web3

def mapping_slot_string_key(key: str, base_slot: int) -> bytes:
    """Compute storage slot for mapping(string => ...) at base_slot."""
    h_k = Web3.keccak(key.encode())
    p = base_slot.to_bytes(32, 'big')
    return Web3.keccak(h_k + p)

def mapping_slot_address_key(addr: str, base_slot: int) -> bytes:
    """Compute storage slot for mapping(address => ...) at base_slot."""
    k = bytes.fromhex(addr.replace("0x", "")).rjust(32, b'\x00')
    p = base_slot.to_bytes(32, 'big')
    return Web3.keccak(k + p)

def mapping_slot_uint_key(key: int, base_slot: int) -> bytes:
    """Compute storage slot for mapping(uint256 => ...) at base_slot."""
    k = key.to_bytes(32, 'big')
    p = base_slot.to_bytes(32, 'big')
    return Web3.keccak(k + p)
```

## Nested Mappings
For `mapping(k1 => mapping(k2 => v))` at slot `p`:
```
inner_slot = keccak256(h(k1) || p)
value_slot = keccak256(h(k2) || inner_slot)
```

## Reading Private Variables
```python
# "private" only means no getter -- storage is always readable
w3.eth.get_storage_at(contract_address, slot_number)

# Example: read slot 2 (a private variable)
val = w3.eth.get_storage_at(addr, 2)
print(int(val.hex(), 16))
```

## Dynamic Arrays
For `T[] arr` at slot `p`:
- `arr.length` stored at slot `p`
- `arr[i]` stored at slot `keccak256(p) + i`

## Packed Variables
```solidity
bool a;    // slot 0, byte 0
uint8 b;   // slot 0, byte 1
address c; // slot 0, bytes 2-21
// All packed into slot 0 (total 22 bytes < 32)
```
