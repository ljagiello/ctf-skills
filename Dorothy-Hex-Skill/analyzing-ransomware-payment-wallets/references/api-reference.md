# API Reference: Ransomware Payment Wallet Analysis

## blockchain.com API

### Get Address Information
```
GET https://blockchain.info/rawaddr/{address}?limit=50
```

Returns transaction history, balance, and UTXO data for a Bitcoin address.

### Response Fields
| Field | Type | Description |
|-------|------|-------------|
| `address` | string | Bitcoin address |
| `n_tx` | int | Total number of transactions |
| `total_received` | int | Total satoshis received |
| `total_sent` | int | Total satoshis sent |
| `final_balance` | int | Current balance in satoshis |
| `txs` | array | Array of transaction objects |

### Get Single Transaction
```
GET https://blockchain.info/rawtx/{tx_hash}
```

### Get Unspent Outputs
```
GET https://blockchain.info/unspent?active={address}
```

## Blockstream.info API

### Get Address Stats
```
GET https://blockstream.info/api/address/{address}
```

### Response Fields
| Field | Type | Description |
|-------|------|-------------|
| `chain_stats.funded_txo_count` | int | Number of funding transactions |
| `chain_stats.spent_txo_count` | int | Number of spending transactions |
| `chain_stats.funded_txo_sum` | int | Total satoshis funded |
| `chain_stats.spent_txo_sum` | int | Total satoshis spent |

### Get Address Transactions
```
GET https://blockstream.info/api/address/{address}/txs
```

## WalletExplorer API

### Look Up Address
```
GET https://www.walletexplorer.com/api/1/address?address={address}&caller=research
```

### Response Fields
| Field | Type | Description |
|-------|------|-------------|
| `wallet_id` | string | Cluster wallet identifier |
| `label` | string | Known entity label (exchange, mixer, etc.) |
| `is_exchange` | bool | Whether address belongs to known exchange |

### Get Wallet Transactions
```
GET https://www.walletexplorer.com/api/1/wallet-addresses?wallet={wallet_id}&caller=research
```

## Bitcoin Address Formats

| Format | Prefix | Example | Notes |
|--------|--------|---------|-------|
| P2PKH (Legacy) | 1 | 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa | Original format |
| P2SH (SegWit compatible) | 3 | 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy | Script hash |
| Bech32 (Native SegWit) | bc1q | bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq | Lower fees |
| Bech32m (Taproot) | bc1p | bc1p... | Newest format |

## Common Ransomware Wallet Indicators

| Pattern | Significance |
|---------|-------------|
| Single large inbound, rapid outbound | Ransom payment received, quickly laundered |
| Multiple small inbound from different addresses | Multiple victims paying same wallet |
| Outbound to known mixer addresses | Laundering through CoinJoin/mixer services |
| Peel chain (sequential diminishing outputs) | Structured laundering to evade detection |
| Transfer to exchange hot wallet | Cash-out attempt via cryptocurrency exchange |

## OFAC SDN Sanctions Check

```
Download list: https://www.treasury.gov/ofac/downloads/sdnlist.txt
Search API:    https://sanctionssearch.ofac.treas.gov/
```

Check addresses against OFAC Specially Designated Nationals list for compliance.
