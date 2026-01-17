# VCP TradingView RTA Verification Guide

This guide provides step-by-step instructions for independently verifying the integrity of the VCP TradingView RTA evidence pack.

## Prerequisites

- Python 3.9+
- No external dependencies (standard library only)

## Quick Verification

### 1. Clone the Repository

```bash
git clone https://github.com/veritaschain/vcp-tradingview-rta-reference.git
cd vcp-tradingview-rta-reference
```

### 2. Run the Verifier

```bash
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_tv_events.jsonl \
    -s evidence/04_anchor/security_object.json
```

### 3. Expected Output

```
======================================================================
VCP v1.1 Verification Report
======================================================================

[Verification Results]
  Overall Status: [PASS] VALID
  Total Events: 40
  Valid Events: 40
  Invalid Events: 0

[Chain Integrity]
  Sequence Continuity: [PASS]
  PrevHash Integrity: [PASS]
  Merkle Root: [PASS]
======================================================================
Verification complete: All checks passed
======================================================================
```

---

## Detailed Verification Steps

### Step 1: Verify Event Hashes

Each event contains an `event_hash` field computed as:

```
event_hash = SHA-256(canonical_json(event))
```

Where `canonical_json` follows RFC 8785 (JCS):
- Keys sorted lexicographically
- No whitespace
- Minimal number representation

The verifier automatically checks each event's hash.

### Step 2: Verify Sequence Continuity

Events are numbered sequentially via `merkle_index`:
- First event: `merkle_index = 0`
- Subsequent events: `merkle_index = previous + 1`

Any gap indicates potential event deletion.

### Step 3: Verify PrevHash Chain

Each event (except the first) contains `prev_hash` linking to the previous event:

```
event[n].prev_hash == event[n-1].event_hash
```

This creates an immutable chain similar to blockchain.

### Step 4: Verify Merkle Root

The Merkle tree follows RFC 6962 with domain separation:

```
leaf_hash(data) = SHA-256(0x00 || data)
internal_hash(L, R) = SHA-256(0x01 || L || R)
```

The computed Merkle root must match the value in `security_object.json`.

### Step 5: Verify Ed25519 Signatures (Optional)

Each event includes an Ed25519 signature. Verify using the public key in `evidence/04_anchor/public_key.json`.

---

## Tamper Detection Test

### Run the Test

```bash
python evidence/03_tamper_detection/tamper_detection_test.py
```

### Expected Output

```
======================================================================
VCP v1.1 Tamper Detection Test Suite
======================================================================

Test 1: Event Modification Detection
  [DETECTED] Event TV-...: Hash mismatch
  Result: [PASS] Tampering successfully detected

Test 2: Event Deletion Detection
  [DETECTED] Sequence gap...
  Result: [PASS] Deletion successfully detected

Test 3: Event Insertion Detection
  [DETECTED] Fake event has invalid hash
  Result: [PASS] Insertion successfully detected

======================================================================
All tamper detection tests passed!
======================================================================
```

---

## Manual Verification (Python)

```python
import json
import hashlib

def verify_event(event):
    """Verify a single event's hash."""
    core = {
        "account_id": event["account_id"],
        "clock_sync": event["clock_sync"],
        "event_id": event["event_id"],
        "event_type": event["event_type"],
        "payload": event["payload"],
        "policy_id": event["policy_id"],
        "system_id": event["system_id"],
        "tier": event["tier"],
        "timestamp": event["timestamp"],
        "vcp_version": event["vcp_version"],
    }
    if event.get("prev_hash"):
        core["prev_hash"] = event["prev_hash"]
    
    canonical = json.dumps(core, sort_keys=True, separators=(',', ':'))
    computed = hashlib.sha256(canonical.encode()).hexdigest()
    
    return computed == event.get("event_hash")

# Load and verify
with open("evidence/01_trade_logs/vcp_tv_events.jsonl") as f:
    for line in f:
        event = json.loads(line)
        valid = verify_event(event)
        print(f"{event['event_id']}: {'VALID' if valid else 'INVALID'}")
```

---

## Troubleshooting

### "Hash mismatch" Error

The event data has been modified. Compare:
- Stored hash in `event_hash` field
- Computed hash from canonical JSON

### "Sequence gap" Error

Events have been deleted. Check `merkle_index` values for gaps.

### "PrevHash mismatch" Error

The event chain has been broken. Verify `prev_hash` matches the previous event's `event_hash`.

### "Merkle root mismatch" Error

The event collection has been modified. Recalculate the Merkle tree and compare.

---

## Contact

For questions about verification:
- **Email:** support@veritaschain.org
- **GitHub Issues:** https://github.com/veritaschain/vcp-tradingview-rta-reference/issues

---

**VeritasChain Standards Organization (VSO)**  
*"Verify, Don't Trust."*
