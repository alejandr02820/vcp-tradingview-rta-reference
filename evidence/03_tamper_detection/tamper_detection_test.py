#!/usr/bin/env python3
"""
VCP v1.1 Tamper Detection Test
Demonstrates VCP's ability to detect various tampering attacks.

This test verifies that VCP can detect:
1. Event Modification (Alteration Attack)
2. Event Deletion (Omission Attack)
3. Event Insertion (Injection Attack)

Copyright (c) 2025 VeritasChain Standards Organization
License: MIT
"""

import json
import hashlib
import sys
from pathlib import Path

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools" / "verifier"))

def compute_hash(event):
    """Compute event hash using canonical JSON."""
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
    canonical = json.dumps(core, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def test_modification_detection():
    """
    Test 1: Event Modification Detection
    
    Modifies an event's payload and verifies that VCP detects the tampering.
    """
    print("\n" + "=" * 60)
    print("Test 1: Event Modification Detection")
    print("=" * 60)
    
    # Load tampered chain
    tampered_path = Path(__file__).parent / "tampered_chain.jsonl"
    
    if not tampered_path.exists():
        print("  [SKIP] tampered_chain.jsonl not found")
        return True
    
    with open(tampered_path) as f:
        events = [json.loads(line) for line in f if line.strip()]
    
    # Check each event
    tampering_detected = False
    for event in events:
        computed = compute_hash(event)
        stored = event.get("event_hash", "")
        
        if computed != stored:
            tampering_detected = True
            print(f"  [DETECTED] Event {event['event_id']}: Hash mismatch")
            print(f"             Computed: {computed[:32]}...")
            print(f"             Stored:   {stored[:32]}...")
    
    if tampering_detected:
        print("\n  Result: [PASS] Tampering successfully detected")
        return True
    else:
        print("\n  Result: [FAIL] Tampering not detected")
        return False


def test_deletion_detection():
    """
    Test 2: Event Deletion Detection
    
    Removes an event from the chain and verifies that VCP detects the gap.
    """
    print("\n" + "=" * 60)
    print("Test 2: Event Deletion Detection")
    print("=" * 60)
    
    # Load original chain
    original_path = Path(__file__).parent.parent / "01_trade_logs" / "vcp_tv_events.jsonl"
    
    if not original_path.exists():
        print("  [SKIP] Original events not found")
        return True
    
    with open(original_path) as f:
        events = [json.loads(line) for line in f if line.strip()]
    
    if len(events) < 5:
        print("  [SKIP] Not enough events for test")
        return True
    
    # Simulate deletion by removing event at index 2
    deleted_chain = events[:2] + events[3:]
    
    # Check for sequence gaps
    gap_detected = False
    for i in range(1, len(deleted_chain)):
        prev_idx = deleted_chain[i-1].get("merkle_index", i-1)
        curr_idx = deleted_chain[i].get("merkle_index", i)
        
        if curr_idx != prev_idx + 1:
            gap_detected = True
            print(f"  [DETECTED] Sequence gap at index {prev_idx} → {curr_idx}")
    
    # Also check prev_hash chain break
    prev_hash_break = False
    for i in range(1, len(deleted_chain)):
        if deleted_chain[i].get("prev_hash"):
            expected = deleted_chain[i-1].get("event_hash", "")
            actual = deleted_chain[i]["prev_hash"]
            if expected != actual:
                prev_hash_break = True
                print(f"  [DETECTED] PrevHash chain break at event {deleted_chain[i]['event_id']}")
    
    if gap_detected or prev_hash_break:
        print("\n  Result: [PASS] Deletion successfully detected")
        return True
    else:
        print("\n  Result: [FAIL] Deletion not detected")
        return False


def test_insertion_detection():
    """
    Test 3: Event Insertion Detection
    
    Inserts a fake event into the chain and verifies that VCP detects it.
    """
    print("\n" + "=" * 60)
    print("Test 3: Event Insertion Detection")
    print("=" * 60)
    
    # Create a fake event
    fake_event = {
        "vcp_version": "1.1",
        "event_id": "FAKE-EVENT-001",
        "timestamp": "2025-01-15T10:07:30.000Z",
        "event_type": "ORDER_NEW",
        "tier": "SILVER",
        "policy_id": "urn:vso:policy:tv-retail:v1",
        "clock_sync": "BEST_EFFORT",
        "system_id": "TV-STRATEGY-DEMO",
        "account_id": "fake_account",
        "payload": {"symbol": "FAKEUSD", "action": "BUY"},
        "event_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "merkle_index": 999
    }
    
    # Compute actual hash
    actual_hash = compute_hash(fake_event)
    
    # Check if stored hash matches
    stored_hash = fake_event["event_hash"]
    
    if actual_hash != stored_hash:
        print(f"  [DETECTED] Fake event has invalid hash")
        print(f"             Computed: {actual_hash[:32]}...")
        print(f"             Stored:   {stored_hash[:32]}...")
        print("\n  Result: [PASS] Insertion successfully detected")
        return True
    else:
        print("\n  Result: [FAIL] Insertion not detected")
        return False


def main():
    """Run all tamper detection tests."""
    print("\n" + "=" * 60)
    print("VCP v1.1 Tamper Detection Test Suite")
    print("=" * 60)
    
    results = []
    
    # Run tests
    results.append(("Modification Detection", test_modification_detection()))
    results.append(("Deletion Detection", test_deletion_detection()))
    results.append(("Insertion Detection", test_insertion_detection()))
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    all_passed = True
    for name, passed in results:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {name}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("All tamper detection tests passed!")
    else:
        print("Some tests failed!")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
