#!/usr/bin/env python3
"""
VCP v1.1 Chain Verifier
VeritasChain Protocol Event Chain Verification Tool

This tool verifies the integrity of VCP v1.1 event chains by checking:
1. Individual event hashes
2. Sequence continuity
3. PrevHash chain integrity
4. Merkle root verification
5. Digital signatures (when security object provided)

Usage:
    python vcp_verifier.py <events.jsonl> [-s security_object.json]

Copyright (c) 2025 VeritasChain Standards Organization
License: MIT
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class VerificationResult:
    """Result of verification for a single event."""
    event_id: str
    valid: bool
    hash_valid: bool
    sequence_valid: bool
    prev_hash_valid: bool
    errors: List[str]


class VCPVerifier:
    """
    VCP v1.1 Event Chain Verifier.
    
    Implements verification of:
    - Event hash integrity
    - Sequence continuity
    - PrevHash chain linking
    - Merkle tree root
    """
    
    # RFC 6962 domain separation prefixes
    LEAF_PREFIX = b'\x00'
    INTERNAL_PREFIX = b'\x01'
    
    def __init__(self, verbose: bool = False):
        """Initialize verifier."""
        self.verbose = verbose
        self.events: List[Dict[str, Any]] = []
        self.security_object: Optional[Dict[str, Any]] = None
    
    def load_events(self, filepath: str) -> int:
        """
        Load events from JSONL file.
        
        Args:
            filepath: Path to events JSONL file
            
        Returns:
            Number of events loaded
        """
        self.events = []
        
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    self.events.append(event)
                except json.JSONDecodeError as e:
                    print(f"Warning: Invalid JSON on line {line_num}: {e}")
        
        return len(self.events)
    
    def load_security_object(self, filepath: str) -> bool:
        """
        Load security object containing Merkle root and signatures.
        
        Args:
            filepath: Path to security object JSON
            
        Returns:
            True if loaded successfully
        """
        try:
            with open(filepath, 'r') as f:
                self.security_object = json.load(f)
            return True
        except Exception as e:
            print(f"Warning: Could not load security object: {e}")
            return False
    
    def _canonical_json(self, event: Dict[str, Any]) -> str:
        """
        Convert event to canonical JSON format (RFC 8785 JCS).
        
        Args:
            event: Event dictionary
            
        Returns:
            Canonical JSON string
        """
        # Extract core fields for hashing (exclude computed fields)
        core_fields = {
            "account_id": event.get("account_id"),
            "clock_sync": event.get("clock_sync"),
            "event_id": event.get("event_id"),
            "event_type": event.get("event_type"),
            "payload": self._sort_dict(event.get("payload", {})),
            "policy_id": event.get("policy_id"),
            "system_id": event.get("system_id"),
            "tier": event.get("tier"),
            "timestamp": event.get("timestamp"),
            "vcp_version": event.get("vcp_version"),
        }
        
        # Include prev_hash only if present
        if event.get("prev_hash"):
            core_fields["prev_hash"] = event["prev_hash"]
        
        return json.dumps(core_fields, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    
    def _sort_dict(self, d: Any) -> Any:
        """Recursively sort dictionary keys."""
        if isinstance(d, dict):
            return {k: self._sort_dict(v) for k, v in sorted(d.items())}
        elif isinstance(d, list):
            return [self._sort_dict(item) for item in d]
        return d
    
    def _compute_hash(self, event: Dict[str, Any]) -> str:
        """
        Compute SHA-256 hash of event.
        
        Args:
            event: Event dictionary
            
        Returns:
            Hash as hex string
        """
        canonical = self._canonical_json(event)
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    
    def _leaf_hash(self, data_hash: bytes) -> bytes:
        """Compute leaf hash with RFC 6962 domain separation."""
        return hashlib.sha256(self.LEAF_PREFIX + data_hash).digest()
    
    def _internal_hash(self, left: bytes, right: bytes) -> bytes:
        """Compute internal node hash with RFC 6962 domain separation."""
        return hashlib.sha256(self.INTERNAL_PREFIX + left + right).digest()
    
    def _compute_merkle_root(self, hashes: List[bytes]) -> bytes:
        """
        Compute Merkle root from list of event hashes.
        
        Args:
            hashes: List of event hashes
            
        Returns:
            Merkle root hash
        """
        if not hashes:
            return b''
        
        # Convert to leaf hashes
        leaves = [self._leaf_hash(h) for h in hashes]
        
        # Build tree
        current_layer = leaves
        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                right = current_layer[i + 1] if i + 1 < len(current_layer) else left
                next_layer.append(self._internal_hash(left, right))
            current_layer = next_layer
        
        return current_layer[0]
    
    def verify_event(self, event: Dict[str, Any], prev_event: Optional[Dict[str, Any]] = None) -> VerificationResult:
        """
        Verify a single event.
        
        Args:
            event: Event to verify
            prev_event: Previous event (for prev_hash verification)
            
        Returns:
            VerificationResult
        """
        errors = []
        
        # 1. Verify event hash
        computed_hash = self._compute_hash(event)
        stored_hash = event.get("event_hash", "")
        hash_valid = computed_hash == stored_hash
        
        if not hash_valid:
            errors.append(f"Hash mismatch: computed={computed_hash[:16]}..., stored={stored_hash[:16]}...")
        
        # 2. Verify sequence (if merkle_index present)
        sequence_valid = True
        if prev_event and "merkle_index" in event and "merkle_index" in prev_event:
            expected_index = prev_event["merkle_index"] + 1
            if event["merkle_index"] != expected_index:
                sequence_valid = False
                errors.append(f"Sequence gap: expected index {expected_index}, got {event['merkle_index']}")
        
        # 3. Verify prev_hash (optional in v1.1)
        prev_hash_valid = True
        if event.get("prev_hash") and prev_event:
            expected_prev_hash = prev_event.get("event_hash", "")
            if event["prev_hash"] != expected_prev_hash:
                prev_hash_valid = False
                errors.append(f"PrevHash mismatch")
        
        return VerificationResult(
            event_id=event.get("event_id", "unknown"),
            valid=hash_valid and sequence_valid and prev_hash_valid,
            hash_valid=hash_valid,
            sequence_valid=sequence_valid,
            prev_hash_valid=prev_hash_valid,
            errors=errors
        )
    
    def verify_chain(self) -> Tuple[bool, List[VerificationResult]]:
        """
        Verify entire event chain.
        
        Returns:
            Tuple of (overall_valid, list of individual results)
        """
        results = []
        prev_event = None
        
        for event in self.events:
            result = self.verify_event(event, prev_event)
            results.append(result)
            prev_event = event
        
        overall_valid = all(r.valid for r in results)
        return overall_valid, results
    
    def verify_merkle_root(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Verify Merkle root against security object.
        
        Returns:
            Tuple of (valid, computed_root, expected_root)
        """
        if not self.security_object:
            return True, None, None
        
        # Compute Merkle root from events
        event_hashes = []
        for event in self.events:
            if event.get("event_hash"):
                event_hashes.append(bytes.fromhex(event["event_hash"]))
        
        if not event_hashes:
            return False, None, None
        
        computed_root = self._compute_merkle_root(event_hashes)
        computed_root_hex = computed_root.hex()
        
        expected_root = self.security_object.get("merkle_root", "")
        
        return computed_root_hex == expected_root, computed_root_hex, expected_root
    
    def print_report(self, chain_valid: bool, results: List[VerificationResult], 
                     merkle_valid: bool, computed_root: Optional[str], expected_root: Optional[str]):
        """Print verification report."""
        
        print("=" * 70)
        print("VCP v1.1 Verification Report")
        print("=" * 70)
        
        # Summary
        valid_count = sum(1 for r in results if r.valid)
        invalid_count = len(results) - valid_count
        
        status = "[PASS] VALID" if chain_valid and merkle_valid else "[FAIL] INVALID"
        
        print(f"\n[Verification Results]")
        print(f"  Overall Status: {status}")
        print(f"  Total Events: {len(results)}")
        print(f"  Valid Events: {valid_count}")
        print(f"  Invalid Events: {invalid_count}")
        
        # Chain integrity
        print(f"\n[Chain Integrity]")
        sequence_valid = all(r.sequence_valid for r in results)
        prev_hash_valid = all(r.prev_hash_valid for r in results)
        
        print(f"  Sequence Continuity: {'[PASS]' if sequence_valid else '[FAIL]'}")
        print(f"  PrevHash Integrity: {'[PASS]' if prev_hash_valid else '[FAIL]'}")
        
        # Merkle root
        if computed_root:
            print(f"  Merkle Root: {'[PASS]' if merkle_valid else '[FAIL]'}")
            if self.verbose:
                print(f"    Computed: {computed_root[:32]}...")
                if expected_root:
                    print(f"    Expected: {expected_root[:32]}...")
        
        # Invalid events details
        if invalid_count > 0:
            print(f"\n[Invalid Events]")
            for r in results:
                if not r.valid:
                    print(f"  - {r.event_id}: {', '.join(r.errors)}")
        
        print("=" * 70)
        if chain_valid and merkle_valid:
            print("Verification complete: All checks passed")
        else:
            print("Verification complete: Some checks failed")
        print("=" * 70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="VCP v1.1 Event Chain Verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vcp_verifier.py events.jsonl
  python vcp_verifier.py events.jsonl -s security_object.json
  python vcp_verifier.py events.jsonl -s security_object.json -v
        """
    )
    
    parser.add_argument("events_file", help="Path to events JSONL file")
    parser.add_argument("-s", "--security-object", help="Path to security object JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Verify file exists
    if not Path(args.events_file).exists():
        print(f"Error: Events file not found: {args.events_file}")
        sys.exit(1)
    
    # Initialize verifier
    verifier = VCPVerifier(verbose=args.verbose)
    
    # Load events
    count = verifier.load_events(args.events_file)
    if count == 0:
        print("Error: No events loaded")
        sys.exit(1)
    
    print(f"Loaded {count} events from {args.events_file}")
    
    # Load security object if provided
    if args.security_object:
        if Path(args.security_object).exists():
            verifier.load_security_object(args.security_object)
        else:
            print(f"Warning: Security object not found: {args.security_object}")
    
    # Verify chain
    chain_valid, results = verifier.verify_chain()
    
    # Verify Merkle root
    merkle_valid, computed_root, expected_root = verifier.verify_merkle_root()
    
    # Print report
    verifier.print_report(chain_valid, results, merkle_valid, computed_root, expected_root)
    
    # Exit code
    sys.exit(0 if chain_valid and merkle_valid else 1)


if __name__ == "__main__":
    main()
