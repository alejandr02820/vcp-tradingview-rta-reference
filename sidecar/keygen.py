"""
VCP Key Generation Utility
Generates Ed25519 key pairs for VCP signing

Usage:
    python -m sidecar.keygen [--output-dir ./keys]

Copyright (c) 2025 VeritasChain Standards Organization
License: MIT
"""

import argparse
import os
from pathlib import Path
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def generate_keys(output_dir: str = "./keys") -> dict:
    """
    Generate Ed25519 key pair and save to files.
    
    Args:
        output_dir: Directory to save keys
    
    Returns:
        Dictionary with key paths and public key hex
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    private_key_path = output_path / "ed25519_private.pem"
    public_key_path = output_path / "ed25519_public.pem"
    
    if not CRYPTO_AVAILABLE:
        print("Error: cryptography library not installed.")
        print("Install with: pip install cryptography")
        return None
    
    # Check if keys already exist
    if private_key_path.exists():
        response = input(f"Keys already exist at {output_dir}. Overwrite? [y/N]: ")
        if response.lower() != 'y':
            print("Aborted.")
            return None
    
    print("Generating Ed25519 key pair...")
    
    # Generate key pair
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Get raw public key for display
    public_key_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    # Save private key with restricted permissions
    with open(private_key_path, 'wb') as f:
        f.write(private_pem)
    os.chmod(private_key_path, 0o600)
    
    # Save public key
    with open(public_key_path, 'wb') as f:
        f.write(public_pem)
    
    # Create key info file
    info_path = output_path / "key_info.txt"
    with open(info_path, 'w') as f:
        f.write(f"VCP Ed25519 Key Pair\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Algorithm: Ed25519\n")
        f.write(f"Public Key (hex): {public_key_raw.hex()}\n")
        f.write(f"Private Key: {private_key_path}\n")
        f.write(f"Public Key: {public_key_path}\n")
    
    result = {
        "private_key_path": str(private_key_path),
        "public_key_path": str(public_key_path),
        "public_key_hex": public_key_raw.hex(),
        "algorithm": "Ed25519"
    }
    
    print(f"\n✓ Keys generated successfully!")
    print(f"  Private key: {private_key_path}")
    print(f"  Public key:  {public_key_path}")
    print(f"  Public key (hex): {public_key_raw.hex()}")
    print(f"\n⚠ IMPORTANT: Keep your private key secure!")
    print(f"  - Do not commit to version control")
    print(f"  - Set restrictive file permissions (chmod 600)")
    print(f"  - Back up securely")
    
    return result


def verify_keys(key_dir: str = "./keys") -> bool:
    """
    Verify that keys exist and are valid.
    
    Args:
        key_dir: Directory containing keys
    
    Returns:
        True if keys are valid
    """
    key_path = Path(key_dir)
    private_key_path = key_path / "ed25519_private.pem"
    public_key_path = key_path / "ed25519_public.pem"
    
    if not private_key_path.exists():
        print(f"✗ Private key not found: {private_key_path}")
        return False
    
    if not public_key_path.exists():
        print(f"✗ Public key not found: {public_key_path}")
        return False
    
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        # Load and verify private key
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        
        # Load and verify public key
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )
        
        # Test sign/verify
        test_message = b"VCP key verification test"
        signature = private_key.sign(test_message)
        public_key.verify(signature, test_message)
        
        print(f"✓ Keys verified successfully!")
        print(f"  Private key: {private_key_path}")
        print(f"  Public key:  {public_key_path}")
        
        # Show public key hex
        public_key_raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        print(f"  Public key (hex): {public_key_raw.hex()}")
        
        return True
        
    except Exception as e:
        print(f"✗ Key verification failed: {e}")
        return False


def main():
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        description="VCP Ed25519 Key Generation Utility"
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="./keys",
        help="Directory to save keys (default: ./keys)"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify existing keys instead of generating new ones"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("VCP Key Generation Utility")
    print("VeritasChain Protocol v1.1")
    print("=" * 60)
    print()
    
    if args.verify:
        verify_keys(args.output_dir)
    else:
        generate_keys(args.output_dir)


if __name__ == "__main__":
    main()
