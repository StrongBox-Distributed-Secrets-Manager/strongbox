#!/usr/bin/env python3
"""
StrongBox Cryptographic Primitive Provider
This module provides AES-256-GCM primitives that are not available in the
standard OpenSSL CLI `enc` command. It is used as a specialized math/primitive
helper, similar to shamir.py, to avoid implementing the GCM tag and nonce
logic in pure Bash.
"""
import sys
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key_hex, plaintext):
    """
    AES-256-GCM Encryption
    Returns: hex(nonce + ciphertext + tag)
    """
    try:
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            print(f"Error: Key must be 32 bytes (64 hex chars), got {len(key)}", file=sys.stderr)
            sys.exit(1)

        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # Standard GCM nonce size
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return (nonce + ciphertext).hex()
    except Exception as e:
        print(f"Encryption failed: {e}", file=sys.stderr)
        sys.exit(1)

def decrypt(key_hex, blob_hex):
    """
    AES-256-GCM Decryption
    Input: hex(nonce + ciphertext + tag)
    """
    try:
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            print(f"Error: Key must be 32 bytes (64 hex chars), got {len(key)}", file=sys.stderr)
            sys.exit(1)

        aesgcm = AESGCM(key)
        blob = bytes.fromhex(blob_hex)
        if len(blob) < 28: # 12 nonce + 16 tag minimum
            print("Error: Blob too short for GCM", file=sys.stderr)
            sys.exit(1)

        nonce = blob[:12]
        ciphertext = blob[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    if len(sys.argv) < 3:
        print("usage: crypto_helper.py encrypt <key_hex> <plaintext>")
        print("       crypto_helper.py decrypt <key_hex> <blob_hex>")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "encrypt":
        print(encrypt(sys.argv[2], sys.argv[3]))
    elif mode == "decrypt":
        print(decrypt(sys.argv[2], sys.argv[3]))
    else:
        print(f"Unknown mode: {mode}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()