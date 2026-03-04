"""
Ixoryn Cryptography Engine
Uses: Argon2id (KDF), AES-256-GCM (encryption), Ed25519 (signatures)
      BLAKE2b, SHA-3 (hashing), ChaCha20-Poly1305 (alternative cipher)
"""

import os
import struct
import hashlib
import json
import base64
from typing import Tuple, Optional
from ixoryn.core.logger import get_logger

logger = get_logger("crypto")

# Argon2id parameters (OWASP recommended)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32

# Magic bytes for encrypted file format
MAGIC = b"IXORYN\x01"

# Supported hash algorithms
HASH_ALGORITHMS = {
    "SHA-256": lambda d: hashlib.sha256(d).hexdigest(),
    "SHA-512": lambda d: hashlib.sha512(d).hexdigest(),
    "SHA-3-256": lambda d: hashlib.sha3_256(d).hexdigest(),
    "SHA-3-512": lambda d: hashlib.sha3_512(d).hexdigest(),
    "BLAKE2b": lambda d: hashlib.blake2b(d).hexdigest(),
    "BLAKE2s": lambda d: hashlib.blake2s(d).hexdigest(),
}


class CryptoEngine:
    """
    Core cryptographic operations for Ixoryn.
    All encryption uses Argon2id for key derivation + AES-256-GCM.
    Signatures use Ed25519 (libsodium via PyNaCl).
    """

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a 32-byte key using Argon2id."""
        try:
            from argon2.low_level import hash_secret_raw, Type
            key = hash_secret_raw(
                secret=password.encode("utf-8"),
                salt=salt,
                time_cost=ARGON2_TIME_COST,
                memory_cost=ARGON2_MEMORY_COST,
                parallelism=ARGON2_PARALLELISM,
                hash_len=ARGON2_HASH_LEN,
                type=Type.ID,
            )
            return key
        except ImportError:
            raise RuntimeError(
                "argon2-cffi is required for cryptography. "
                "Install it with: pip install argon2-cffi"
            )

    def encrypt(self, data: bytes, password: str, filename: Optional[str] = None) -> bytes:
        """
        Encrypt data using AES-256-GCM with Argon2id key derivation.

        Format:
          MAGIC (7) | salt (16) | nonce (12) | filename_len (2) | filename (var) | ciphertext + tag
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise RuntimeError("cryptography package required. Install: pip install cryptography")

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(password, salt)

        # Encode filename metadata
        fname_bytes = (filename or "").encode("utf-8")[:255]
        fname_len = struct.pack(">H", len(fname_bytes))

        # Encrypt
        aesgcm = AESGCM(key)
        aad = MAGIC + salt + nonce + fname_len + fname_bytes  # authenticated data
        ciphertext = aesgcm.encrypt(nonce, data, aad)

        result = MAGIC + salt + nonce + fname_len + fname_bytes + ciphertext

        logger.info(f"Encrypted {len(data)} bytes → {len(result)} bytes")
        return result

    def decrypt(self, ciphertext: bytes, password: str) -> Tuple[bytes, Optional[str]]:
        """
        Decrypt data encrypted by CryptoEngine.encrypt().
        Returns (plaintext, filename_or_None)
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise RuntimeError("cryptography package required.")

        offset = 0

        # Verify magic
        if ciphertext[:7] != MAGIC:
            raise ValueError(
                "Invalid encrypted file format. "
                "File may not be an Ixoryn encrypted file, or it may be corrupted."
            )
        offset += 7

        salt = ciphertext[offset:offset + 16]
        offset += 16
        nonce = ciphertext[offset:offset + 12]
        offset += 12

        fname_len = struct.unpack(">H", ciphertext[offset:offset + 2])[0]
        offset += 2

        fname_bytes = ciphertext[offset:offset + fname_len]
        filename = fname_bytes.decode("utf-8") if fname_bytes else None
        offset += fname_len

        key = self._derive_key(password, salt)

        aad = MAGIC + salt + nonce + struct.pack(">H", fname_len) + fname_bytes
        aesgcm = AESGCM(key)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext[offset:], aad)
        except Exception:
            raise ValueError(
                "Decryption failed. "
                "Possible causes: wrong password, corrupted ciphertext, or tampered data."
            )

        logger.info(f"Decrypted {len(ciphertext)} bytes → {len(plaintext)} bytes")
        return plaintext, filename

    def hash_data(self, data: bytes, algorithm: str = "SHA-256") -> str:
        """Hash data using the specified algorithm."""
        alg = algorithm.upper().replace("-", "-")
        if alg not in HASH_ALGORITHMS:
            # Try case-insensitive match
            matches = [k for k in HASH_ALGORITHMS if k.upper() == alg]
            if matches:
                alg = matches[0]
            else:
                raise ValueError(
                    f"Unknown algorithm '{algorithm}'. "
                    f"Supported: {', '.join(HASH_ALGORITHMS.keys())}"
                )
        return HASH_ALGORITHMS[alg](data)

    def generate_keypair(self, password: str) -> Tuple[bytes, bytes]:
        """
        Generate an Ed25519 key pair.
        Private key is encrypted with Argon2id + AES-256-GCM.
        Returns (encrypted_private_key_bytes, public_key_bytes)
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat, PrivateFormat, NoEncryption
            )
        except ImportError:
            raise RuntimeError("cryptography package required.")

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize keys
        priv_bytes = private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption()
        )
        pub_bytes = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )

        # Encrypt private key with password
        encrypted_priv = self.encrypt(priv_bytes, password, filename="ed25519.privkey")

        logger.info("Generated Ed25519 key pair")
        return encrypted_priv, pub_bytes

    def sign(self, data: bytes, encrypted_private_key: bytes, password: str) -> bytes:
        """
        Sign data with an Ed25519 private key.
        Returns the 64-byte signature.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            raise RuntimeError("cryptography package required.")

        priv_bytes, _ = self.decrypt(encrypted_private_key, password)

        private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        signature = private_key.sign(data)

        logger.info(f"Signed {len(data)} bytes of data")
        return signature

    def verify(self, data: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        """
        Verify an Ed25519 signature.
        Returns True if valid, False otherwise.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
        except ImportError:
            raise RuntimeError("cryptography package required.")

        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        try:
            public_key.verify(signature, data)
            logger.info("Signature verification: VALID")
            return True
        except InvalidSignature:
            logger.info("Signature verification: INVALID")
            return False

    def encrypt_with_nacl(self, data: bytes, recipient_public_key: bytes,
                          sender_private_key: bytes) -> bytes:
        """
        Encrypt data for a recipient using NaCl Box (X25519 + XSalsa20-Poly1305).
        Used for asymmetric public-key encryption (sender knows recipient's public key).
        """
        try:
            import nacl.public
            import nacl.utils
        except ImportError:
            raise RuntimeError("PyNaCl required for asymmetric encryption.")

        sender_key = nacl.public.PrivateKey(sender_private_key)
        recipient_key = nacl.public.PublicKey(recipient_public_key)
        box = nacl.public.Box(sender_key, recipient_key)
        return bytes(box.encrypt(data))

    def decrypt_with_nacl(self, ciphertext: bytes, sender_public_key: bytes,
                          recipient_private_key: bytes) -> bytes:
        """Decrypt data encrypted with encrypt_with_nacl."""
        try:
            import nacl.public
        except ImportError:
            raise RuntimeError("PyNaCl required.")

        recipient_key = nacl.public.PrivateKey(recipient_private_key)
        sender_key = nacl.public.PublicKey(sender_public_key)
        box = nacl.public.Box(recipient_key, sender_key)
        return bytes(box.decrypt(ciphertext))

    def get_file_fingerprint(self, data: bytes) -> dict:
        """Get comprehensive cryptographic fingerprints of data."""
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
            "sha3_256": hashlib.sha3_256(data).hexdigest(),
            "blake2b": hashlib.blake2b(data).hexdigest(),
            "size_bytes": len(data),
        }
