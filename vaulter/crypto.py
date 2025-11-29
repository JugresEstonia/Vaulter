from argon2.low_level import hash_secret_raw, Type
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)
from nacl.exceptions import CryptoError
import os, hmac, ctypes

NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES

ARGON2_PARAMS = dict(
    time_cost=3,
    memory_cost=256 * 1024,
    parallelism=2,
    hash_len=32,
    type=Type.ID,
)


def kdf_argon2id(password_bytes: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte key from the user-supplied password using Argon2id."""
    try:
        return hash_secret_raw(password_bytes, salt, **ARGON2_PARAMS)
    finally:
        zero_bytes(password_bytes)


def gen_nonce() -> bytes:
    """Return a cryptographically-random 24-byte nonce for XChaCha20-Poly1305."""
    return os.urandom(NONCE_SIZE)


def gen_key() -> bytes:
    """Return a random 256-bit key for wrapping DEKs and encrypting filenames."""
    return os.urandom(KEY_SIZE)


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, ad: bytes) -> bytes:
    """Encrypt `plaintext` with XChaCha20-Poly1305 using the supplied nonce and AD."""
    return crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, nonce, key)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    """Decrypt a ciphertext produced by `aead_encrypt`, raising ValueError on failure."""
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, ad, nonce, key)
    except CryptoError as exc:
        raise ValueError("decryption failed") from exc


def consteq(a: bytes, b: bytes) -> bool:
    """Constant-time comparison helper to avoid timing leaks when comparing secrets."""
    return hmac.compare_digest(a, b)

def zero_bytes(b: bytes):
    """Best-effort zeroization for mutable buffers that held sensitive information."""
    if isinstance(b, bytearray):
        for i in range(len(b)):
            b[i] = 0
    elif isinstance(b, memoryview) and not b.readonly:
        b[:] = b"\x00" * len(b)
