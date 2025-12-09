from pydantic import BaseModel, Field, field_validator
from typing import List, Optional

class RecoveryConfig(BaseModel):
    """Metadata describing the wrapped master key used for password recovery."""
    nonce_b64: str
    wrapped_master_b64: str

class VaultConfig(BaseModel):
    """Top-level config file stored next to the vault; contains salts and wrap info."""
    version: int = 1
    kdf_salt_b64: str
    index_ad_b64: str
    master_wrap_nonce_b64: Optional[str] = None
    wrapped_master_b64: Optional[str] = None
    recovery: Optional[RecoveryConfig] = None

class IndexRecord(BaseModel):
    """Single entry in the encrypted index describing a stored blob."""
    id: str                          # blob id (hex)
    enc_name_b64: str                # base64([24B nonce][ciphertext(tag)])
    size: int
    created: str
    aead: str = "xchacha20poly1305"
    nonce_b64: str                   # for DEK wrap
    ad_b64: str                      # blob AD (16 bytes)
    wrapped_dek_b64: str
    tags: List[str] = []

    @field_validator("size")
    @classmethod
    def validate_size(cls, v: int):
        """Ensure stored plaintext sizes remain within supported limits."""
        if v < 0:
            raise ValueError("size must be non-negative")
        if v > (1 << 35):
            raise ValueError("size exceeds supported limit")
        return v

class IndexFile(BaseModel):
    """Collection of `IndexRecord` objects persisted in the encrypted index."""
    records: List[IndexRecord] = []


@field_validator("size")
def validate_size(cls, v: int):
    """Module-level validator used by legacy callers to enforce safe sizes."""
    if v < 0:
        raise ValueError("size must be non-negative")
    if v > (1 << 35):
        raise ValueError("size exceeds supported limit")
    return v
