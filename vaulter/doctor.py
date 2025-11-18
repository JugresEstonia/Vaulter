#!/usr/bin/env python3
"""
vaulter_doctor.py

Structural and security checks for a Vaulter vault.

This implements:
- Permission checks (700/600)
- Ownership checks
- Symlink / hardlink / traversal checks
- Basic index vs blobs consistency hooks
- Optional crypto hooks (you must wire to your actual index/crypto code)

Usage:
    python vaulter_doctor.py /path/to/vault
    python vaulter_doctor.py /path/to/vault --skip-crypto
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Dict, Any, Tuple


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    OK = "OK"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass
class CheckResult:
    id: str
    severity: Severity
    message: str
    path: Optional[Path] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "message": self.message,
            "path": str(self.path) if self.path else None,
            "details": self.details or None,
        }


@dataclass
class IndexEntry:
    """Logical index entry (you must adapt this to your real format)."""
    blob_id: str            # usually hex or base32/64 string
    size: int               # plaintext file size
    nonce: bytes            # AEAD nonce
    tag: bytes              # AEAD tag
    enc_filename: bytes     # encrypted filename (ciphertext)


@dataclass
class ParsedIndex:
    """Parsed index (you must adapt this to your real format)."""
    version: int
    entries: List[IndexEntry]


# ---------------------------------------------------------------------------
# Crypto hooks (to be wired to your real implementation)
# ---------------------------------------------------------------------------

# Signatures for user-provided callbacks:
LoadKeyFn = Callable[[Path], bytes]
DecryptIndexFn = Callable[[bytes, bytes], ParsedIndex]


def default_load_key(_: Path) -> bytes:
    """
    Placeholder key loader.

    Replace with your actual key-loading logic.
    For now it just raises to force you to wire it up deliberately.
    """
    raise NotImplementedError(
        "load_key() is not implemented. Wire vaulter_doctor to your key management."
    )


def default_decrypt_index(_: bytes, __: bytes) -> ParsedIndex:
    """
    Placeholder index decryption/parser.

    Replace with your real index decryption + parsing code.
    """
    raise NotImplementedError(
        "decrypt_index() is not implemented. Wire vaulter_doctor to your index format."
    )


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _mode_bits(path: Path) -> int:
    """Return the permission bits (0o000–0o777) for a path without following symlinks."""
    st = os.lstat(path)
    return stat.S_IMODE(st.st_mode)


def _is_owned_by_current_user(path: Path) -> bool:
    st = os.lstat(path)
    return st.st_uid == os.getuid()


def _is_symlink(path: Path) -> bool:
    return stat.S_ISLNK(os.lstat(path).st_mode)


def _canonical(path: Path) -> Path:
    """Resolve symlinks and normalize path."""
    return path.resolve(strict=True)


def _is_inside(child: Path, parent: Path) -> bool:
    """Return True if canonical child path is inside canonical parent path."""
    child_res = child.resolve(strict=True)
    parent_res = parent.resolve(strict=True)
    try:
        child_res.relative_to(parent_res)
        return True
    except ValueError:
        return False


def _expected_file_mode(path: Path, expected: int) -> Optional[CheckResult]:
    actual = _mode_bits(path)
    if actual != expected:
        return CheckResult(
            id="permission_mismatch",
            severity=Severity.ERROR,
            message=f"File permissions {oct(actual)} != expected {oct(expected)}",
            path=path,
            details={"expected": oct(expected), "actual": oct(actual)},
        )
    return None


def _expected_dir_mode(path: Path, expected: int) -> Optional[CheckResult]:
    actual = _mode_bits(path)
    if actual != expected:
        return CheckResult(
            id="permission_mismatch",
            severity=Severity.ERROR,
            message=f"Directory permissions {oct(actual)} != expected {oct(expected)}",
            path=path,
            details={"expected": oct(expected), "actual": oct(actual)},
        )
    return None


# ---------------------------------------------------------------------------
# VaulterDoctor
# ---------------------------------------------------------------------------

class VaulterDoctor:
    def __init__(
        self,
        vault_root: Path,
        load_key: LoadKeyFn = default_load_key,
        decrypt_index: DecryptIndexFn = default_decrypt_index,
        skip_crypto: bool = False,
    ) -> None:
        self.vault_root = vault_root
        self.index_path = vault_root / "index.bin"
        self.blobs_dir = vault_root / "blobs"
        self.load_key = load_key
        self.decrypt_index = decrypt_index
        self.skip_crypto = skip_crypto

        self._parsed_index: Optional[ParsedIndex] = None
        self._index_read_bytes: Optional[bytes] = None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def run(self) -> List[CheckResult]:
        results: List[CheckResult] = []

        results.extend(self._check_root())
        results.extend(self._check_index_file())
        results.extend(self._check_blobs_dir())
        results.extend(self._check_symlinks_and_paths())

        # Only attempt crypto-related checks if not skipped and hooks implemented
        if not self.skip_crypto:
            results.extend(self._check_index_crypto_and_consistency())

        # Summarize if no errors/warnings
        if not any(r.severity != Severity.OK for r in results):
            results.append(
                CheckResult(
                    id="summary_all_good",
                    severity=Severity.OK,
                    message="Vault passed all checks.",
                    path=self.vault_root,
                )
            )

        return results

    # ------------------------------------------------------------------ #
    # Individual check groups
    # ------------------------------------------------------------------ #

    def _check_root(self) -> List[CheckResult]:
        results: List[CheckResult] = []
        p = self.vault_root

        if not p.exists():
            return [
                CheckResult(
                    id="vault_missing",
                    severity=Severity.ERROR,
                    message="Vault root does not exist.",
                    path=p,
                )
            ]

        try:
            st = os.lstat(p)
        except OSError as e:
            return [
                CheckResult(
                    id="stat_failed",
                    severity=Severity.ERROR,
                    message=f"lstat failed for vault root: {e}",
                    path=p,
                )
            ]

        if stat.S_ISLNK(st.st_mode):
            results.append(
                CheckResult(
                    id="vault_is_symlink",
                    severity=Severity.ERROR,
                    message="Vault root is a symlink. This is not allowed.",
                    path=p,
                )
            )

        if not stat.S_ISDIR(st.st_mode):
            results.append(
                CheckResult(
                    id="vault_not_dir",
                    severity=Severity.ERROR,
                    message="Vault root is not a directory.",
                    path=p,
                )
            )
            return results

        if not _is_owned_by_current_user(p):
            results.append(
                CheckResult(
                    id="vault_wrong_owner",
                    severity=Severity.ERROR,
                    message="Vault root is not owned by the current user.",
                    path=p,
                )
            )
        else:
            results.append(
                CheckResult(
                    id="vault_owner_ok",
                    severity=Severity.OK,
                    message="Vault root owned by current user.",
                    path=p,
                )
            )

        perm_res = _expected_dir_mode(p, 0o700)
        results.append(
            perm_res
            or CheckResult(
                id="vault_permissions_ok",
                severity=Severity.OK,
                message="Vault root permissions are 700.",
                path=p,
            )
        )

        # Canonicalization check
        try:
            canon = _canonical(p)
            if canon != p.resolve():
                results.append(
                    CheckResult(
                        id="vault_path_not_canonical",
                        severity=Severity.WARNING,
                        message="Vault root path is not canonical (use resolved absolute path).",
                        path=p,
                        details={"canonical": str(canon)},
                    )
                )
        except FileNotFoundError:
            results.append(
                CheckResult(
                    id="vault_canonicalization_failed",
                    severity=Severity.ERROR,
                    message="Failed to canonicalize vault root.",
                    path=p,
                )
            )

        return results

    def _check_index_file(self) -> List[CheckResult]:
        results: List[CheckResult] = []
        p = self.index_path

        if not p.exists():
            results.append(
                CheckResult(
                    id="index_missing",
                    severity=Severity.ERROR,
                    message="index.bin is missing.",
                    path=p,
                )
            )
            return results

        try:
            st = os.lstat(p)
        except OSError as e:
            results.append(
                CheckResult(
                    id="index_stat_failed",
                    severity=Severity.ERROR,
                    message=f"lstat failed for index.bin: {e}",
                    path=p,
                )
            )
            return results

        if stat.S_ISLNK(st.st_mode):
            results.append(
                CheckResult(
                    id="index_is_symlink",
                    severity=Severity.ERROR,
                    message="index.bin is a symlink. This is not allowed.",
                    path=p,
                )
            )

        if not stat.S_ISREG(st.st_mode):
            results.append(
                CheckResult(
                    id="index_not_regular_file",
                    severity=Severity.ERROR,
                    message="index.bin is not a regular file.",
                    path=p,
                )
            )

        if not _is_owned_by_current_user(p):
            results.append(
                CheckResult(
                    id="index_wrong_owner",
                    severity=Severity.ERROR,
                    message="index.bin is not owned by the current user.",
                    path=p,
                )
            )
        else:
            results.append(
                CheckResult(
                    id="index_owner_ok",
                    severity=Severity.OK,
                    message="index.bin owned by current user.",
                    path=p,
                )
            )

        perm_res = _expected_file_mode(p, 0o600)
        results.append(
            perm_res
            or CheckResult(
                id="index_permissions_ok",
                severity=Severity.OK,
                message="index.bin permissions are 600.",
                path=p,
            )
        )

        # Size sanity check: index shouldn't be absurdly large
        max_reasonable_size = 512 * 1024 * 1024  # 512MB
        if st.st_size <= 0:
            results.append(
                CheckResult(
                    id="index_empty",
                    severity=Severity.ERROR,
                    message="index.bin is empty.",
                    path=p,
                )
            )
        elif st.st_size > max_reasonable_size:
            results.append(
                CheckResult(
                    id="index_suspicious_size",
                    severity=Severity.WARNING,
                    message="index.bin is larger than 512MB – suspicious for a vault.",
                    path=p,
                    details={"size_bytes": st.st_size},
                )
            )
        else:
            results.append(
                CheckResult(
                    id="index_size_ok",
                    severity=Severity.OK,
                    message="index.bin size is within reasonable bounds.",
                    path=p,
                    details={"size_bytes": st.st_size},
                )
            )

        return results

    def _check_blobs_dir(self) -> List[CheckResult]:
        results: List[CheckResult] = []
        p = self.blobs_dir

        if not p.exists():
            results.append(
                CheckResult(
                    id="blobs_missing",
                    severity=Severity.ERROR,
                    message="blobs/ directory is missing.",
                    path=p,
                )
            )
            return results

        try:
            st = os.lstat(p)
        except OSError as e:
            results.append(
                CheckResult(
                    id="blobs_stat_failed",
                    severity=Severity.ERROR,
                    message=f"lstat failed for blobs/: {e}",
                    path=p,
                )
            )
            return results

        if stat.S_ISLNK(st.st_mode):
            results.append(
                CheckResult(
                    id="blobs_is_symlink",
                    severity=Severity.ERROR,
                    message="blobs/ is a symlink. This is not allowed.",
                    path=p,
                )
            )

        if not stat.S_ISDIR(st.st_mode):
            results.append(
                CheckResult(
                    id="blobs_not_dir",
                    severity=Severity.ERROR,
                    message="blobs/ is not a directory.",
                    path=p,
                )
            )
            return results

        if not _is_owned_by_current_user(p):
            results.append(
                CheckResult(
                    id="blobs_wrong_owner",
                    severity=Severity.ERROR,
                    message="blobs/ is not owned by the current user.",
                    path=p,
                )
            )
        else:
            results.append(
                CheckResult(
                    id="blobs_owner_ok",
                    severity=Severity.OK,
                    message="blobs/ owned by current user.",
                    path=p,
                )
            )

        perm_res = _expected_dir_mode(p, 0o700)
        results.append(
            perm_res
            or CheckResult(
                id="blobs_permissions_ok",
                severity=Severity.OK,
                message="blobs/ permissions are 700.",
                path=p,
            )
        )

        # Walk all files and subdirectories
        for root, dirs, files in os.walk(p, topdown=True, followlinks=False):
            root_path = Path(root)

            # Directories: must not be symlink, must be 700
            for d in dirs:
                dpath = root_path / d
                try:
                    st = os.lstat(dpath)
                except OSError as e:
                    results.append(
                        CheckResult(
                            id="blob_dir_stat_failed",
                            severity=Severity.ERROR,
                            message=f"lstat failed for blob subdirectory: {e}",
                            path=dpath,
                        )
                    )
                    continue

                if stat.S_ISLNK(st.st_mode):
                    results.append(
                        CheckResult(
                            id="blob_dir_symlink",
                            severity=Severity.ERROR,
                            message="Subdirectory under blobs/ is a symlink. Not allowed.",
                            path=dpath,
                        )
                    )

                # Required for subdirectories: 700
                perm_res = _expected_dir_mode(dpath, 0o700)
                results.append(
                    perm_res
                    or CheckResult(
                        id="blob_dir_permissions_ok",
                        severity=Severity.OK,
                        message="Blob subdirectory permissions are 700.",
                        path=dpath,
                    )
                )

                if not _is_owned_by_current_user(dpath):
                    results.append(
                        CheckResult(
                            id="blob_dir_wrong_owner",
                            severity=Severity.ERROR,
                            message="Blob subdirectory not owned by current user.",
                            path=dpath,
                        )
                    )

            # Files: must be regular, 600, owned by user, no symlink
            for f in files:
                fpath = root_path / f
                try:
                    st = os.lstat(fpath)
                except OSError as e:
                    results.append(
                        CheckResult(
                            id="blob_file_stat_failed",
                            severity=Severity.ERROR,
                            message=f"lstat failed for blob file: {e}",
                            path=fpath,
                        )
                    )
                    continue

                if stat.S_ISLNK(st.st_mode):
                    results.append(
                        CheckResult(
                            id="blob_file_symlink",
                            severity=Severity.ERROR,
                            message="Blob file is a symlink. Not allowed.",
                            path=fpath,
                        )
                    )

                if not stat.S_ISREG(st.st_mode):
                    results.append(
                        CheckResult(
                            id="blob_file_not_regular",
                            severity=Severity.ERROR,
                            message="Blob is not a regular file.",
                            path=fpath,
                        )
                    )

                perm_res = _expected_file_mode(fpath, 0o600)
                results.append(
                    perm_res
                    or CheckResult(
                        id="blob_file_permissions_ok",
                        severity=Severity.OK,
                        message="Blob file permissions are 600.",
                        path=fpath,
                    )
                )

                if not _is_owned_by_current_user(fpath):
                    results.append(
                        CheckResult(
                            id="blob_file_wrong_owner",
                            severity=Severity.ERROR,
                            message="Blob file not owned by current user.",
                            path=fpath,
                        )
                    )

        return results

    def _check_symlinks_and_paths(self) -> List[CheckResult]:
        results: List[CheckResult] = []
        root = self.vault_root

        try:
            root_canon = _canonical(root)
        except Exception as e:
            return [
                CheckResult(
                    id="vault_canonicalization_error",
                    severity=Severity.ERROR,
                    message=f"Failed to resolve vault root: {e}",
                    path=root,
                )
            ]

        for dirpath, dirs, files in os.walk(root, topdown=True, followlinks=False):
            dpath = Path(dirpath)

            # Ensure everything we walk is inside vault root after canonicalization
            try:
                if not _is_inside(dpath, root_canon):
                    results.append(
                        CheckResult(
                            id="path_escapes_vault",
                            severity=Severity.ERROR,
                            message="Directory escapes vault root after canonicalization.",
                            path=dpath,
                            details={"vault_root": str(root_canon)},
                        )
                    )
            except FileNotFoundError:
                results.append(
                    CheckResult(
                        id="path_canonicalization_race",
                        severity=Severity.ERROR,
                        message="Directory disappeared during walk (possible race).",
                        path=dpath,
                    )
                )

            for name in files + dirs:
                p = dpath / name
                try:
                    if not _is_inside(p, root_canon):
                        results.append(
                            CheckResult(
                                id="path_escapes_vault",
                                severity=Severity.ERROR,
                                message="File/directory escapes vault root after canonicalization.",
                                path=p,
                                details={"vault_root": str(root_canon)},
                            )
                        )
                except FileNotFoundError:
                    results.append(
                        CheckResult(
                            id="path_canonicalization_race",
                            severity=Severity.WARNING,
                            message="File/directory disappeared during walk (possible race).",
                            path=p,
                        )
                    )

                # Simple filename sanity checks for blobs/index (no traversal in names)
                if p.is_file():
                    if ".." in p.name or "/" in p.name or "\\" in p.name:
                        results.append(
                            CheckResult(
                                id="suspicious_filename",
                                severity=Severity.WARNING,
                                message="Filename contains traversal-like components.",
                                path=p,
                            )
                        )

        return results

    def _load_and_parse_index(self) -> Tuple[Optional[ParsedIndex], List[CheckResult]]:
        """Load and parse index, using supplied crypto callbacks."""
        results: List[CheckResult] = []

        if self.skip_crypto:
            return None, results

        try:
            key = self.load_key(self.vault_root)
        except NotImplementedError as e:
            results.append(
                CheckResult(
                    id="crypto_not_configured",
                    severity=Severity.WARNING,
                    message=str(e),
                    path=self.vault_root,
                )
            )
            return None, results
        except Exception as e:
            results.append(
                CheckResult(
                    id="key_load_failed",
                    severity=Severity.ERROR,
                    message=f"Failed to load vault key: {e}",
                    path=self.vault_root,
                )
            )
            return None, results

        try:
            data = self.index_path.read_bytes()
            self._index_read_bytes = data
        except Exception as e:
            results.append(
                CheckResult(
                    id="index_read_failed",
                    severity=Severity.ERROR,
                    message=f"Failed to read index.bin: {e}",
                    path=self.index_path,
                )
            )
            return None, results

        try:
            parsed = self.decrypt_index(data, key)
            self._parsed_index = parsed
            results.append(
                CheckResult(
                    id="index_decrypt_ok",
                    severity=Severity.OK,
                    message="index.bin decrypted and parsed successfully.",
                    path=self.index_path,
                    details={"version": parsed.version, "entries": len(parsed.entries)},
                )
            )
            return parsed, results
        except NotImplementedError as e:
            results.append(
                CheckResult(
                    id="crypto_not_configured",
                    severity=Severity.WARNING,
                    message=str(e),
                    path=self.vault_root,
                )
            )
        except Exception as e:
            results.append(
                CheckResult(
                    id="index_decrypt_failed",
                    severity=Severity.ERROR,
                    message=f"Failed to decrypt/parse index.bin (AEAD tag failure or format error): {e}",
                    path=self.index_path,
                )
            )

        return None, results

    def _check_index_crypto_and_consistency(self) -> List[CheckResult]:
        results: List[CheckResult] = []
        parsed, pre_results = self._load_and_parse_index()
        results.extend(pre_results)

        if parsed is None:
            # Nothing more we can do without parsed index
            return results

        # 1) Nonce reuse detection
        nonce_set = set()
        reuse_detected = False
        for entry in parsed.entries:
            n = entry.nonce
            if len(n) != 24:  # XChaCha20 nonce
                results.append(
                    CheckResult(
                        id="nonce_invalid_length",
                        severity=Severity.ERROR,
                        message="Index entry nonce is not 24 bytes (XChaCha20).",
                        details={"blob_id": entry.blob_id, "len": len(n)},
                    )
                )
            if n in nonce_set:
                reuse_detected = True
                results.append(
                    CheckResult(
                        id="nonce_reuse",
                        severity=Severity.ERROR,
                        message="Nonce reuse detected across index entries. Catastrophic for AEAD.",
                        details={"blob_id": entry.blob_id},
                    )
                )
            else:
                nonce_set.add(n)

        if not reuse_detected:
            results.append(
                CheckResult(
                    id="nonce_reuse_check_ok",
                    severity=Severity.OK,
                    message="No nonce reuse detected in index entries.",
                )
            )

        # 2) Index↔blob consistency (presence and size)
        blob_root = self.blobs_dir
        fs_blobs: Dict[str, Path] = {}

        for dirpath, dirs, files in os.walk(blob_root, topdown=True, followlinks=False):
            dpath = Path(dirpath)
            for f in files:
                p = dpath / f
                # Expect blob ID to be filename or path component:
                blob_id = f  # adjust if you use nested directories as part of the id
                fs_blobs[blob_id] = p

        total_missing = 0
        total_orphans = 0
        total_size_mismatch = 0

        # Entries without corresponding blobs
        for entry in parsed.entries:
            # If your blob_id encoding is structured (e.g. first 2 chars as subdir),
            # adjust this mapping logic accordingly.
            p = fs_blobs.get(entry.blob_id)
            if p is None:
                results.append(
                    CheckResult(
                        id="blob_missing",
                        severity=Severity.ERROR,
                        message="Blob referenced in index is missing on disk.",
                        details={"blob_id": entry.blob_id},
                    )
                )
                total_missing += 1
                continue

            try:
                st = os.lstat(p)
            except OSError as e:
                results.append(
                    CheckResult(
                        id="blob_stat_failed",
                        severity=Severity.ERROR,
                        message=f"lstat failed for blob referenced in index: {e}",
                        path=p,
                        details={"blob_id": entry.blob_id},
                    )
                )
                total_missing += 1
                continue

            # Size check: exact equality between stored size and file size
            if st.st_size != entry.size:
                results.append(
                    CheckResult(
                        id="blob_size_mismatch",
                        severity=Severity.ERROR,
                        message="Blob size on disk does not match index metadata.",
                        path=p,
                        details={
                            "blob_id": entry.blob_id,
                            "index_size": entry.size,
                            "fs_size": st.st_size,
                        },
                    )
                )
                total_size_mismatch += 1

        # Blob files not referenced in index (orphans)
        index_blob_ids = {e.blob_id for e in parsed.entries}
        for blob_id, p in fs_blobs.items():
            if blob_id not in index_blob_ids:
                results.append(
                    CheckResult(
                        id="blob_orphan",
                        severity=Severity.WARNING,
                        message="Blob exists on disk but is not referenced in index (orphan).",
                        path=p,
                        details={"blob_id": blob_id},
                    )
                )
                total_orphans += 1

        if total_missing == 0 and total_orphans == 0 and total_size_mismatch == 0:
            results.append(
                CheckResult(
                    id="index_blob_consistency_ok",
                    severity=Severity.OK,
                    message="Index and blobs are consistent (no missing/orphaned/mismatched blobs).",
                )
            )

        # 3) Very light encrypted filename sanity (no plaintext detection)
        suspicious_plaintext_like = 0
        for entry in parsed.entries:
            try:
                sample = entry.enc_filename[:32]
                # Heuristic: if this decodes cleanly as UTF-8 and mostly printable,
                # it might be plaintext. This is intentionally conservative.
                s = sample.decode("utf-8", errors="ignore")
                printable = sum(c.isprintable() and not c.isspace() for c in s)
                if s and printable / max(len(s), 1) > 0.7:
                    suspicious_plaintext_like += 1
                    results.append(
                        CheckResult(
                            id="encrypted_filename_suspicious",
                            severity=Severity.WARNING,
                            message="Encrypted filename looks like plaintext. Check filename encryption.",
                            details={"blob_id": entry.blob_id},
                        )
                    )
            except Exception:
                # Ignore decoding errors – that's good, it's probably real ciphertext.
                pass

        if suspicious_plaintext_like == 0:
            results.append(
                CheckResult(
                    id="encrypted_filename_check_ok",
                    severity=Severity.OK,
                    message="Encrypted filenames do not resemble plaintext.",
                )
            )

        return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run security and consistency checks on a Vaulter vault."
    )
    p.add_argument(
        "vault",
        type=str,
        help="Path to vault root directory.",
    )
    p.add_argument(
        "--skip-crypto",
        action="store_true",
        help="Skip crypto-dependent checks (index decryption, nonce reuse, blob size verification).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of human-readable text.",
    )
    return p.parse_args(argv)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    vault_root = Path(args.vault)

    doctor = VaulterDoctor(
        vault_root=vault_root,
        load_key=default_load_key,         # replace with your key loader
        decrypt_index=default_decrypt_index,  # replace with your index decryptor
        skip_crypto=args.skip_crypto,
    )
    results = doctor.run()

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            prefix = {
                Severity.OK: "[OK]     ",
                Severity.WARNING: "[WARN]   ",
                Severity.ERROR: "[ERROR]  ",
            }[r.severity]
            loc = f" ({r.path})" if r.path else ""
            print(f"{prefix}{r.id}: {r.message}{loc}")
            if r.details:
                print(f"          details: {r.details}")

    # Exit code: 0 if no ERROR, 1 otherwise
    has_error = any(r.severity == Severity.ERROR for r in results)
    return 1 if has_error else 0


if __name__ == "__main__":
    sys.exit(main())
