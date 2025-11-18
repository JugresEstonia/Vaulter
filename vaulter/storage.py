import os, json, base64, pathlib, time, stat, re, tempfile
from .models import VaultConfig, IndexFile, IndexRecord, RecoveryConfig
from .crypto import (
    kdf_argon2id,
    gen_key,
    gen_nonce,
    aead_encrypt,
    aead_decrypt,
    NONCE_SIZE,
    zero_bytes,
)
from .logging import get_logger

LOG = get_logger(False)

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("ascii"))

MAX_BLOB_SIZE = 1 << 35  # 32 GiB limit for blobs/index payloads
NOFOLLOW_FLAG = getattr(os, "O_NOFOLLOW", 0)
MASTER_WRAP_CONTEXT = b"master-wrap"
RECOVERY_WRAP_CONTEXT = b"recovery-master"

def _require_min_length(buf: bytes, expected: int, what: str):
    if len(buf) < expected:
        raise ValueError(f"{what} is too short ({len(buf)} < {expected})")

def _safe_add(a: int, b: int, limit: int = MAX_BLOB_SIZE) -> int:
    """Safe addition helper for size arithmetic (prevents overflow in bounded space)."""
    if a < 0 or b < 0:
        raise ValueError("size values must be non-negative")
    if a > limit or b > limit or a + b > limit:
        raise OverflowError("size computation overflow")
    return a + b

def _check_size(value: int, label: str):
    if value < 0:
        raise ValueError(f"{label} cannot be negative")
    if value > MAX_BLOB_SIZE:
        raise OverflowError(f"{label} exceeds supported limit ({value} > {MAX_BLOB_SIZE})")

def ensure_not_symlink(path: pathlib.Path, label: str):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise RuntimeError(f"{label} {path} is a symlink, which is not allowed")

def ensure_regular_file(path: pathlib.Path, label: str, allow_missing: bool = False):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return
        raise
    if not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"{label} {path} is not a regular file")
    if st.st_nlink > 1:
        raise RuntimeError(f"{label} {path} has unexpected hard links")

def safe_read_bytes(path: pathlib.Path) -> bytes:
    """
    Atomically open and read a file while holding the descriptor, preventing TOCTOU.
    """
    ensure_regular_file(path, str(path))
    flags = os.O_RDONLY
    if NOFOLLOW_FLAG:
        flags |= NOFOLLOW_FLAG
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as f:
        data = f.read()
    return data

def write_secure_file(path, data: bytes):
    """Write file with mode 0600 (owner read/write only)."""
    path = pathlib.Path(path)
    ensure_not_symlink(path.parent, "Parent directory")
    ensure_not_symlink(path, "Target file")
    fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
    ensure_regular_file(path, "Target file")

def check_vault_permissions(path: pathlib.Path):
    if os.name != "posix":
        return  # only enforce on Linux/Unix
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            raise PermissionError(f"Vault directory {path} cannot be a symlink")
        # Group or Others have any permission? -> too open
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError(
            f"Vault directory {path} is too open. "
            f"Fix with: chmod 700 {path}"
        )
    except FileNotFoundError:
    # Directory not there yet -> will be created
        pass

def _enc_name(master_key: bytes, name: str) -> str:
    name_nonce = gen_nonce()                     # 24 bytes for XChaCha20-Poly1305
    ct = aead_encrypt(master_key, name_nonce, name.encode(), b"fname")
    return b64e(name_nonce + ct)

def _dec_name(master_key: bytes, enc_name_b64: str) -> str:
    raw = b64d(enc_name_b64)
    _check_size(len(raw), "encoded name length")
    _require_min_length(raw, NONCE_SIZE + 16, "encrypted filename")
    nonce, ct = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
    return aead_decrypt(master_key, nonce, ct, b"fname").decode()

NAME_PATTERN = re.compile(r"^[A-Za-z0-9._ -]{1,255}$")

def _validate_name(name: str) -> str:
    if not isinstance(name, str):
        raise TypeError("name must be a string")
    if not name:
        raise ValueError("name must be 1-255 characters long")
    try:
        name_bytes = name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("name must be valid UTF-8") from exc
    if len(name_bytes) > 255:
        raise ValueError("name must be <=255 bytes once encoded")
    if name.startswith("/") or ".." in pathlib.Path(name).parts:
        raise ValueError("invalid name: contains forbidden path components")
    if not NAME_PATTERN.fullmatch(name):
        raise ValueError("invalid name: use letters, numbers, space, dot, underscore, dash only")
    return name

def canonicalize_path(path: pathlib.Path) -> pathlib.Path:
    """
    Return an absolute, symlink-resolved version of the provided path.
    Ensures vault operations always operate on canonical paths.
    """
    p = pathlib.Path(path).expanduser()
    return p.resolve(strict=False)

class Vault:
    def __init__(self, root: pathlib.Path):
        self.root = canonicalize_path(root)
        ensure_not_symlink(self.root, "Vault root")
        check_vault_permissions(self.root)   # <--- new
        self.config_path = self.root / "config.json"
        self.index_path = self.root / "index.bin"
        self.blobs_dir = self.root / "blobs"
        self._mkroot()

    def _store_cfg(self, cfg: VaultConfig):
        write_secure_file(self.config_path, cfg.model_dump_json(indent=2).encode())

    def _mkroot(self):
        self.root.mkdir(parents=True, exist_ok=True)
        ensure_not_symlink(self.root, "Vault root")
        if os.name == "posix":
            os.chmod(self.root, 0o700)

        self.blobs_dir.mkdir(parents=True, exist_ok=True)
        ensure_not_symlink(self.blobs_dir, "blobs directory")
        if os.name == "posix":
            os.chmod(self.blobs_dir, 0o700)

    def init(self, password: bytes, enable_recovery: bool = False):
        assert not self.config_path.exists(), "Vault already exists"
        salt = os.urandom(16)
        ad = os.urandom(16)
        master = gen_key()
        wrap_nonce = gen_nonce()
        pwd_key = kdf_argon2id(password, salt)
        wrapped_master = aead_encrypt(pwd_key, wrap_nonce, master, MASTER_WRAP_CONTEXT)
        recovery_cfg = None
        recovery_key = None
        if enable_recovery:
            recovery_key = gen_key()
            rec_nonce = gen_nonce()
            rec_wrap = aead_encrypt(recovery_key, rec_nonce, master, RECOVERY_WRAP_CONTEXT)
            recovery_cfg = RecoveryConfig(
                nonce_b64=b64e(rec_nonce),
                wrapped_master_b64=b64e(rec_wrap),
            )

        cfg = VaultConfig(
            kdf_salt_b64=b64e(salt),
            argon2={"t":3,"m":256*1024,"p":2},
            index_ad_b64=b64e(ad),
            master_wrap_nonce_b64=b64e(wrap_nonce),
            wrapped_master_b64=b64e(wrapped_master),
            recovery=recovery_cfg,
        )

        self._store_cfg(cfg)

        # empty encrypted index with 0600 perms
        idx = IndexFile().model_dump_json().encode()
        nonce = gen_nonce()
        ct = aead_encrypt(master, nonce, idx, ad)
        write_secure_file(self.index_path, nonce + ct)
        zero_bytes(bytearray(pwd_key))
        zero_bytes(bytearray(master))
        return recovery_key

    def _load_cfg(self) -> VaultConfig:
        ensure_regular_file(self.config_path, "config.json")
        raw = safe_read_bytes(self.config_path)
        return VaultConfig.model_validate_json(raw.decode())

    def _load_master_key(self, password: bytes) -> bytes:
        cfg = self._load_cfg()
        derived = kdf_argon2id(password, b64d(cfg.kdf_salt_b64))
        if cfg.wrapped_master_b64 and cfg.master_wrap_nonce_b64:
            master = aead_decrypt(
                derived,
                b64d(cfg.master_wrap_nonce_b64),
                b64d(cfg.wrapped_master_b64),
                MASTER_WRAP_CONTEXT,
            )
            zero_bytes(bytearray(derived))
            return master
        return derived

    def _load_master_key_from_recovery(self, recovery_key: bytes) -> bytes:
        cfg = self._load_cfg()
        if cfg.recovery is None:
            raise RuntimeError("Recovery key not configured for this vault")
        return aead_decrypt(
            recovery_key,
            b64d(cfg.recovery.nonce_b64),
            b64d(cfg.recovery.wrapped_master_b64),
            RECOVERY_WRAP_CONTEXT,
        )

    def _load_index(self, master_key: bytes) -> IndexFile:
        cfg = self._load_cfg()
        ensure_regular_file(self.index_path, "index.bin")
        raw = safe_read_bytes(self.index_path)
        _check_size(len(raw), "index blob length")
        _require_min_length(raw, NONCE_SIZE + 16, "index blob")
        nonce, ct = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
        pt = aead_decrypt(master_key, nonce, ct, b64d(cfg.index_ad_b64))
        _check_size(len(pt), "decrypted index length")
        return IndexFile.model_validate_json(pt.decode())

    def _store_index(self, master_key: bytes, idx: IndexFile):
        cfg = self._load_cfg()
        nonce = gen_nonce()
        pt = idx.model_dump_json().encode()
        ct = aead_encrypt(master_key, nonce, pt, b64d(cfg.index_ad_b64))

        # enforce 0600 permissions
        write_secure_file(self.index_path, nonce + ct)


    def add_file(self, password: bytes, src_path: pathlib.Path, alias: str | None = None):
        master = self._load_master_key(password)
        idx = self._load_index(master)
        src = src_path.resolve(strict=True)
        # sanitize: forbid absolute/.. in alias
        name = _validate_name(alias) if alias is not None else _validate_name(src.name)
        dek = gen_key()
        nonce = gen_nonce()
        ad = os.urandom(16)
        data = src.read_bytes()
        _check_size(len(data), "source file size")
        ct = aead_encrypt(dek, nonce, data, ad)
        blob_id = os.urandom(16).hex()
        shard = self.blobs_dir / blob_id[:2] / blob_id[2:4]
        ensure_not_symlink(self.blobs_dir, "blobs directory")
        ensure_not_symlink(shard.parent, "blob shard parent")
        ensure_not_symlink(shard, "blob shard directory")
        shard.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            # enforce 0700 on the whole shard path (e.g. blobs/aa and blobs/aa/bb)
            for parent in [self.blobs_dir, shard.parent, shard]:
                if parent.exists():
                    os.chmod(parent, 0o700)
        payload_len = _safe_add(len(nonce), len(ad))
        payload_len = _safe_add(payload_len, len(ct))
        _require_min_length(ct, 16, "ciphertext payload")
        _check_size(payload_len, "blob payload length")
        write_secure_file(shard / blob_id, nonce + ad + ct)
        # wrap DEK with master key (simple: AEAD with zero nonce on wrapper, better is dedicated key wrap)
        wrap_nonce = gen_nonce()
        wrapped_dek = aead_encrypt(master, wrap_nonce, dek, b"dek-wrap")
        enc_name = _enc_name(master, name)

        rec = IndexRecord(
            id=blob_id,
            enc_name_b64=enc_name,
            size=len(data),
            created=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            nonce_b64=b64e(wrap_nonce),
            ad_b64=b64e(ad),
            wrapped_dek_b64=b64e(wrapped_dek),
        )
        idx.records.append(rec)
        self._store_index(master, idx)
        # best-effort wipe
        zero_bytes(password)
        zero_bytes(bytearray(master))
        zero_bytes(bytearray(dek))
        del data, dek, master

    def get_file(self, password: bytes, name: str, out: pathlib.Path | None):
        name = _validate_name(name)
        master = self._load_master_key(password)
        idx = self._load_index(master)
        rec = None
        for r in idx.records:
            if _dec_name(master, r.enc_name_b64) == name:
                rec = r
                break
        if rec is None:
            raise FileNotFoundError("not found")
        if rec.size < 0 or rec.size > MAX_BLOB_SIZE:
            raise ValueError("record size out of bounds")
        blob = self.blobs_dir / rec.id[:2] / rec.id[2:4] / rec.id
        ensure_regular_file(blob, "blob file")
        raw = safe_read_bytes(blob)
        _check_size(len(raw), "blob record length")
        min_len = NONCE_SIZE + 16 + 16  # nonce + AD + tag
        _require_min_length(raw, min_len, "blob record")
        nonce_blob = raw[:NONCE_SIZE]
        ad = raw[NONCE_SIZE:NONCE_SIZE + 16]
        ct = raw[NONCE_SIZE + 16:]
        _require_min_length(ct, 16, "ciphertext payload")
        if len(ct) < rec.size:
            raise ValueError("ciphertext shorter than recorded size")
        dek = aead_decrypt(master, b64d(rec.nonce_b64), b64d(rec.wrapped_dek_b64), b"dek-wrap")
        pt = aead_decrypt(dek, nonce_blob, ct, ad)
        zero_bytes(bytearray(master))
        zero_bytes(bytearray(dek))
        zero_bytes(password)
        if out is None or str(out) == "-":
            return pt
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "wb", buffering=0) as f:
            f.write(pt)
            f.flush()
            os.fsync(f.fileno())

    def remove(self, password: bytes, name: str, erase_blob: bool = False):
        name = _validate_name(name)
        master = self._load_master_key(password)
        idx = self._load_index(master)
        keep = []
        removed = None
        for r in idx.records:
            if _dec_name(master, r.enc_name_b64) == name:
                removed = r
            else:
                keep.append(r)
        if not removed:
            raise FileNotFoundError("not found")
        idx.records = keep
        self._store_index(master, idx)
        if erase_blob:
            p = self.blobs_dir / removed.id[:2] / removed.id[2:4] / removed.id
            try:
                ensure_regular_file(p, "blob file", allow_missing=True)
                os.remove(p)
            except FileNotFoundError: pass
        zero_bytes(password)
        zero_bytes(bytearray(master))

    def reset_password_with_recovery(self, recovery_key: bytes, new_password: bytes):
        cfg = self._load_cfg()
        master = self._load_master_key_from_recovery(recovery_key)
        new_salt = os.urandom(16)
        wrap_nonce = gen_nonce()
        pwd_key = kdf_argon2id(new_password, new_salt)
        wrapped_master = aead_encrypt(pwd_key, wrap_nonce, master, MASTER_WRAP_CONTEXT)
        cfg.kdf_salt_b64 = b64e(new_salt)
        cfg.master_wrap_nonce_b64 = b64e(wrap_nonce)
        cfg.wrapped_master_b64 = b64e(wrapped_master)
        self._store_cfg(cfg)
        zero_bytes(bytearray(master))
        zero_bytes(bytearray(pwd_key))
        zero_bytes(bytearray(recovery_key))
        zero_bytes(bytearray(new_password))
