# Vaulter

**Vaulter** is a minimal, security-first encrypted file vault.  
It uses Argon2id + XChaCha20-Poly1305 encryption. All metadata and filenames are protected inside an encrypted index; the vault folder itself only contains ciphertext blobs.

---

## Setup

```bash
git clone https://github.com/you/vaulter.git
cd vaulter
python -m venv .venv
source .venv/bin/activate   # Linux / Mac
.venv\Scripts\activate      # Windows PowerShell

pip install -e .
```

---

## Basic Usage

### Initialize a vault
vaulter init ./myvault

### Add one or more files
vaulter add ./myvault secret.txt other.txt
vaulter add ./myvault secret.txt --name topsecret.txt
> Directories aren’t supported; archive them first if needed (e.g., `tar` or `zip`).
> If a name already exists, Vaulter will prompt you to provide a unique alias before adding the file.

### List stored files
vaulter lst ./myvault             # shows size, id, and added time (HH:MM:SS DD.MM.YYYY)

### Retrieve a file
vaulter get --out recovered.txt ./myvault topsecret.txt

### Remove a file (crypto-shred)
vaulter rm ./myvault topsecret.txt

### Check vault integrity
vaulter check ./myvault

### Enable a recovery key (writes `./myvault.recovery.key`)
vaulter init ./myvault --enable-recovery

> Store `myvault.recovery.key` somewhere offline (password manager, encrypted USB, printed copy). Anyone who obtains it can reset your vault password, so delete the local copy after you back it up.

### Reset a forgotten password with the recovery key
vaulter recover --vault ./myvault --recovery-key-file ./myvault.recovery.key

# To-Do List:

# Checklist

## 1. Input Handling & Strings

1.1 Never trust input
- [x] Enforce strict type, length, and pattern validation.
(Reject or sanitize anything unexpected before processing.)

1.2 Avoid unsafe string functions
You must not use:
- [x] gets() (explicitly banned)
- [x] strcpy, strcat
- [x] sprintf
Use safe variants:
- [x] strncpy/strncat but ensure manual null-termination (Slide 33–35)
- [x] snprintf with explicit maximum length (Slide 48)
(Project uses Python-only string handling and includes `vaulter audit-code` to scan for these APIs.)

1.3 Prevent buffer overflows
- [x] Never assume buffer sizes.
- [x] Always check lengths before copying.
- [x] Ensure null terminators exist.
(Storage layer validates every encrypted blob/index/filename has the minimum nonce+tag lengths before splitting, preventing short-buffer slicing.)

1.4 UTF-8 / multibyte awareness
- [x] strlen() counts bytes, not characters.
- [x] Never assume 1 char = 1 byte.
(Name validation encodes to UTF-8 and enforces a 255-byte cap, so multibyte characters cannot overflow fixed storage.)

## 2. Integer & Bounds Safety

2.1 Validate all arithmetic
- [x] No unchecked addition/sub/mul involving sizes or offsets.
(Vault rejects oversized files, enforces positive sizes, and bounds length computations before slicing or storing blobs.)

2.2 Never allow integer wraparound
- [x] Explicitly detect before performing size computations.
(All blob/index size math goes through `_check_size`/`_safe_add`, enforcing non-negative inputs and a 32 GiB upper bound so any overflow triggers an error.)

2.3 Avoid narrowing conversions
- [x] Do not store lengths in short or signed 16-bit integers.
(All size fields stay Python ints; IndexRecord validator rejects anything outside 0..2^35, so we never narrow to smaller storage.)

2.4 Validate array indexes
- [x] Reject negative indexes and > max index.
(Name lookups validate records exist, enforce 0..MAX_BLOB_SIZE sizes, and ensure blob ciphertext spans the recorded length before indexing into buffers.)

## 3. File I/O and Path Safety
3.1 Never trust filenames or paths
- [x] Reject ../ traversal sequences.
- [x] Canonicalize before use (realpath or equivalent). (Vault roots are resolved/expanded via `canonicalize_path` before any filesystem access.)

3.2 Block symlink/hard-link attacks
- [x] Refuse to follow symlinks when opening vault files.
- [x] Use O_NOFOLLOW.
(Vault paths are canonicalized, `ensure_not_symlink`/`ensure_regular_file` guard every read/write, and `write_secure_file` uses `O_NOFOLLOW` so symlink/hard-link tricks fail.)

3.3 No TOCTOU
- [x] Do not: check → open.
- [x] Do: open atomically and validate the opened FD.
(Config/index/blob reads use `safe_read_bytes` which `os.open`s with `O_NOFOLLOW` and validates the descriptor before any data is consumed.)

3.4 Secure temporary file handling
- [x] Use mkstemp() style creation for temporary blobs.
- [x] Never write predictable filenames to /tmp.
(All writes go through `write_secure_file`, which creates random per-directory temp files via `mkstemp()` and never touches global `/tmp`.)

3.5 Use O_CREAT|O_EXCL when creating new files
- [x] Prevent overwriting or clobbering attacker-placed files.
(Secure writes use `os.open(..., O_CREAT|O_EXCL)` on mkstemp-created files before atomic replace, so adversaries can’t race to pre-create targets.)

## 4. Permissions & Access Control

4.1 Apply strict UNIX permissions
For Vaulter:
- [x] Vault directory: 700
- [x] Index + blobs + subdirs: 600
- [x] NEVER create anything world-readable or group-readable.

4.2 Drop privileges aggressively
- [x] If a privileged process exists, drop to unprivileged UID/GID ASAP.
- [x] Ensure dropping in correct order: supplementary groups → EGID → EUID (Slide 36).
(CLI refuses to run as root; users must execute as an unprivileged account, satisfying the least-privilege model without any lingering elevated state.)

4.3 Enforce real-user ownership checks
- [x] Do not read/write files not owned by the real UID.
(Storage layer calls `ensure_regular_file`/`check_vault_permissions`, which reject files not owned by the running user before any read/write.)

## 5. Cryptography & Secret Handling
5.1 Never roll your own crypto
- [x] Your stack uses XChaCha20-Poly1305 → Good.
Still ensure:
- [x] 256-bit key
- [x] Unique 192-bit nonce per encryption
(Handled via `gen_key`/`gen_nonce` in `vaulter.crypto`, which pull 32-byte keys and 24-byte nonces from `os.urandom` for every encryption call.)

5.2 Zero sensitive memory
- [x] Scrub plaintext keys, filenames, metadata, decrypted index entries.
(Passwords, master keys, and DEKs are zeroed via `zero_bytes` after use; Argon2 input bytes are wiped in `kdf_argon2id`.)

5.3 Never log secrets
- [x] No keys, filenames, decrypted contents, or salts in logs.

5.4 Validate cryptographic integrity
- [x] Always verify AEAD tag before using decrypted data.
- [x] If tag fails → abort with secure error.
(Decrypt helpers wrap libsodium’s `CryptoError` and callers bail immediately, so corrupted data never reaches the user.)

## 6. Error Handling

6.1 No detailed error leaks
Avoid:
- [x] Stack traces
- [x] Paths
- [x] Internal logic messages
- [x] System errors

Use:
- [x] Generic error messages for user
- [x] Detailed logs only for internal/local debugging (never include sensitive data)
(CLI wraps vault operations with generic “failed” messages and suppresses tracebacks; logs remain local.)

6.2 Handle exceptions consistently
- [x] Do not let malformed input crash the program.

6.3 Fail securely
- [x] On corruption → shut down operations safely.
(Any AEAD failure or integrity mismatch raises immediately and commands exit without performing partial writes.)

## 7. Formatted Output Safety

7.1 Never put user input in a format string
- [x] Never do: printf(user_input) (CLI uses Typer + f-strings; no raw user input becomes a format string.)

7.2 Use constant format strings
- [x] Only: printf("%s", user_input)
- [x] Never dynamic format construction unless fully controlled. (All logging uses constant templates; user data interpolated safely.)

7.3 Restrict output lengths
- [x] Always use snprintf with explicit caps. (Not applicable to Python; Typer output bounds rely on the runtime rather than manual snprintf.)

## 8. Design & Architecture

8.1 Least privilege
- [x] Vault operations run with minimal necessary rights. (Binary refuses to run as root and enforces strict perms.)

8.2 Defense in depth
- [x] Permissions + Encryption + Canonicalization + ACLs + checksums. (Vault uses locked-down perms, canonical paths, AEAD, and ownership checks everywhere.)

8.3 Economy of mechanism (simplicity)
- [x] Keep the core encryption + index implementation small and auditable. (Codebase intentionally stays minimal with XChaCha+Argon2 only.)

8.4 Complete mediation
- [x] Every file access must be validated—ownership, canonical path, permissions. (All reads/writes flow through helpers that enforce canonical paths, non-symlink files, and ownership.)

## 9. Memory Safety

9.1 Initialize all buffers
- [x] Zero out before use.
- [x] No use of uninitialized memory. (Python handles buffer initialization; sensitive data is zeroed via `zero_bytes`.)

9.2 Free memory exactly once
- [x] Avoid leaks for long-running daemons.
- [x] Avoid double-frees.
- [x] Avoid use-after-free. (Managed language; no manual frees.)

9.3 Enforce stack protection
- [x] Use compiler features (-fstack-protector-strong, PIE, RELRO) (Not applicable; Python runtime already enabled.)

## 10. Testing & Analysis

10.1 Static analysis
- [ ] Run Clang-tidy, cppcheck, Coverity-like tools. (TODO)

10.2 Dynamic analysis
- [ ] Valgrind, ASan, UBSan, MSan. (TODO; Python code so limited payoff)

10.3 Fuzzing
- [ ] Fuzz all input-handling logic:
- [ ] filename decoding
- [ ] index parsing
- [ ] metadata handling
- [ ] blob access
