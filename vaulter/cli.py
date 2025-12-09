import typer, getpass, pathlib, sys, os, stat, base64
from datetime import datetime
from .storage import Vault, _dec_name, write_secure_file
from .crypto import NONCE_SIZE, zero_bytes
from .logging import get_logger

app = typer.Typer(no_args_is_help=True)
LOG = get_logger(False)

def _log_error(event: str, message: str, **details):
    LOG.error(event, message=message, **details)

def ask_pw(prompt="Master password: ") -> bytes:
    """Prompt the user for a password using getpass and return UTF-8 bytes."""
    pw = getpass.getpass(prompt)
    return pw.encode("utf-8")

def _format_timestamp(ts: str) -> str:
    """Display ISO timestamps from the index in HH:MM:SS DD.MM.YYYY format."""
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        return dt.strftime("%H:%M:%S %d.%m.%Y")
    except ValueError:
        return ts

def _load_master_or_exit(vault_obj: Vault, password: bytes) -> bytes:
    """Attempt to load the master key, logging and exiting on authentication failure."""
    try:
        return vault_obj._load_master_key(password)
    except ValueError:
        _log_error("auth_failed", message="Incorrect master password", vault=str(vault_obj.root))
        typer.echo("✖ Incorrect master password.")
        raise typer.Exit(1)

def ask_new_password() -> bytes:
    """Prompt the user twice for a new master password and ensure the entries match."""
    first = ask_pw("New master password: ")
    second = ask_pw("Confirm new master password: ")
    if first != second:
        typer.echo("✖ Passwords did not match. Aborting.")
        raise typer.Exit(1)
    return first

def _load_recovery_key(value: str | None, path: str | None) -> bytes:
    """Accept either a literal key string or file path and return the decoded bytes."""
    if (value is None and path is None) or (value is not None and path is not None):
        raise typer.BadParameter("Provide exactly one of --recovery-key or --recovery-key-file")
    data: str
    if path is not None:
        data = pathlib.Path(path).read_text().strip()
    else:
        data = value.strip()
    try:
        return base64.b64decode(data.encode("ascii"))
    except Exception as exc:
        raise typer.BadParameter("Recovery key must be base64 encoded") from exc

def _default_recovery_path(vault_path: pathlib.Path) -> pathlib.Path:
    """Derive the default `<vault>.recovery.key` path for new vaults."""
    resolved = pathlib.Path(vault_path).expanduser().resolve()
    return resolved.parent / f"{resolved.name}.recovery.key"

@app.command()
def init(
    vault: str = typer.Option(..., "--vault", dir_okay=True, file_okay=False, readable=True, writable=True),
    enable_recovery: bool = typer.Option(False, "--enable-recovery", help="Generate a one-time recovery key file"),
):
    """Initialize a new vault directory, master key, and optional recovery key."""
    vault_path = pathlib.Path(vault)
    v = Vault(vault_path)
    pw = ask_pw("Set master password: ")
    try:
        recovery_key = v.init(pw, enable_recovery=enable_recovery)
    except Exception as exc:
        LOG.exception("vault_init_failed", vault=str(vault_path), error=str(exc))
        typer.echo("✖ Failed to initialize vault (see logs for details)", err=True)
        raise typer.Exit(1)
    typer.echo("Vault initialized.")
    if recovery_key:
        rec_b64 = base64.b64encode(recovery_key).decode("ascii")
        recovery_path = _default_recovery_path(vault_path)
        payload = (rec_b64 + "\n").encode("ascii")
        try:
            recovery_path.parent.mkdir(parents=True, exist_ok=True)
            write_secure_file(recovery_path, payload)
        except Exception as exc:
            LOG.exception("recovery_key_write_failed", vault=str(vault_path), file=str(recovery_path), error=str(exc))
            typer.echo(f"✖ Recovery key generated but could not be written to {recovery_path}: {exc}", err=True)
            raise typer.Exit(1)
        finally:
            zero_bytes(bytearray(recovery_key))
        typer.echo(
            f"Recovery key stored at {recovery_path}.\nMove it offline (password manager, encrypted USB, paper) and delete the local copy after backup—anyone with this file can reset your vault."
        )

@app.command()
def add(
    vault: str,
    paths: list[str] = typer.Argument(..., metavar="PATH", help="One or more files to add"),
    name: str = typer.Option(None, "--name", help="Optional alias (only valid for single file)"),
):
    """Encrypt and store one or more files in the vault, ensuring unique names."""
    if len(paths) > 1 and name is not None:
        _log_error("add_invalid_usage", message="--name used with multiple files", vault=vault)
        typer.echo("✖ --name can only be used when adding a single file")
        raise typer.Exit(1)
    v = Vault(pathlib.Path(vault))
    pw = ask_pw()
    master = _load_master_or_exit(v, pw)
    try:
        idx = v._load_index(master)
    except Exception as exc:
        _log_error("load_index_failed", message="Failed to load vault index", vault=vault, error=str(exc))
        typer.echo(f"✖ Failed to load vault index: {exc}")
        raise typer.Exit(1)
    existing_names = set()
    for r in idx.records:
        try:
            existing_names.add(_dec_name(master, r.enc_name_b64))
        except Exception:
            continue
    zero_bytes(bytearray(master))
    errors = 0
    pending_names = set()
    for raw_path in paths:
        p = pathlib.Path(raw_path)
        if p.is_dir():
            _log_error("add_directory_not_supported", message="Attempted to add directory", vault=vault, path=str(p))
            typer.echo(f"✖ {p} is a directory; directories are not supported")
            errors += 1
            continue
        alias = name if name is not None and len(paths) == 1 else None
        try:
            default_name = p.resolve(strict=True).name
        except FileNotFoundError:
            _log_error("add_missing_file", message="File does not exist", vault=vault, path=str(p))
            typer.echo(f"✖ Add failed for {p}: file does not exist")
            errors += 1
            continue
        effective_name = alias if alias is not None else default_name
        while effective_name in existing_names or effective_name in pending_names:
            typer.echo(f"⚠ Name '{effective_name}' already exists in this vault.")
            new_alias = typer.prompt(
                "Enter a different name (leave blank to skip this file)",
                default="",
                show_default=False,
            ).strip()
            if not new_alias:
                typer.echo(f"↷ Skipped {p}")
                effective_name = None
                break
            alias = new_alias
            effective_name = alias
        if effective_name is None:
            continue
        try:
            v.add_file(pw, p, alias)
            typer.echo(f"✔ Added {p}")
            existing_names.add(effective_name)
            pending_names.add(effective_name)
        except (FileNotFoundError, ValueError) as exc:
            _log_error("add_failed", message="Add failed", vault=vault, path=str(p), error=str(exc))
            typer.echo(f"✖ Add failed for {p}: {exc}")
            errors += 1
        except Exception as exc:
            _log_error("add_unexpected_error", message="Unexpected error while adding file", vault=vault, path=str(p), error=str(exc))
            typer.echo(f"✖ Unexpected error while adding {p}")
            errors += 1
    if errors:
        raise typer.Exit(1)

@app.command("lst")
def lst_cmd(vault: str, raw: bool = typer.Option(False, "--raw", help="Show raw encrypted filename alongside decrypted name")):
    """List vault entries with sizes and IDs, optionally including raw metadata."""
    from .storage import IndexFile, _dec_name, Vault
    import pathlib, typer
    v = Vault(pathlib.Path(vault))
    pw = ask_pw()
    master = _load_master_or_exit(v, pw)
    idx: IndexFile = v._load_index(master)

    for r in idx.records:
        try:
            name = _dec_name(master, r.enc_name_b64)
        except Exception:
            name = "<unreadable-name>"

        ts = _format_timestamp(r.created)
        if raw:
            typer.echo(f"{name}\t{r.size} bytes\tid={r.id}\tadded={ts}\t(enc_name_b64={r.enc_name_b64})")
        else:
            typer.echo(f"{name}\t{r.size} bytes\tid={r.id}\tadded={ts}")

def _expand_range(pattern: str) -> list[str] | None:
    """Deterministically expand brace ranges without regex backtracking risks."""
    try:
        lbrace = pattern.index("{")
        rbrace = pattern.index("}", lbrace + 1)
    except ValueError:
        return None
    inner = pattern[lbrace + 1 : rbrace]
    if ".." not in inner:
        return None
    start_txt, end_txt = inner.split("..", 1)
    if not (start_txt.isdigit() and end_txt.isdigit()):
        return None
    prefix, suffix = pattern[:lbrace], pattern[rbrace + 1 :]
    start_i, end_i = int(start_txt), int(end_txt)
    if start_i > end_i:
        start_i, end_i = end_i, start_i
    width = max(len(start_txt), len(end_txt))
    return [f"{prefix}{str(i).zfill(width)}{suffix}" for i in range(start_i, end_i + 1)]


def _prompt_for_outputs(count: int, template: str | None) -> list[str | None]:
    """Interactive helper that lets users confirm or skip each retrieval target."""
    outputs: list[str | None] = []
    for idx in range(1, count + 1):
        default = (template.format(n=idx) if template and "{n}" in template else template) or f"recovered{idx}.txt"
        val = typer.prompt(
            f"Output filename for file #{idx} (type 'skip' to omit)",
            default=default,
        ).strip()
        if not val:
            val = default
        if val.lower() == "skip":
            outputs.append(None)
        else:
            outputs.append(val)
    return outputs


@app.command()
def get(
    vault: str,
    names: list[str] = typer.Argument(..., metavar="NAME", help="One or more record names or brace ranges"),
    out: str = typer.Option("-", "--out", help="Destination path, '-' for stdout, or brace template"),
):
    """Retrieve one or more records, supporting brace-expansion and interactive targets."""
    v = Vault(pathlib.Path(vault))
    pw = ask_pw()

    expanded_names = _expand_name_patterns(names)
    if not expanded_names:
        typer.echo("✖ No files specified")
        raise typer.Exit(1)

    outputs = _resolve_outputs(out, expanded_names)

    errors = 0
    for idx, name in enumerate(expanded_names):
        target = outputs[idx]
        if target is None:
            typer.echo(f"↷ Skipped {name}")
            continue
        try:
            data = v.get_file(pw, name, None if target == "-" else pathlib.Path(target))
        except FileNotFoundError:
            _log_error("get_not_found", message="Requested file not found", vault=vault, name=name)
            typer.echo(f"✖ File not found in vault: {name}")
            errors += 1
            continue
        except Exception as exc:
            _log_error("get_failed", message="Failed to retrieve file", vault=vault, name=name, error=str(exc))
            typer.echo(f"✖ Failed to retrieve file: {name}")
            errors += 1
            continue

        if target == "-":
            sys.stdout.buffer.write(data)
        else:
            typer.echo(f"✔ Retrieved {name} -> {target}")

    if errors:
        raise typer.Exit(1)

@app.command()
def rm(
    vault: str,
    names: list[str] = typer.Argument(..., metavar="NAME", help="One or more record names to delete"),
    keep_blob: bool = typer.Option(False, "--keep-blob", help="Leave ciphertext blob on disk for forensic recovery"),
):
    """Delete one or more records. Blobs are shredded unless --keep-blob is provided."""
    v = Vault(pathlib.Path(vault))
    pw = ask_pw()
    if not keep_blob:
        typer.echo("⚠ WARNING: This will crypto-shred the encrypted blobs. Use --keep-blob if you need forensic recovery.")
        if not typer.confirm("Proceed with destructive removal?", default=False):
            typer.echo("↷ Aborted.")
            raise typer.Exit(0)
    errors = 0
    for name in names:
        try:
            v.remove(pw, name, erase_blob=not keep_blob)
            typer.echo(f"✔ Removed {name}")
        except FileNotFoundError:
            _log_error("rm_not_found", message="Attempted to remove missing record", vault=vault, name=name)
            typer.echo(f"✖ File not found: {name}")
            errors += 1
        except Exception as exc:
            _log_error("rm_failed", message="Failed to remove record", vault=vault, name=name, error=str(exc))
            typer.echo(f"✖ Failed to remove {name}")
            errors += 1
    if errors:
        raise typer.Exit(1)

@app.command("check")
def check(vault: str):
    """Audit vault permissions, integrity, and cryptographic metadata."""
    vpath = pathlib.Path(vault)
    if not vpath.exists():
        typer.echo(f"✖ Vault does not exist: {vpath}")
        raise typer.Exit(1)

    pw = ask_pw("Enter master password:")

    def mode_bits(p: pathlib.Path) -> int:
        return stat.S_IMODE(os.lstat(p).st_mode)

    def owned_by_me(p: pathlib.Path) -> bool:
        return os.lstat(p).st_uid == os.getuid()

    # Authenticate before running any checks to avoid partial pass output on wrong passwords.
    try:
        vobj = Vault(vpath)
        master = _load_master_or_exit(vobj, pw)
    except typer.Exit:
        raise
    except Exception as exc:
        _log_error("check_auth_failed", message="Failed to authenticate vault before checks", vault=vault, error=str(exc))
        typer.echo(f"✖ Failed to load vault: {exc}")
        raise typer.Exit(1)

    has_error = False

    # ----------------------------------------------------check------------------
    # 1. Vault root checks
    # ----------------------------------------------------------------------
    st = os.lstat(vpath)
    if stat.S_ISLNK(st.st_mode):
        typer.echo("✖ Vault root is a symlink (not allowed)")
        has_error = True

    if not stat.S_ISDIR(st.st_mode):
        typer.echo("✖ Vault root is not a directory")
        raise typer.Exit(1)

    root_mode = mode_bits(vpath)
    if root_mode != 0o700:
        typer.echo(f"✖ Vault root perms {oct(root_mode)} != 0o700")
        has_error = True
    else:
        typer.echo("✔ Vault root permissions 700")

    if not owned_by_me(vpath):
        typer.echo("✖ Vault root not owned by current user")
        has_error = True
    else:
        typer.echo("✔ Vault owned by current user")

    # ----------------------------------------------------------------------
    # 2. Core structure: config.json / index.bin / blobs/
    # ----------------------------------------------------------------------
    config_path = vpath / "config.json"
    index_path = vpath / "index.bin"
    blobs_dir = vpath / "blobs"

    # config.json
    if not config_path.exists():
        typer.echo("✖ config.json missing")
        has_error = True
    else:
        if mode_bits(config_path) != 0o600:
            typer.echo(f"✖ config.json perms != 600 ({oct(mode_bits(config_path))})")
            has_error = True
        else:
            typer.echo("✔ config.json present (600)")

    # index.bin
    if not index_path.exists():
        typer.echo("✖ index.bin missing")
        has_error = True
    else:
        st = os.lstat(index_path)
        if stat.S_ISLNK(st.st_mode):
            typer.echo("✖ index.bin is symlink")
            has_error = True
        if not stat.S_ISREG(st.st_mode):
            typer.echo("✖ index.bin not regular file")
            has_error = True

        if mode_bits(index_path) != 0o600:
            typer.echo(f"✖ index.bin perms != 600 ({oct(mode_bits(index_path))})")
            has_error = True
        else:
            typer.echo("✔ index.bin present (600)")

    # blobs/
    if not blobs_dir.exists():
        typer.echo("✖ blobs/ missing")
        has_error = True
    else:
        st = os.lstat(blobs_dir)
        if stat.S_ISLNK(st.st_mode):
            typer.echo("✖ blobs/ is symlink")
            has_error = True
        if not stat.S_ISDIR(st.st_mode):
            typer.echo("✖ blobs/ is not directory")
            has_error = True

        if mode_bits(blobs_dir) != 0o700:
            typer.echo(f"✖ blobs/ perms != 700 ({oct(mode_bits(blobs_dir))})")
            has_error = True
        else:
            typer.echo("✔ blobs/ directory (700)")

    # ----------------------------------------------------------------------
    # 3. Crypto/index load
    # ----------------------------------------------------------------------
    try:
        idx = vobj._load_index(master)
    except Exception as e:
        typer.echo(f"✖ Failed to decrypt index: {e}")
        raise typer.Exit(1)

    typer.echo("✔ index.bin decryptable")
    typer.echo(f"✔ {len(idx.records)} records loaded")

    # ----------------------------------------------------------------------
    # 4. Blob presence/orphans
    # ----------------------------------------------------------------------
    blob_ids = {rec.id for rec in idx.records}
    fs_blobs = {
        p.name for p in blobs_dir.rglob("*") if p.is_file()
    }

    missing = blob_ids - fs_blobs
    orphans = fs_blobs - blob_ids

    if missing:
        typer.echo(f"✖ Missing blobs: {', '.join(sorted(missing))}")
        has_error = True
    else:
        typer.echo("✔ All blobs present")

    if orphans:
        typer.echo(f"WARNING: {len(orphans)} orphaned blobs (exist but not in index)")
    else:
        typer.echo("✔ No orphaned blobs")

    # ----------------------------------------------------------------------
    # 5. Blob file / directory permissions
    # ----------------------------------------------------------------------
    for root, dirs, files in os.walk(blobs_dir, topdown=True):
        rpath = pathlib.Path(root)

        for d in dirs:
            dpath = rpath / d
            st = os.lstat(dpath)

            if stat.S_ISLNK(st.st_mode):
                typer.echo(f"✖ Blob subdir symlink: {dpath}")
                has_error = True
                continue

            if mode_bits(dpath) != 0o700:
                typer.echo(f"✖ Blob subdir {dpath} perms != 700")
                has_error = True

            if not owned_by_me(dpath):
                typer.echo(f"✖ Blob subdir not owned by user: {dpath}")
                has_error = True

        for f in files:
            fpath = rpath / f
            st = os.lstat(fpath)

            if stat.S_ISLNK(st.st_mode):
                typer.echo(f"✖ Blob file symlink: {fpath}")
                has_error = True
                continue

            if not stat.S_ISREG(st.st_mode):
                typer.echo(f"✖ Blob not regular file: {fpath}")
                has_error = True
                continue

            if mode_bits(fpath) != 0o600:
                typer.echo(f"✖ Blob file {fpath} perms != 600")
                has_error = True

            if not owned_by_me(fpath):
                typer.echo(f"✖ Blob file not owned by user: {fpath}")
                has_error = True

    # ----------------------------------------------------------------------
    # 6. Nonce checks (XChaCha20 nonce must be 24 bytes)
    # ----------------------------------------------------------------------
    seen_nonces = set()
    nonce_reuse = False

    for rec in idx.records:
        try:
            nonce = base64.b64decode(rec.nonce_b64)
        except Exception:
            typer.echo(f"✖ Invalid base64 nonce in record {rec.id}")
            has_error = True
            continue

        if len(nonce) != NONCE_SIZE:
            typer.echo(f"✖ Nonce for {rec.id} length={len(nonce)} != {NONCE_SIZE}")
            has_error = True

        if nonce in seen_nonces:
            typer.echo(f"✖ Nonce reuse detected for {rec.id}")
            nonce_reuse = True
            has_error = True
        else:
            seen_nonces.add(nonce)

    if not nonce_reuse:
        typer.echo("✔ No nonce reuse detected")

    # ----------------------------------------------------------------------
    # 7. Blob size mismatch (index vs filesystem)
    # ----------------------------------------------------------------------
    size_mismatch = False
    for rec in idx.records:
        blob_path = blobs_dir / rec.id

        if blob_path.exists():
            fs_size = blob_path.stat().st_size
            if fs_size != rec.size:
                typer.echo(f"✖ Size mismatch for {rec.id}: index={rec.size}, fs={fs_size}")
                size_mismatch = True
                has_error = True

    if not size_mismatch:
        typer.echo("✔ No size mismatches")

    # ----------------------------------------------------------------------
    # 8. Encrypted filename sanity check
    # ----------------------------------------------------------------------
    bad_names = False
    for rec in idx.records:
        try:
            _dec_name(master, rec.enc_name_b64)
        except Exception as exc:
            typer.echo(f"✖ Encrypted filename for {rec.id} failed to decrypt: {exc}")
            has_error = True
            bad_names = True

    if not bad_names:
        typer.echo("✔ Encrypted filenames decrypt correctly")

    # ----------------------------------------------------------------------
    # Final result
    # ----------------------------------------------------------------------
    if has_error:
        raise typer.Exit(1)
    else:
        typer.echo("✔ Vault passed all checks")
        raise typer.Exit(0)


@app.command("recover")
def recover(
    vault: str = typer.Option(..., "--vault", dir_okay=True, file_okay=False, readable=True, writable=True),
    recovery_key: str = typer.Option(None, "--recovery-key", help="Base64 recovery key string"),
    recovery_key_file: str = typer.Option(None, "--recovery-key-file", help="Path to file containing the base64 recovery key"),
):
    """Reset the vault password using a stored recovery key."""
    vault_path = pathlib.Path(vault)
    v = Vault(vault_path)
    try:
        key = _load_recovery_key(recovery_key, recovery_key_file)
    except typer.BadParameter as exc:
        typer.echo(f"✖ {exc}")
        raise typer.Exit(1)
    new_pw = ask_new_password()
    try:
        v.reset_password_with_recovery(key, new_pw)
    except RuntimeError as exc:
        LOG.exception("recovery_reset_failed", vault=str(vault_path), error=str(exc))
        typer.echo(f"✖ {exc}")
        raise typer.Exit(1)
    except Exception as exc:
        LOG.exception("recovery_reset_failed", vault=str(vault_path), error=str(exc))
        typer.echo("✖ Failed to reset password with recovery key")
        raise typer.Exit(1)
    typer.echo("✔ Vault password reset. Use the new password for future operations.")
def _expand_name_patterns(names: list[str]) -> list[str]:
    """Expand all brace expressions from the CLI arguments into concrete names."""
    expanded: list[str] = []
    for entry in names:
        rng = _expand_range(entry)
        if rng:
            expanded.extend(rng)
        else:
            expanded.append(entry)
    return expanded


def _resolve_outputs(out: str, expanded_names: list[str]) -> list[str | None]:
    """Resolve the desired output destinations for each requested record."""
    if out == "-" and len(expanded_names) == 1:
        return ["-"]
    template_range = None if out in ("-", None) else _expand_range(out)
    if template_range:
        if len(template_range) != len(expanded_names):
            typer.echo("✖ Output range count does not match number of files")
            raise typer.Exit(1)
        return template_range
    if out not in ("-", None) and len(expanded_names) == 1:
        return [out]
    return _prompt_for_outputs(len(expanded_names), None if out in ("-", None) else out)
