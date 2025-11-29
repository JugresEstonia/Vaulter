# Vaulter

**Vaulter** is a minimal, security-first encrypted file vault for UNIX systems.
It uses Argon2id + XChaCha20-Poly1305 encryption. All metadata and filenames are protected inside an encrypted index; the vault folder itself only contains ciphertext blobs.

---

## Setup

```bash
git clone https://github.com/JugresEstonia/Vaulter.git
cd vaulter
python -m venv .venv
source .venv/bin/activate

pip install -e .
```

---

## Basic Usage

### Initialize a vault
vaulter init --vault ./myvault

### Add one or more files
vaulter add ./myvault secret.txt other.txt
vaulter add ./myvault secret.txt --name topsecret.txt
> Directories aren’t supported; archive them first if needed (e.g., `tar` or `zip`).
> If a name already exists, Vaulter will prompt you to provide a unique alias before adding the file.

### List stored files
vaulter lst ./myvault             # shows size, id, and added time (HH:MM:SS DD.MM.YYYY)

### Retrieve a file
vaulter get ./myvault topsecret.txt --out recovered.txt 

### Remove files (crypto-shred by default)
vaulter rm ./myvault topsecret.txt other.txt              # wipes blobs (prompts for confirmation)
vaulter rm ./myvault topsecret.txt --keep-blob            # keep ciphertext for forensic recovery

### Check vault integrity
vaulter check ./myvault

### Enable a recovery key (writes `./myvault.recovery.key`)
vaulter init ./myvault --enable-recovery

> Store `myvault.recovery.key` somewhere offline (password manager, encrypted USB, printed copy). Anyone who obtains it can reset your vault password, so delete the local copy after you back it up.

### Reset a forgotten password with the recovery key
vaulter recover --vault ./myvault --recovery-key-file ./myvault.recovery.key

All CLI commands emit log lines to `~/.local/state/vaulter/vaulter.log` (override via `VAULTER_LOG=/path/to/file`); files are created with 0600 permissions and include ISO timestamps.
