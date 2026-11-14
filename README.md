# SecureVault 🔐 — File & Directory Encryption Suite for Linux

> **Course:** Operating Systems / UNIX Shell Scripting Project  
> **Topic:** Encrypt and Decrypt a File or Directory using Shell Scripting  
> **Implementation:** Pure Bash (POSIX compliant coreutils) + OpenSSL AES-256-CBC with PBKDF2  

---

## 📌 Project Overview

**SecureVault** is an enterprise-grade yet student-friendly shell script designed to securely encrypt and decrypt both **individual files** and **entire directory hierarchies** on Linux/UNIX systems.

While basic encryption scripts exist online, they are typically 10-line basic wrappers that:
1. Expose passwords in plaintext or process tables (`ps aux`).
2. Completely fail when given a directory (`Is a directory` error).
3. Leave unencrypted sensitive temporary files in `/tmp` if interrupted (e.g., Ctrl+C).
4. Provide zero tamper detection or cryptographic integrity verification.
5. Lack structured auditing or automated test suites.

**SecureVault solves all of these challenges** from scratch using core UNIX philosophy and standard system utilities.

---

## 🚀 Key Features (Why This Stands Out to Faculty)

| Feature | Standard Online Tutorial | **SecureVault (This Project)** |
| :--- | :--- | :--- |
| **Cipher Algorithm** | Deprecated DES / unsalted AES | **AES-256-CBC with PBKDF2** (100,000 iterations + salt) |
| **Directory Support** | ❌ Fails on directories | ✅ **Full directory trees** via integrated `tar` + `gzip` streaming |
| **Decryption Auto-Detect** | ❌ User must manually unpack | ✅ **Smart detection**: automatically detects if vault is a directory or file |
| **Password Hygiene** | Exposed in `ps` (`-pass pass:$p`) | ✅ **Streams via `stdin`** + masked input (`read -s`) + typo confirmation |
| **Signal Handling** | Leaves temp files on disk on abort | ✅ **`trap cleanup EXIT INT TERM`** securely shreds & removes temp files |
| **Integrity Verification** | ❌ None (silent corruption) | ✅ **SHA-256 checksum** computed before & after + audit log verification |
| **Audit Trail** | ❌ None | ✅ Structured, timestamped **`vault_audit.log`** with user & action info |
| **Operation Modes** | Interactive only | ✅ **Dual-mode**: Interactive colorful menu + scriptable CLI flags (`getopts`) |
| **Automated Testing** | ❌ None | ✅ Integrated **automated test runner (`test_vault.sh`)** |

---

## 📂 Project Structure

```text
jawad_linux/
├── vault.sh                   # Main production shell script
├── test_vault.sh              # Comprehensive automated verification suite
├── index.html                 # Personal HTML + Tailwind documentation & viva defense guide
├── vault_audit.log            # Audit log recording operations & SHA-256 hashes
├── demo_data/                 # Sample files for faculty demonstration
│   ├── classified_report.txt  # Sample text file
│   └── research_project/      # Sample nested directory structure
│       ├── experiment.py
│       ├── dataset.csv
│       └── project_summary.md
└── README.md                  # Project manual & documentation
```

---

## 🛠️ Prerequisites

SecureVault uses standard tools available out-of-the-box on almost all UNIX/Linux distributions (Ubuntu, Debian, Fedora, Arch, macOS, WSL, Cygwin, Git-Bash):
- `bash` (4.0+)
- `openssl` (1.1.1+ or 3.x)
- `tar` and `gzip`
- `sha256sum` (or `shasum` on macOS/BSD)

---

## 💻 How to Run

### 1. Interactive Menu Mode (Recommended for Live Demo)
Simply run the script with no arguments:
```bash
./vault.sh
```
This presents a user-friendly, color-coded menu:
```text
  ____                            __     __            _ _   
 / ___|  ___  ___ _   _ _ __ ___  \ \   / /_ _ _   _ _| | |_ 
 \___ \ / _ \/ __| | | | '__/ _ \  \ \ / / _` | | | | | | __|
  ___) |  __/ (__| |_| | | |  __/   \ V / (_| | |_| | | | |_ 
 |____/ \___|\___|\__,_|_|  \___|    \_/ \__,_|\__,_|_|_|\__|
  File & Directory Encryption Suite (AES-256-CBC + PBKDF2)
  Version: 1.2.0 | University Shell Scripting Project
----------------------------------------------------------------------
Select an operation:
  [1] Encrypt a File
  [2] Encrypt a Directory
  [3] Decrypt a Vault (.vault package)
  [4] Verify File / Directory Checksum (SHA-256)
  [5] View Audit Logs
  [6] Run Automated Self-Tests
  [7] Exit
```

### 2. Command-Line Options (CLI Mode)
SecureVault also supports standard POSIX flags for scriptability and crontab automation:

```bash
# Encrypt a single file:
./vault.sh -e demo_data/classified_report.txt

# Encrypt an entire directory tree:
./vault.sh -e demo_data/research_project

# Decrypt any .vault package (auto-detects file vs folder):
./vault.sh -d demo_data/classified_report.txt.vault
./vault.sh -d demo_data/research_project.vault

# Check SHA-256 integrity against audit history:
./vault.sh -v demo_data/classified_report.txt

# View audit history log:
./vault.sh -l

# Run internal self-test suite:
./vault.sh -t

# Display help message:
./vault.sh -h
```

---

## 🧪 Automated Verification Suite

To demonstrate code robustness to faculty, run the automated verification script:
```bash
./test_vault.sh
```

**What it tests:**
1. Verifies availability of system binaries (`openssl`, `tar`, `gzip`, `sha256sum`).
2. Round-trip single file encryption and bit-for-bit SHA-256 hash match.
3. Negative security test: validates that invalid passwords are cleanly rejected.
4. Nested directory archiving, encryption, decryption, and directory tree restoration.
5. Exit code checks on all CLI flags.

---

## 🌐 Interactive Documentation & Viva Defense Guide

Open `index.html` in your browser (simply double-click the file or run `xdg-open index.html` / `open index.html` / `start index.html`):
- **Full Architecture & Logic Flow** with visual diagrams.
- **Side-by-side comparison** against naive online scripts.
- **Line-by-line code explanation** and what to highlight.
- **Top 10 Viva Voce questions** with faculty-ready answers.
- **Live Terminal Simulator** that lets you simulate commands interactively inside your browser!

---

## 🎓 Faculty Defense & Viva Voce Quick Cheat Sheet

1. **Why AES-256-CBC with PBKDF2?**
   - AES-256 provides military-grade confidentiality. CBC prevents ciphertext block repetition. PBKDF2 with 100,000 iterations and salt counters dictionary & rainbow-table attacks.
2. **How does decryption auto-detect directories?**
   - It stages the decrypted stream into a temporary file and executes `tar -tzf $temp`. If the command succeeds (exit code `0`), it's a tarball and extracts the directory hierarchy. Otherwise, it restores it as a regular file.
3. **Why pass passwords via `stdin` instead of `-pass pass:...`?**
   - Command-line arguments are visible to any user on a system via `ps aux` or `/proc/[pid]/cmdline`. Streaming via `stdin` prevents memory leakage into the OS process table.
4. **Why is `trap` essential in security scripts?**
   - If a script is interrupted (Ctrl+C / SIGINT), unencrypted temporary tarballs in `/tmp` could leak confidential data. `trap cleanup EXIT INT TERM` catches all termination signals and securely overwrites temporary files before deletion.

