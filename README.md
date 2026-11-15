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
├── vault.sh                   # Main production shell script (Linux/WSL/Git Bash)
├── vault.bat                  # Windows 10 PowerShell / CMD launcher
├── test_vault.sh              # Comprehensive automated verification suite
├── test_vault.bat             # Windows 10 test launcher
├── run_menu.bat               # Windows double-click interactive menu
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

SecureVault runs natively on **Linux, macOS, WSL**, and directly in **Windows 10 PowerShell / Command Prompt**.

---

## 🖥️ Pure CLI Tutorial: Zero GUI / No Right-Clicking (Linux & Windows Side-by-Side)

> **Golden Rule for University Labs:** In computer science exams, creating files with mouse right-click or Windows Explorer will cost you marks. Everything must be executed via shell commands!

### 1. Essential Command Equivalents: Linux vs Windows PowerShell

| Action | 🐧 Linux (Bash Terminal) | 🪟 Windows (PowerShell) |
| :--- | :--- | :--- |
| **Create empty file** | `touch document.txt` | `New-Item document.txt` |
| **Create file with text** | `echo "Secret Data" > secret.txt` | `echo "Secret Data" > secret.txt` |
| **Append line to file** | `echo "More Data" >> secret.txt` | `echo "More Data" >> secret.txt` |
| **View / Read file** | `cat secret.txt` | `cat secret.txt` *(or `Get-Content`)* |
| **Create folder** | `mkdir confidential_lab` | `mkdir confidential_lab` |
| **Create nested folders** | `mkdir -p project/src/utils` | `mkdir project/src/utils` |
| **List directory contents** | `ls -la` | `ls` *(or `dir`)* |
| **Delete file** | `rm secret.txt` | `rm secret.txt` |
| **Delete folder & contents** | `rm -rf confidential_lab` | `rm -r -fo confidential_lab` |
| **Make script executable** | `chmod +x vault.sh` | Run `.\vault.bat` |

---

### 2. Feature-by-Feature Guided Hands-On Practice

#### Step 1: Make Scripts Executable (Linux Only)
- **Linux:** `chmod +x vault.sh test_vault.sh`
- **Windows:** Automatically handled by `.\vault.bat`

#### Step 2: Create a Secret File via Terminal (No GUI!)
- **Linux:**
  ```bash
  echo "CONFIDENTIAL: Midterm Exam Paper Key 2026" > my_secret.txt
  cat my_secret.txt
  ```
- **Windows PowerShell:**
  ```powershell
  echo "CONFIDENTIAL: Midterm Exam Paper Key 2026" > my_secret.txt
  cat my_secret.txt
  ```

#### Step 3: Encrypt the File
- **Linux:** `./vault.sh -e my_secret.txt`
- **Windows PowerShell:** `.\vault.bat -e my_secret.txt`
*(Enter password `Secret123!`, confirm it, and choose `n` for shredding)*
- **Inspect Ciphertext:** `cat my_secret.txt.vault` *(Notice scrambled unreadable ciphertext)*

#### Step 4: Delete Plaintext & Decrypt It Back
- **Linux:**
  ```bash
  rm my_secret.txt
  ./vault.sh -d my_secret.txt.vault
  cat my_secret.txt
  ```
- **Windows PowerShell:**
  ```powershell
  rm my_secret.txt
  .\vault.bat -d my_secret.txt.vault
  cat my_secret.txt
  ```

#### Step 5: Create a Nested Directory Structure via Terminal
- **Linux:**
  ```bash
  mkdir -p my_project/src my_project/data
  echo "print('Secure Computation')" > my_project/src/app.py
  echo "id,score\n202601,98" > my_project/data/scores.csv
  ls -R my_project
  ```
- **Windows PowerShell:**
  ```powershell
  mkdir my_project/src, my_project/data
  echo "print('Secure Computation')" > my_project/src/app.py
  echo "id,token`n1,alpha99" > my_project/data/scores.csv
  ls -R my_project
  ```

#### Step 6: Encrypt & Decrypt Directory
- **Linux:**
  ```bash
  ./vault.sh -e my_project          # Encrypt
  rm -rf my_project                 # Remove original
  ./vault.sh -d my_project.vault    # Decrypt (auto-extracts tree)
  ls -R my_project                  # Verify structure
  ```
- **Windows PowerShell:**
  ```powershell
  .\vault.bat -e my_project         # Encrypt
  rm -r -fo my_project              # Remove original
  .\vault.bat -d my_project.vault   # Decrypt (auto-extracts tree)
  ls -R my_project                  # Verify structure
  ```

#### Step 7: Security Negative Test (Wrong Password Rejection)
- **Linux:** `./vault.sh -d my_secret.txt.vault` *(Type: `WrongPass999`)*
- **Windows PowerShell:** `.\vault.bat -d my_secret.txt.vault` *(Type: `WrongPass999`)*
*(Cleanly rejected with `[ERROR] Decryption failed! Incorrect password or corrupted file.`)*

#### Step 8: Verify SHA-256 Checksum & View Audit Trail
- **Linux:**
  ```bash
  ./vault.sh -v my_secret.txt
  ./vault.sh -l
  ```
- **Windows PowerShell:**
  ```powershell
  .\vault.bat -v my_secret.txt
  .\vault.bat -l
  ```

#### Step 9: Run Automated Self-Tests
- **Linux:** `./test_vault.sh`
- **Windows PowerShell:** `.\test_vault.bat`

#### Step 10: Launch Interactive Terminal Menu
- **Linux:** `./vault.sh`
- **Windows PowerShell:** `.\vault.bat` *(or double-click `run_menu.bat`)*

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

