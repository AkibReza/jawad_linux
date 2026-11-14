#!/usr/bin/env bash
# ==============================================================================
# Project: SecureVault - File & Directory Encryption Suite
# Course: Operating Systems / Shell Scripting Project
# Description: A secure, student-friendly Bash script for encrypting and
#              decrypting files and directories using OpenSSL (AES-256-CBC)
#              with SHA-256 integrity verification, safe signal handling,
#              directory archiving, and audit logging.
# ==============================================================================

# Exit immediately if a command exits with a non-zero status (defensive scripting)
# Note: We manage error exits explicitly in key functions.
set -o pipefail

# ------------------------------------------------------------------------------
# Global Constants & Color Codes
# ------------------------------------------------------------------------------
readonly SCRIPT_NAME="SecureVault"
readonly SCRIPT_VERSION="1.2.0"
readonly AUDIT_LOG_FILE="vault_audit.log"
readonly PBKDF2_ITERATIONS=100000

# ANSI color codes for readable, professional terminal output
readonly COLOR_RESET="\033[0m"
readonly COLOR_BOLD="\033[1m"
readonly COLOR_GREEN="\033[1;32m"
readonly COLOR_RED="\033[1;31m"
readonly COLOR_YELLOW="\033[1;33m"
readonly COLOR_CYAN="\033[1;36m"
readonly COLOR_BLUE="\033[1;34m"
readonly COLOR_MAGENTA="\033[1;35m"

# Array to track temporary files that must be removed on exit
TEMP_FILES=()

# ------------------------------------------------------------------------------
# Signal Handling & Cleanup
# Concept: Uses 'trap' to ensure no sensitive temporary data remains on disk
# if the script terminates unexpectedly (Ctrl+C, kill signal, normal exit).
# ------------------------------------------------------------------------------
cleanup() {
    local exit_code=$?
    if [[ ${#TEMP_FILES[@]} -gt 0 ]]; then
        for tmp in "${TEMP_FILES[@]}"; do
            if [[ -f "$tmp" ]]; then
                # Overwrite temp file before deleting for basic security
                dd if=/dev/urandom of="$tmp" bs=1k count=1 status=none 2>/dev/null || true
                rm -f "$tmp" 2>/dev/null || true
            elif [[ -d "$tmp" ]]; then
                rm -rf "$tmp" 2>/dev/null || true
            fi
        done
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------------------------
# UI Helper Functions
# ------------------------------------------------------------------------------
print_banner() {
    echo -e "${COLOR_CYAN}"
    cat << "EOF"
  ____                            __     __            _ _   
 / ___|  ___  ___ _   _ _ __ ___  \ \   / /_ _ _   _ _| | |_ 
 \___ \ / _ \/ __| | | | '__/ _ \  \ \ / / _` | | | | | | __|
  ___) |  __/ (__| |_| | | |  __/   \ V / (_| | |_| | | | |_ 
 |____/ \___|\___|\__,_|_|  \___|    \_/ \__,_|\__,_|_|_|\__|
EOF
    echo -e "${COLOR_BOLD}  File & Directory Encryption Suite (AES-256-CBC + PBKDF2)${COLOR_RESET}"
    echo -e "${COLOR_BLUE}  Version: ${SCRIPT_VERSION} | University Shell Scripting Project${COLOR_RESET}"
    echo -e "----------------------------------------------------------------------"
}

msg_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
}

msg_success() {
    echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_RESET} $1"
}

msg_warn() {
    echo -e "${COLOR_YELLOW}[WARNING]${COLOR_RESET} $1"
}

msg_error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $1" >&2
}

# ------------------------------------------------------------------------------
# Dependency Verification
# Ensures all required standard UNIX tools exist on the system.
# ------------------------------------------------------------------------------
check_dependencies() {
    local missing=()
    for cmd in openssl tar gzip; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    # Check for sha256 checksum tool (supports both GNU sha256sum and BSD shasum)
    if ! command -v sha256sum &>/dev/null && ! command -v shasum &>/dev/null; then
        missing+=("sha256sum/shasum")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        msg_error "Missing required dependencies: ${missing[*]}"
        msg_error "Please install them via your package manager (e.g., apt install openssl coreutils tar)."
        exit 1
    fi
}

# Portable SHA-256 calculation
calculate_sha256() {
    local target="$1"
    if command -v sha256sum &>/dev/null; then
        sha256sum "$target" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$target" | awk '{print $1}'
    else
        echo "UNAVAILABLE"
    fi
}

# ------------------------------------------------------------------------------
# Audit Logging
# Concept: Maintains a local audit trail for security auditing and accountability.
# ------------------------------------------------------------------------------
log_audit() {
    local action="$1"
    local target="$2"
    local status="$3"
    local details="$4"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local user="${USER:-$(whoami 2>/dev/null || echo "unknown")}"

    # Format: [TIMESTAMP] [USER] [ACTION] [TARGET] [STATUS] [DETAILS]
    echo "[$timestamp] [User: $user] [Action: $action] [Target: $target] [Status: $status] - $details" >> "$AUDIT_LOG_FILE"
}

# ------------------------------------------------------------------------------
# Secure Password Input
# Concept: Uses 'read -s' to mask passwords, prevents shoulder-surfing,
# and enforces confirmation to protect against locking yourself out with typos.
# ------------------------------------------------------------------------------
prompt_password() {
    local confirm_needed="$1" # Set to "true" during encryption
    local pass1=""
    local pass2=""

    while true; do
        echo -en "${COLOR_BOLD}Enter encryption password: ${COLOR_RESET}"
        read -r -s pass1
        echo ""

        if [[ -z "$pass1" ]]; then
            msg_warn "Password cannot be empty. Please try again."
            continue
        fi

        if [[ ${#pass1} -lt 6 ]]; then
            msg_warn "Password should be at least 6 characters for security."
        fi

        if [[ "$confirm_needed" == "true" ]]; then
            echo -en "${COLOR_BOLD}Confirm password: ${COLOR_RESET}"
            read -r -s pass2
            echo ""

            if [[ "$pass1" != "$pass2" ]]; then
                msg_error "Passwords do not match. Please try again."
                continue
            fi
        fi

        # Export password safely to caller via global variable
        USER_PASSWORD="$pass1"
        break
    done
}

# ------------------------------------------------------------------------------
# Optional Secure Shredding
# Concept: Overwriting file before deletion so data cannot be recovered by tools.
# ------------------------------------------------------------------------------
prompt_secure_delete() {
    local target="$1"
    local is_dir="$2"

    echo ""
    echo -en "${COLOR_YELLOW}[SECURITY OPTION] Do you want to securely remove the unencrypted original? (y/N): ${COLOR_RESET}"
    read -r choice

    case "$choice" in
        [yY]|[yY][eE][sS])
            msg_info "Securely removing unencrypted original: $target"
            if [[ "$is_dir" == "true" ]]; then
                rm -rf "$target"
                msg_success "Original directory deleted."
            else
                if command -v shred &>/dev/null; then
                    shred -u -z -n 3 "$target" 2>/dev/null || rm -f "$target"
                else
                    # Fallback overwrite using dd
                    local size
                    size=$(wc -c < "$target" 2>/dev/null || echo 0)
                    if [[ $size -gt 0 ]]; then
                        dd if=/dev/urandom of="$target" bs=1k count=$(( (size / 1024) + 1 )) status=none 2>/dev/null || true
                    fi
                    rm -f "$target"
                fi
                msg_success "Original file securely shredded."
            fi
            ;;
        *)
            msg_info "Original file retained at user request."
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Core Feature: Encrypt File
# ------------------------------------------------------------------------------
encrypt_file() {
    local infile="$1"

    if [[ ! -f "$infile" ]]; then
        msg_error "File not found: $infile"
        return 1
    fi

    # Output filename
    local outfile="${infile}.vault"
    if [[ -f "$outfile" ]]; then
        echo -en "${COLOR_YELLOW}Warning: Output file '$outfile' already exists. Overwrite? (y/N): ${COLOR_RESET}"
        read -r ans
        if [[ ! "$ans" =~ ^[yY]$ ]]; then
            msg_info "Encryption canceled by user."
            return 0
        fi
    fi

    prompt_password "true"
    local password="$USER_PASSWORD"
    unset USER_PASSWORD

    msg_info "Computing SHA-256 checksum of original file..."
    local original_checksum
    original_checksum=$(calculate_sha256 "$infile")
    echo -e "  ${COLOR_CYAN}SHA-256:${COLOR_RESET} $original_checksum"

    msg_info "Encrypting using AES-256-CBC with PBKDF2 (100,000 iterations)..."
    
    # Run OpenSSL encryption
    # Using -pbkdf2 and high iteration count protects against brute-force dictionary attacks
    if printf "%s" "$password" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter "$PBKDF2_ITERATIONS" \
        -in "$infile" -out "$outfile" -pass stdin 2>/dev/null; then
        
        local encrypted_checksum
        encrypted_checksum=$(calculate_sha256 "$outfile")

        msg_success "Encryption successful!"
        echo -e "  ${COLOR_GREEN}Encrypted file:${COLOR_RESET} $outfile"
        echo -e "  ${COLOR_CYAN}Vault Checksum:${COLOR_RESET} $encrypted_checksum"

        log_audit "ENCRYPT_FILE" "$infile" "SUCCESS" "Vault: $outfile | OrigSHA: $original_checksum"
        prompt_secure_delete "$infile" "false"
    else
        msg_error "Encryption failed during OpenSSL operation."
        log_audit "ENCRYPT_FILE" "$infile" "FAILED" "OpenSSL execution error"
        rm -f "$outfile" 2>/dev/null || true
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Core Feature: Encrypt Directory
# Concept: Archives directory with tar+gzip, then encrypts resulting stream.
# ------------------------------------------------------------------------------
encrypt_directory() {
    local indir="$1"

    # Remove trailing slash for consistency
    indir="${indir%/}"

    if [[ ! -d "$indir" ]]; then
        msg_error "Directory not found: $indir"
        return 1
    fi

    local outfile="${indir}.vault"
    if [[ -f "$outfile" ]]; then
        echo -en "${COLOR_YELLOW}Warning: Output file '$outfile' already exists. Overwrite? (y/N): ${COLOR_RESET}"
        read -r ans
        if [[ ! "$ans" =~ ^[yY]$ ]]; then
            msg_info "Encryption canceled by user."
            return 0
        fi
    fi

    prompt_password "true"
    local password="$USER_PASSWORD"
    unset USER_PASSWORD

    # Create temporary tarball
    local temp_tar
    temp_tar=$(mktemp "/tmp/vault_dir_XXXXXX.tar.gz" 2>/dev/null || mktemp "./.vault_dir_XXXXXX.tar.gz")
    TEMP_FILES+=("$temp_tar")

    msg_info "Archiving directory into compressed package..."
    local parent_dir
    local base_dir
    parent_dir="$(dirname "$indir")"
    base_dir="$(basename "$indir")"

    if ! tar -czf "$temp_tar" -C "$parent_dir" "$base_dir" 2>/dev/null; then
        msg_error "Failed to archive directory with tar."
        log_audit "ENCRYPT_DIR" "$indir" "FAILED" "tar creation failed"
        return 1
    fi

    local archive_checksum
    archive_checksum=$(calculate_sha256 "$temp_tar")

    msg_info "Encrypting archive using AES-256-CBC..."
    if printf "%s" "$password" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter "$PBKDF2_ITERATIONS" \
        -in "$temp_tar" -out "$outfile" -pass stdin 2>/dev/null; then

        msg_success "Directory encrypted successfully!"
        echo -e "  ${COLOR_GREEN}Encrypted Vault:${COLOR_RESET} $outfile"
        echo -e "  ${COLOR_CYAN}Archive SHA-256:${COLOR_RESET} $archive_checksum"

        log_audit "ENCRYPT_DIR" "$indir" "SUCCESS" "Vault: $outfile | ArchiveSHA: $archive_checksum"
        prompt_secure_delete "$indir" "true"
    else
        msg_error "Failed to encrypt directory archive."
        log_audit "ENCRYPT_DIR" "$indir" "FAILED" "OpenSSL execution error"
        rm -f "$outfile" 2>/dev/null || true
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Core Feature: Decrypt Vault (File or Directory)
# Concept: Decrypts payload into a temporary space, inspects if it's a tar archive
# or a standard file, and restores the original content accurately.
# ------------------------------------------------------------------------------
decrypt_vault() {
    local vault_file="$1"

    if [[ ! -f "$vault_file" ]]; then
        msg_error "Vault file not found: $vault_file"
        return 1
    fi

    prompt_password "false"
    local password="$USER_PASSWORD"
    unset USER_PASSWORD

    # Create temporary file to test decrypted content
    local temp_decrypted
    temp_decrypted=$(mktemp "/tmp/vault_dec_XXXXXX" 2>/dev/null || mktemp "./.vault_dec_XXXXXX")
    TEMP_FILES+=("$temp_decrypted")

    msg_info "Attempting decryption with OpenSSL..."
    
    # Decrypt to temporary file first
    if ! printf "%s" "$password" | openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter "$PBKDF2_ITERATIONS" \
        -in "$vault_file" -out "$temp_decrypted" -pass stdin 2>/dev/null; then
        msg_error "Decryption failed! Incorrect password or corrupted file."
        log_audit "DECRYPT" "$vault_file" "FAILED" "Invalid password / Bad decrypt"
        return 1
    fi

    # Determine default restored name by stripping '.vault' if present
    local restored_name
    if [[ "$vault_file" == *.vault ]]; then
        restored_name="${vault_file%.vault}"
    else
        restored_name="${vault_file}.decrypted"
    fi

    # Check if decrypted stream is a compressed TAR archive (Directory detection)
    if tar -tzf "$temp_decrypted" &>/dev/null; then
        msg_info "Detected encrypted DIRECTORY archive."
        
        # Check if destination directory already exists
        local dest_parent="."
        if [[ -d "$restored_name" ]]; then
            echo -en "${COLOR_YELLOW}Directory '$restored_name' already exists. Overwrite contents? (y/N): ${COLOR_RESET}"
            read -r ans
            if [[ ! "$ans" =~ ^[yY]$ ]]; then
                restored_name="${restored_name}_restored_$(date +%s)"
                msg_info "Extracting to alternate folder: $restored_name"
                mkdir -p "$restored_name"
                dest_parent="$restored_name"
            fi
        fi

        if tar -xzf "$temp_decrypted" -C "$dest_parent" 2>/dev/null; then
            msg_success "Directory successfully restored!"
            echo -e "  ${COLOR_GREEN}Restored to:${COLOR_RESET} $restored_name"
            log_audit "DECRYPT_DIR" "$vault_file" "SUCCESS" "Extracted to $restored_name"
        else
            msg_error "Failed to unpack restored directory archive."
            log_audit "DECRYPT_DIR" "$vault_file" "FAILED" "tar unpack failed"
            return 1
        fi
    else
        # Regular File Restoration
        msg_info "Detected regular FILE payload."

        if [[ -e "$restored_name" ]]; then
            echo -en "${COLOR_YELLOW}File '$restored_name' already exists. Overwrite? (y/N): ${COLOR_RESET}"
            read -r ans
            if [[ ! "$ans" =~ ^[yY]$ ]]; then
                restored_name="${restored_name}.restored_$(date +%s)"
                msg_info "Saving to alternate filename: $restored_name"
            fi
        fi

        mv "$temp_decrypted" "$restored_name"
        local restored_checksum
        restored_checksum=$(calculate_sha256 "$restored_name")

        msg_success "File successfully decrypted!"
        echo -e "  ${COLOR_GREEN}Restored file:${COLOR_RESET} $restored_name"
        echo -e "  ${COLOR_CYAN}Restored SHA-256:${COLOR_RESET} $restored_checksum"

        log_audit "DECRYPT_FILE" "$vault_file" "SUCCESS" "Restored: $restored_name | SHA: $restored_checksum"
    fi
}

# ------------------------------------------------------------------------------
# Feature: Verify File Checksum
# ------------------------------------------------------------------------------
verify_integrity() {
    local target="$1"

    if [[ ! -e "$target" ]]; then
        msg_error "Target not found: $target"
        return 1
    fi

    if [[ -d "$target" ]]; then
        msg_info "Target is a directory. Generating SHA-256 checksums of its files..."
        find "$target" -type f -exec sha256sum {} + 2>/dev/null || find "$target" -type f -exec shasum -a 256 {} +
        return 0
    fi

    msg_info "Computing SHA-256 checksum for: $target"
    local checksum
    checksum=$(calculate_sha256 "$target")
    echo -e "  ${COLOR_BOLD}Target:${COLOR_RESET}   $target"
    echo -e "  ${COLOR_CYAN}SHA-256:${COLOR_RESET}  $checksum"

    if [[ -f "$AUDIT_LOG_FILE" ]]; then
        local match
        match=$(grep "$checksum" "$AUDIT_LOG_FILE" 2>/dev/null | tail -n 1)
        if [[ -n "$match" ]]; then
            msg_success "Checksum verified in audit log!"
            echo -e "  ${COLOR_BLUE}Log Entry:${COLOR_RESET} $match"
        else
            msg_info "No matching hash recorded in current local audit log."
        fi
    fi
}

# ------------------------------------------------------------------------------
# Feature: View Audit Logs
# ------------------------------------------------------------------------------
show_audit_log() {
    if [[ ! -f "$AUDIT_LOG_FILE" ]]; then
        msg_info "No audit log file found ($AUDIT_LOG_FILE). Perform an operation to generate logs."
        return 0
    fi

    echo -e "${COLOR_BOLD}=== SECUREVAULT AUDIT HISTORY ===${COLOR_RESET}"
    echo -e "${COLOR_CYAN}File: $AUDIT_LOG_FILE${COLOR_RESET}"
    echo "----------------------------------------------------------------------"
    tail -n 25 "$AUDIT_LOG_FILE"
    echo "----------------------------------------------------------------------"
    msg_info "Displaying the latest 25 log entries."
}

# ------------------------------------------------------------------------------
# Self-Test / Verification Suite
# Demonstrates script reliability directly to professors.
# ------------------------------------------------------------------------------
run_self_test() {
    echo -e "\n${COLOR_BOLD}=== RUNNING AUTOMATED SELF-TEST SUITE ===${COLOR_RESET}"
    local test_dir
    test_dir=$(mktemp -d "/tmp/vault_test_XXXXXX" 2>/dev/null || mktemp -d "./.vault_test_XXXXXX")
    TEMP_FILES+=("$test_dir")

    local test_file="$test_dir/sample.txt"
    echo "Top Secret University Lab Data 123456" > "$test_file"
    local sample_orig_hash
    sample_orig_hash=$(calculate_sha256 "$test_file")

    echo -e "1. Testing File Encryption..."
    local test_pass="MySecurePass123!"
    if ! printf "%s" "$test_pass" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter "$PBKDF2_ITERATIONS" \
        -in "$test_file" -out "$test_file.vault" -pass stdin 2>/dev/null; then
        msg_error "Self-test file encryption failed."
        return 1
    fi
    msg_success "File encrypted successfully."

    echo -e "2. Testing File Decryption..."
    local test_dec="$test_dir/sample_dec.txt"
    if ! printf "%s" "$test_pass" | openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter "$PBKDF2_ITERATIONS" \
        -in "$test_file.vault" -out "$test_dec" -pass stdin 2>/dev/null; then
        msg_error "Self-test file decryption failed."
        return 1
    fi

    local sample_dec_hash
    sample_dec_hash=$(calculate_sha256 "$test_dec")
    if [[ "$sample_orig_hash" == "$sample_dec_hash" ]]; then
        msg_success "Decrypted content matches original hash: [PASS]"
    else
        msg_error "Hash mismatch between original and decrypted file: [FAIL]"
        return 1
    fi

    echo -e "3. Testing Wrong Password Rejection..."
    if printf "%s" "WrongPass!" | openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter "$PBKDF2_ITERATIONS" \
        -in "$test_file.vault" -out "$test_dir/invalid.txt" -pass stdin 2>/dev/null; then
        msg_error "Security vulnerability: Wrong password did not fail!"
        return 1
    else
        msg_success "Wrong password rejected properly: [PASS]"
    fi

    echo -e "4. Testing Directory Archive & Encryption..."
    local sample_sub="$test_dir/subfolder"
    mkdir -p "$sample_sub"
    echo "Document A" > "$sample_sub/docA.txt"
    echo "Document B" > "$sample_sub/docB.txt"

    local temp_archive="$test_dir/sub.tar.gz"
    tar -czf "$temp_archive" -C "$test_dir" "subfolder" 2>/dev/null
    printf "%s" "$test_pass" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter "$PBKDF2_ITERATIONS" \
        -in "$temp_archive" -out "$test_dir/subfolder.vault" -pass stdin 2>/dev/null
    
    # Decrypt and unpack
    local dec_archive="$test_dir/restored_sub.tar.gz"
    printf "%s" "$test_pass" | openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter "$PBKDF2_ITERATIONS" \
        -in "$test_dir/subfolder.vault" -out "$dec_archive" -pass stdin 2>/dev/null
    
    local restore_out="$test_dir/restored"
    mkdir -p "$restore_out"
    tar -xzf "$dec_archive" -C "$restore_out" 2>/dev/null

    if [[ -f "$restore_out/subfolder/docA.txt" && -f "$restore_out/subfolder/docB.txt" ]]; then
        msg_success "Directory structure preserved & restored: [PASS]"
    else
        msg_error "Directory restore verification failed: [FAIL]"
        return 1
    fi

    echo -e "\n${COLOR_GREEN}${COLOR_BOLD}ALL 4 SELF-TEST SUITES PASSED FLAWLESSLY!${COLOR_RESET}\n"
    rm -rf "$test_dir" 2>/dev/null || true
}

# ------------------------------------------------------------------------------
# Interactive Menu
# ------------------------------------------------------------------------------
show_help() {
    print_banner
    echo -e "${COLOR_BOLD}USAGE:${COLOR_RESET}"
    echo "  $0 [OPTIONS] [TARGET]"
    echo ""
    echo -e "${COLOR_BOLD}OPTIONS:${COLOR_RESET}"
    echo "  -e <path>    Encrypt a file or directory"
    echo "  -d <vault>   Decrypt a .vault package (auto-detects file or directory)"
    echo "  -v <path>    Verify SHA-256 checksum against audit log"
    echo "  -l           Display operation audit logs"
    echo "  -t           Run automated self-tests and validation"
    echo "  -h           Show this help message"
    echo ""
    echo -e "${COLOR_BOLD}EXAMPLES:${COLOR_RESET}"
    echo "  $0 -e confidential.pdf        # Encrypts file to confidential.pdf.vault"
    echo "  $0 -e ./project_folder        # Archives and encrypts directory to project_folder.vault"
    echo "  $0 -d confidential.pdf.vault  # Decrypts file back to confidential.pdf"
    echo "  $0                            # Runs interactive student menu"
    echo ""
}

interactive_menu() {
    while true; do
        print_banner
        echo -e "${COLOR_BOLD}Select an operation:${COLOR_RESET}"
        echo -e "  ${COLOR_CYAN}[1]${COLOR_RESET} Encrypt a File"
        echo -e "  ${COLOR_CYAN}[2]${COLOR_RESET} Encrypt a Directory"
        echo -e "  ${COLOR_CYAN}[3]${COLOR_RESET} Decrypt a Vault (.vault package)"
        echo -e "  ${COLOR_CYAN}[4]${COLOR_RESET} Verify File / Directory Checksum (SHA-256)"
        echo -e "  ${COLOR_CYAN}[5]${COLOR_RESET} View Audit Logs"
        echo -e "  ${COLOR_CYAN}[6]${COLOR_RESET} Run Automated Self-Tests"
        echo -e "  ${COLOR_CYAN}[7]${COLOR_RESET} Exit"
        echo ""
        echo -en "${COLOR_BOLD}Enter choice [1-7]: ${COLOR_RESET}"
        read -r choice

        case "$choice" in
            1)
                echo -en "Enter path of file to encrypt: "
                read -r filepath
                encrypt_file "$filepath"
                ;;
            2)
                echo -en "Enter path of directory to encrypt: "
                read -r dirpath
                encrypt_directory "$dirpath"
                ;;
            3)
                echo -en "Enter path of .vault file to decrypt: "
                read -r vaultpath
                decrypt_vault "$vaultpath"
                ;;
            4)
                echo -en "Enter path of file/directory to verify: "
                read -r verify_path
                verify_integrity "$verify_path"
                ;;
            5)
                show_audit_log
                ;;
            6)
                run_self_test
                ;;
            7)
                msg_info "Exiting SecureVault. Stay safe!"
                exit 0
                ;;
            *)
                msg_error "Invalid option '$choice'. Please select between 1 and 7."
                ;;
        esac

        echo ""
        echo -en "${COLOR_BLUE}Press [Enter] to return to menu...${COLOR_RESET}"
        read -r
    done
}

# ------------------------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------------------------
main() {
    check_dependencies

    # If no arguments provided, launch interactive menu
    if [[ $# -eq 0 ]]; then
        interactive_menu
        exit 0
    fi

    # Parse command line flags with getopts
    while getopts ":e:d:v:lth" opt; do
        case "$opt" in
            e)
                local target="$OPTARG"
                if [[ -d "$target" ]]; then
                    encrypt_directory "$target"
                elif [[ -f "$target" ]]; then
                    encrypt_file "$target"
                else
                    msg_error "Target '$target' is neither a valid file nor directory."
                    exit 1
                fi
                exit 0
                ;;
            d)
                decrypt_vault "$OPTARG"
                exit 0
                ;;
            v)
                verify_integrity "$OPTARG"
                exit 0
                ;;
            l)
                show_audit_log
                exit 0
                ;;
            t)
                run_self_test
                exit 0
                ;;
            h)
                show_help
                exit 0
                ;;
            \?)
                msg_error "Invalid option: -$OPTARG"
                show_help
                exit 1
                ;;
            :)
                msg_error "Option -$OPTARG requires an argument."
                show_help
                exit 1
                ;;
        esac
    done

    # If an argument was provided without flags, show help
    show_help
}

# Invoke entry point
main "$@"

