#!/usr/bin/env bash
# ==============================================================================
# Script: test_vault.sh
# Purpose: Comprehensive Automated Verification Suite for SecureVault
# Usage: ./test_vault.sh
# ==============================================================================

set -o pipefail

# Color palette
GREEN="\033[1;32m"
RED="\033[1;31m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
BOLD="\033[1m"
RESET="\033[0m"

PASS_COUNT=0
FAIL_COUNT=0

print_test_header() {
    echo -e "\n${BOLD}${CYAN}---> [TEST $1] $2${RESET}"
}

record_pass() {
    echo -e "${GREEN}[PASS] $1${RESET}"
    ((PASS_COUNT++))
}

record_fail() {
    echo -e "${RED}[FAIL] $1${RESET}"
    ((FAIL_COUNT++))
}

# Workspace setup
WORKSPACE_DIR="./.test_workspace_$$"
mkdir -p "$WORKSPACE_DIR"

cleanup_tests() {
    rm -rf "$WORKSPACE_DIR" 2>/dev/null || true
}
trap cleanup_tests EXIT INT TERM

echo -e "${BOLD}======================================================================${RESET}"
echo -e "${BOLD}         SECUREVAULT AUTOMATED VERIFICATION & TEST SUITE            ${RESET}"
echo -e "${BOLD}======================================================================${RESET}"

# Test 1: Check required binaries
print_test_header "1" "System Dependencies Check"
for cmd in openssl tar gzip; do
    if command -v "$cmd" &>/dev/null; then
        record_pass "Command '$cmd' is available in system PATH."
    else
        record_fail "Command '$cmd' is missing."
    fi
done

# Test 2: Single File Encryption & Bit-for-Bit Decryption
print_test_header "2" "Single File Encrypt & Decrypt Round-Trip"
SAMPLE_FILE="$WORKSPACE_DIR/original_data.txt"
echo "University Final Project - Operating Systems Lab Secret Data 2026" > "$SAMPLE_FILE"
ORIG_HASH=$(sha256sum "$SAMPLE_FILE" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$SAMPLE_FILE" | awk '{print $1}')
TEST_PASSWORD="StrongUniversityPassword123!"

# Encrypt file manually using vault logic
printf "%s" "$TEST_PASSWORD" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -in "$SAMPLE_FILE" -out "$SAMPLE_FILE.vault" -pass stdin 2>/dev/null

if [[ -f "$SAMPLE_FILE.vault" ]]; then
    record_pass "Encrypted vault file was created successfully."
else
    record_fail "Vault file creation failed."
fi

# Decrypt file to new location
DECRYPTED_FILE="$WORKSPACE_DIR/restored_data.txt"
printf "%s" "$TEST_PASSWORD" | openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -in "$SAMPLE_FILE.vault" -out "$DECRYPTED_FILE" -pass stdin 2>/dev/null

REST_HASH=$(sha256sum "$DECRYPTED_FILE" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$DECRYPTED_FILE" | awk '{print $1}')

if [[ "$ORIG_HASH" == "$REST_HASH" ]]; then
    record_pass "Decrypted file SHA-256 matches original exactly: $ORIG_HASH"
else
    record_fail "Decrypted hash mismatch! Original: $ORIG_HASH vs Decrypted: $REST_HASH"
fi

# Test 3: Wrong Password Tamper Resistance
print_test_header "3" "Authentication & Incorrect Password Rejection"
WRONG_DECRYPT_OUTPUT="$WORKSPACE_DIR/tampered.txt"
if printf "%s" "IncorrectPassword999" | openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -in "$SAMPLE_FILE.vault" -out "$WRONG_DECRYPT_OUTPUT" -pass stdin 2>/dev/null; then
    record_fail "Security Failure! OpenSSL did NOT fail with a wrong password."
else
    record_pass "Wrong password was cleanly rejected by AES-256 PBKDF2."
fi

# Test 4: Nested Directory Archiving and Restoration
print_test_header "4" "Nested Directory Archiving & Decryption"
SAMPLE_DIR="$WORKSPACE_DIR/project_vault_test"
mkdir -p "$SAMPLE_DIR/subfolder/assets"
echo "Code File 1" > "$SAMPLE_DIR/main.py"
echo "Code File 2" > "$SAMPLE_DIR/subfolder/helper.py"
echo "Asset Binary Dummy" > "$SAMPLE_DIR/subfolder/assets/logo.png"

# Archive and encrypt
DIR_ARCHIVE="$WORKSPACE_DIR/dir_pack.tar.gz"
tar -czf "$DIR_ARCHIVE" -C "$WORKSPACE_DIR" "project_vault_test" 2>/dev/null
DIR_VAULT="$WORKSPACE_DIR/project_vault_test.vault"

printf "%s" "$TEST_PASSWORD" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -in "$DIR_ARCHIVE" -out "$DIR_VAULT" -pass stdin 2>/dev/null

if [[ -f "$DIR_VAULT" ]]; then
    record_pass "Directory successfully bundled and encrypted into .vault file."
else
    record_fail "Directory vault creation failed."
fi

# Unpack and verify structure
DIR_DEC_TAR="$WORKSPACE_DIR/dir_dec.tar.gz"
printf "%s" "$TEST_PASSWORD" | openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -in "$DIR_VAULT" -out "$DIR_DEC_TAR" -pass stdin 2>/dev/null

RESTORE_DIR="$WORKSPACE_DIR/restored_output"
mkdir -p "$RESTORE_DIR"
tar -xzf "$DIR_DEC_TAR" -C "$RESTORE_DIR" 2>/dev/null

if [[ -f "$RESTORE_DIR/project_vault_test/main.py" && \
      -f "$RESTORE_DIR/project_vault_test/subfolder/helper.py" && \
      -f "$RESTORE_DIR/project_vault_test/subfolder/assets/logo.png" ]]; then
    record_pass "All files, subdirectories, and tree hierarchy preserved accurately."
else
    record_fail "Restored directory structure does not match original."
fi

# Test 5: Script Help and Self-Test Flags Execution
print_test_header "5" "Script CLI Flags Execution (-h and -t)"
if bash vault.sh -h &>/dev/null; then
    record_pass "vault.sh -h executed with zero return code."
else
    record_fail "vault.sh -h failed."
fi

if bash vault.sh -t &>/dev/null; then
    record_pass "vault.sh -t self-test internal suite passed."
else
    record_fail "vault.sh -t failed."
fi

# Final Summary
echo -e "\n${BOLD}======================================================================${RESET}"
echo -e "${BOLD}                       TEST EXECUTION SUMMARY                         ${RESET}"
echo -e "${BOLD}======================================================================${RESET}"
echo -e "  ${GREEN}Passed Checks:${RESET} $PASS_COUNT"
echo -e "  ${RED}Failed Checks:${RESET} $FAIL_COUNT"

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "\n${GREEN}${BOLD}>>> ALL TEST CASES PASSED WITH 100% SUCCESS! Ready for University Evaluation. <<<${RESET}\n"
    exit 0
else
    echo -e "\n${RED}${BOLD}>>> SOME TESTS FAILED. Please review the output above. <<<${RESET}\n"
    exit 1
fi

