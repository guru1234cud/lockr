#!/usr/bin/env bash
# End-to-end test suite for Lockr.
# Runs against a live production server.
#
# Usage:
#   LOCKR_TOKEN=lkat_... ./test/e2e.sh
#
# Optional env vars:
#   LOCKR_ADDR   — server address (default: https://localhost:8300)
#   LOCKR_CA     — path to CA cert (default: /etc/lockr/tls/ca.crt)
#   LOCKR_TOKEN  — admin token (required)
#   LOCKR_BIN    — path to lockr binary (default: ./lockr)

set -uo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

ADDR="${LOCKR_ADDR:-https://localhost:8300}"
CA="${LOCKR_CA:-/etc/lockr/tls/ca.crt}"
ADMIN_TOKEN="${LOCKR_TOKEN:-}"
BIN="${LOCKR_BIN:-./lockr}"

# Test identities — prefixed to avoid clashing with real data
USER_RO="e2e-alice"
USER_RW="e2e-bob"
SVC_NAME="e2e-svc"
SECRET_PATH="e2e/test/db-password"
SECRET_VAL='{"password":"s3cr3t-test-value"}'
SECRET_VAL_UPDATED='{"password":"updated-test-value"}'

TMPDIR_E2E=$(mktemp -d)
SVC_KEY_FILE="$TMPDIR_E2E/$SVC_NAME.key"

PASS=0
FAIL=0
declare -a FAILURES=()

# ── Colors ────────────────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────

pass() {
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}✓${NC} $1"
}

fail() {
    FAIL=$((FAIL + 1))
    FAILURES+=("$1")
    echo -e "  ${RED}✗${NC} $1"
}

section() {
    echo ""
    echo -e "${BOLD}── $1 ──${NC}"
}

# Run a lockr command with shared flags. Exits 0 on success, non-zero on error.
L() {
    "$BIN" "$@" --addr "$ADDR" --ca "$CA" 2>&1
}

# Admin-authed command.
LA() {
    L "$@" --token "$ADMIN_TOKEN"
}

# Service command — clears LOCKR_TOKEN so Ed25519/key auth is used, not the env token.
L_SVC() {
    LOCKR_TOKEN="" "$BIN" "$@" --addr "$ADDR" --ca "$CA" 2>&1
}

# Expect a command to succeed.
expect_ok() {
    local desc="$1"; shift
    if L "$@" > /dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc (expected success, got failure)"
    fi
}

# Expect a command to fail (e.g. permission denied).
expect_fail() {
    local desc="$1"; shift
    if L "$@" > /dev/null 2>&1; then
        fail "$desc (expected failure, got success)"
    else
        pass "$desc"
    fi
}

# Expect an admin command to succeed.
expect_admin_ok() {
    local desc="$1"; shift
    if LA "$@" > /dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc (expected success, got failure)"
    fi
}

# Run a command and capture output, return output.
capture() {
    L "$@" 2>&1
}

capture_admin() {
    LA "$@" 2>&1
}

# ── Cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    section "Cleanup"
    LA user delete --username "$USER_RO"  > /dev/null 2>&1 && echo "  removed user $USER_RO"  || true
    LA user delete --username "$USER_RW"  > /dev/null 2>&1 && echo "  removed user $USER_RW"  || true
    LA revoke --service "$SVC_NAME"       > /dev/null 2>&1 && echo "  revoked service $SVC_NAME" || true
    LA delete "$SECRET_PATH"              > /dev/null 2>&1 && echo "  deleted test secret"    || true
    rm -rf "$TMPDIR_E2E"
}

trap cleanup EXIT

# ── Preflight ─────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}Lockr E2E Test Suite${NC}"
echo -e "Server : $ADDR"
echo -e "CA     : $CA"
echo -e "Binary : $BIN"

if [[ -z "$ADMIN_TOKEN" ]]; then
    echo -e "${RED}Error: LOCKR_TOKEN is required.${NC}"
    echo "  export LOCKR_TOKEN=lkat_..."
    exit 1
fi

if [[ ! -f "$BIN" ]]; then
    echo -e "${RED}Error: binary not found at $BIN${NC}"
    exit 1
fi

if [[ ! -f "$CA" ]]; then
    echo -e "${RED}Error: CA cert not found at $CA${NC}"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}Warning: jq not found — value assertions will be skipped${NC}"
    HAS_JQ=false
else
    HAS_JQ=true
fi

# ── Tests ─────────────────────────────────────────────────────────────────────

section "1. Health Check"

if L status | grep -q "ok"; then
    pass "server is healthy"
else
    echo -e "${RED}Server is not reachable. Aborting.${NC}"
    exit 1
fi

# ── User System ───────────────────────────────────────────────────────────────

section "2. Create Users"

expect_admin_ok "create readonly user ($USER_RO)" \
    user create --username "$USER_RO" --password "ro-pass-123" --policy readonly

expect_admin_ok "create readwrite user ($USER_RW)" \
    user create --username "$USER_RW" --password "rw-pass-123" --policy readwrite

# Duplicate should fail
if LA user create --username "$USER_RO" --password "x" --policy readonly > /dev/null 2>&1; then
    fail "duplicate user create should fail"
else
    pass "duplicate user create correctly rejected"
fi

section "3. List Users"

USER_LIST=$(capture_admin user list)
if echo "$USER_LIST" | grep -q "$USER_RO" && echo "$USER_LIST" | grep -q "$USER_RW"; then
    pass "both users appear in list"
else
    fail "user list missing expected users"
fi

section "4. User Login"

RO_TOKEN=$(L login --username "$USER_RO" --password "ro-pass-123" 2>/dev/null | grep "^lvt_" || true)
if [[ -n "$RO_TOKEN" ]]; then
    pass "readonly user login returns lvt_ token"
else
    fail "readonly user login failed"
    RO_TOKEN=""
fi

RW_TOKEN=$(L login --username "$USER_RW" --password "rw-pass-123" 2>/dev/null | grep "^lvt_" || true)
if [[ -n "$RW_TOKEN" ]]; then
    pass "readwrite user login returns lvt_ token"
else
    fail "readwrite user login failed"
    RW_TOKEN=""
fi

# Wrong password must fail
if L login --username "$USER_RO" --password "wrongpassword" > /dev/null 2>&1; then
    fail "login with wrong password should fail"
else
    pass "login with wrong password correctly rejected"
fi

# Wrong username must fail
if L login --username "nobody" --password "anything" > /dev/null 2>&1; then
    fail "login with unknown user should fail"
else
    pass "login with unknown username correctly rejected"
fi

# ── KV Secrets ────────────────────────────────────────────────────────────────

section "5. Write Secret (as admin)"

expect_admin_ok "admin writes test secret" \
    set "$SECRET_PATH" "$SECRET_VAL"

section "6. Read Permissions"

if [[ -n "$RO_TOKEN" ]]; then
    # Readonly user can read
    if L get "$SECRET_PATH" --token "$RO_TOKEN" > /dev/null 2>&1; then
        pass "readonly user can read secret"
    else
        fail "readonly user should be able to read secret"
    fi

    # Readonly user cannot write
    if L set "$SECRET_PATH" "$SECRET_VAL_UPDATED" --token "$RO_TOKEN" > /dev/null 2>&1; then
        fail "readonly user should NOT be able to write secret"
    else
        pass "readonly user correctly denied write"
    fi

    # Readonly user cannot delete
    if L delete "$SECRET_PATH" --token "$RO_TOKEN" > /dev/null 2>&1; then
        fail "readonly user should NOT be able to delete secret"
    else
        pass "readonly user correctly denied delete"
    fi
else
    fail "skipped read permission tests (no RO token)"
    fail "skipped write denial test (no RO token)"
    fail "skipped delete denial test (no RO token)"
fi

section "7. Write Permissions"

if [[ -n "$RW_TOKEN" ]]; then
    # Readwrite user can read
    if L get "$SECRET_PATH" --token "$RW_TOKEN" > /dev/null 2>&1; then
        pass "readwrite user can read secret"
    else
        fail "readwrite user should be able to read secret"
    fi

    # Readwrite user can write
    if L set "$SECRET_PATH" "$SECRET_VAL_UPDATED" --token "$RW_TOKEN" > /dev/null 2>&1; then
        pass "readwrite user can write secret"
    else
        fail "readwrite user should be able to write secret"
    fi

    # Verify value was actually updated — text mode prints data directly, value is nested
    if [[ "$HAS_JQ" == true ]]; then
        FETCHED=$(L get "$SECRET_PATH" --token "$RW_TOKEN" 2>/dev/null \
            | jq -r '.value.password // ""' 2>/dev/null || true)
        if [[ "$FETCHED" == "updated-test-value" ]]; then
            pass "secret value matches what was written"
        else
            fail "secret value mismatch (got: $FETCHED)"
        fi
    fi
else
    fail "skipped write permission tests (no RW token)"
fi

# ── Service Auth ──────────────────────────────────────────────────────────────

section "8. Service Enrollment"

ENROLL_OUT=$(LA enroll --service "$SVC_NAME" --policy readwrite 2>/dev/null || true)
if echo "$ENROLL_OUT" | grep -q "private_key"; then
    pass "service enrolled successfully"

    if [[ "$HAS_JQ" == true ]]; then
        PRIV_KEY=$(echo "$ENROLL_OUT" | jq -r '.private_key // ""' 2>/dev/null || true)
        if [[ -n "$PRIV_KEY" ]]; then
            echo "$PRIV_KEY" > "$SVC_KEY_FILE"
            chmod 600 "$SVC_KEY_FILE"
            pass "service private key saved"
        else
            fail "could not extract private key from enroll response"
        fi
    else
        fail "skipped key extraction (jq not available)"
    fi
else
    fail "service enrollment failed"
fi

section "9. Service Authentication and Access"

if [[ -f "$SVC_KEY_FILE" ]]; then
    # Service can read
    if L_SVC get "$SECRET_PATH" --identity "$SVC_NAME" --key "$SVC_KEY_FILE" > /dev/null 2>&1; then
        pass "service can read secret via Ed25519 auth"
    else
        fail "service should be able to read secret"
    fi

    # Service can write
    if L_SVC set "$SECRET_PATH" "$SECRET_VAL" --identity "$SVC_NAME" --key "$SVC_KEY_FILE" > /dev/null 2>&1; then
        pass "service can write secret via Ed25519 auth"
    else
        fail "service should be able to write secret"
    fi

    # Revoked service cannot access
    LA revoke --service "$SVC_NAME" > /dev/null 2>&1
    if L_SVC get "$SECRET_PATH" --identity "$SVC_NAME" --key "$SVC_KEY_FILE" > /dev/null 2>&1; then
        fail "revoked service should NOT be able to authenticate"
    else
        pass "revoked service correctly denied"
    fi
else
    fail "skipped service auth tests (no key file)"
    fail "skipped service write test (no key file)"
    fail "skipped revoke test (no key file)"
fi

# ── User Management ───────────────────────────────────────────────────────────

section "10. Change User Policy"

expect_admin_ok "change $USER_RO policy to readwrite" \
    user set-policy --username "$USER_RO" --policy readwrite

# Re-login to get new session with updated policy
RO_TOKEN_NEW=$(L login --username "$USER_RO" --password "ro-pass-123" 2>/dev/null | grep "^lvt_" || true)
if [[ -n "$RO_TOKEN_NEW" ]]; then
    if L set "$SECRET_PATH" "$SECRET_VAL_UPDATED" --token "$RO_TOKEN_NEW" > /dev/null 2>&1; then
        pass "$USER_RO can write after policy upgrade to readwrite"
    else
        fail "$USER_RO should be able to write after policy upgrade"
    fi
else
    fail "could not re-login after policy change"
fi

section "11. Reset Password"

expect_admin_ok "reset $USER_RO password" \
    user reset-password --username "$USER_RO" --password "new-pass-456"

# Old password must fail
if L login --username "$USER_RO" --password "ro-pass-123" > /dev/null 2>&1; then
    fail "old password should not work after reset"
else
    pass "old password correctly rejected after reset"
fi

# New password must work
NEW_TOKEN=$(L login --username "$USER_RO" --password "new-pass-456" 2>/dev/null | grep "^lvt_" || true)
if [[ -n "$NEW_TOKEN" ]]; then
    pass "new password works after reset"
else
    fail "new password should work after reset"
fi

section "12. Delete User"

expect_admin_ok "delete user $USER_RO" \
    user delete --username "$USER_RO"

if L login --username "$USER_RO" --password "new-pass-456" > /dev/null 2>&1; then
    fail "deleted user should not be able to login"
else
    pass "deleted user correctly rejected"
fi

# ── Audit Log ─────────────────────────────────────────────────────────────────

section "13. Audit Log"

AUDIT_OUT=$(LA audit --limit 50 2>/dev/null || true)
if echo "$AUDIT_OUT" | grep -q "e2e"; then
    pass "audit log contains e2e test entries"
else
    fail "audit log should contain e2e entries"
fi

if echo "$AUDIT_OUT" | grep -q "user:e2e"; then
    pass "audit log shows user: prefixed identities"
else
    fail "audit log should show user: prefixed identities"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}══════════════════════════════════════${NC}"
echo -e "${BOLD}Results: ${GREEN}$PASS passed${NC} / ${RED}$FAIL failed${NC}"
echo -e "${BOLD}══════════════════════════════════════${NC}"

if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""
    echo -e "${RED}Failed tests:${NC}"
    for f in "${FAILURES[@]}"; do
        echo "  - $f"
    done
fi

echo ""
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
