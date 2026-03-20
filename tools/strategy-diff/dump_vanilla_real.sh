#!/bin/bash
# Dump strategies by sourcing REAL vanilla blockcheck2.d scripts.
# Replaces pktws_curl_test_update with echo to capture all generated strategies.
#
# Usage: bash dump_vanilla_real.sh [http|tls12|tls13]

set +ue

PROTO="${1:-tls12}"
REFDIR="$(cd "$(dirname "$0")/../../reference/zapret2" && pwd)"
TESTDIR="$REFDIR/blockcheck2.d/standard"

# --- Stub pktws_curl_test_update: print strategy args, always "succeed" ---
# Returning 0 (success) preserves vanilla's early-exit optimizations:
# once a TTL works, higher TTLs are skipped (correct behavior).
pktws_curl_test_update() {
    # $1 = test function name (ignored)
    # $2 = domain (ignored)
    # $3... = nfqws2 args (what we want)
    shift 2
    echo "$*"
    return 0
}

# --- Import real helpers ---
contains() {
    [ "${1#*$2}" != "$1" ]
}

extract_arg() {
    local n=$1
    while [ -n "$1" ]; do
        shift
        [ $n -eq 1 ] && { echo "$1"; return 0; }
        n=$(($n-1))
    done
}

# --- Vanilla env ---
SCANLEVEL=force
IPV=4
IPVV=
MULTIDISORDER=multidisorder
TCP_MD5=tcp_md5
UNAME=Linux

# Need flags — force mode means "test everything", set all to 1
need_multisplit=1
need_multidisorder=1
need_fakedsplit=1
need_fakeddisorder=1
need_hostfakesplit=1
need_fake=1

# No custom patterns/fakes
FAKE_HTTP=
FAKE_HTTPS=
FAKED_PATTERN_HTTP=
FAKED_PATTERN_HTTPS=
SEQOVL_PATTERN_HTTP=
SEQOVL_PATTERN_HTTPS=
HOSTFAKE=

# --- Iterate all phase scripts in order ---
for script in "$TESTDIR/"*.sh; do
    basename="$(basename "$script")"

    # Skip quic for now
    [[ "$basename" == *quic* ]] && continue

    echo "# === $basename ==="

    # Source the script (it defines pktws_check_http, pktws_check_https_tls12, etc.)
    . "$script"

    # Call the right function based on protocol
    case "$PROTO" in
        http)
            if type pktws_check_http >/dev/null 2>&1; then
                pktws_check_http "curl_test_http" "example.com" 2>/dev/null || true
            fi
            ;;
        tls12)
            if type pktws_check_https_tls12 >/dev/null 2>&1; then
                pktws_check_https_tls12 "curl_test_https_tls12" "example.com" 2>/dev/null || true
            fi
            ;;
        tls13)
            if type pktws_check_https_tls13 >/dev/null 2>&1; then
                pktws_check_https_tls13 "curl_test_https_tls13" "example.com" 2>/dev/null || true
            fi
            ;;
    esac

    # Note: do NOT unset functions — later scripts may reuse helpers from earlier ones.
    # Also need_multisplit etc. carry over between phases (that's how vanilla works).
done
