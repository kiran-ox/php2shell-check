#!/bin/sh
# php2shell-check.sh: read-only checker for PHP2Shell
# (CVE-2026-109618, CVE-2026-109619) on Linux, macOS, BSD and containers.
#
# It answers three questions separately: is a vulnerable PHP build present,
# is it serving web traffic (and is the running code the patched code), and
# are there signs of exploitation? The detection logic is in docs/SPEC.md.
#
# Safety: it never modifies the system, never uses the network, never runs
# the PHP binaries it finds unless --exec is given, and never prints file
# contents (only paths, counts and short log lines).
#
# SPDX-License-Identifier: Apache-2.0

TOOL_VERSION=1.0.0

# BEGIN PHP2SHELL DATA (mirrors data/php2shell.json; tests/run.sh checks they match)
DATA_VERSION=2026-10-21.1
FIXED_8_2=8.2.35
FIXED_8_3=8.3.36
FIXED_8_4=8.4.27
FIXED_8_5=8.5.12
FINGERPRINT='Hard memory limit of '
FINGERPRINT_ALT='memory_hard_limit_percent'
CVE_LIST='CVE-2026-109618 CVE-2026-109619'
CVE_RE='CVE-2026-10961[89]'
DEFAULT_SINCE=2026-10-20
# Vendor backports, one per line: os_id|os_version_id|package|fixed_package_version
VENDOR_BACKPORTS=''
# END PHP2SHELL DATA

# Everything up to the PHP2SHELL_SOURCE_ONLY line only defines functions and
# default values, so tests can source this file and call the functions.
LC_ALL=C
export LC_ALL

TAB=$(printf '\t')
NL='
'
# Field separator of every internal record file: ASCII unit separator. TAB is
# IFS whitespace, so "IFS=<TAB> read" would collapse empty fields.
SEP=$(printf '\037')

# ---------------------------------------------------------------- options --

OPT_JSON=0
OPT_JSON_FILE=''
OPT_SINCE=$DEFAULT_SINCE
OPT_SKIP_IOC=0
OPT_SKIP_CONTAINERS=0
OPT_DEEP=0
OPT_EXEC=0
OPT_ROOT=''
OPT_NO_COLOR=0
OPT_QUIET=0
OPT_WEBROOTS=''
SINCE_NUM=$(printf '%s' "$DEFAULT_SINCE" | tr -d '-')

# Test hooks: a fake /proc and a fake host filesystem root.
PROC=${PHP2SHELL_PROC:-/proc}
HOSTROOT=${PHP2SHELL_HOSTROOT:-}

# Working directory for record files; the main section replaces it with mktemp.
TMPD=${TMPD:-/nonexistent/php2shell-check}
COV_LIMITED=0
# 1 when running processes could not be inspected at all (no Linux /proc).
PROC_UNCHECKED=0
PROC_MODE=none

# Report values, filled in by the main section.
C_RED=''; C_GRN=''; C_YEL=''; C_BLD=''; C_DIM=''; C_OFF=''
R_HOST=''; R_OS=''; R_ISROOT=no; R_WHEN=''; R_PLATFORM=''; R_VERDICT=INCOMPLETE
R_N=0; R_VULN=0; R_FIXED=0; R_UNKNOWN=0; R_RESTART=0; R_HIGH=0; R_REVIEW=0; R_EXIT=0

usage() {
    cat <<'EOF'
Usage: php2shell-check.sh [options]

Checks this machine and its running containers for PHP builds affected by
PHP2Shell (CVE-2026-109618, CVE-2026-109619) and for signs of exploitation.
Read-only: it changes nothing and sends nothing anywhere.

Options:
  --json              Print the JSON report instead of the text report
  --json-file FILE    Also write the JSON report to FILE
  --since YYYY-MM-DD  Start of the compromise-triage window (default 2026-10-20)
  --skip-ioc          Only check for vulnerable PHP; skip compromise triage
  --skip-containers   Don't look inside running containers
  --deep              Search the whole filesystem for PHP builds (slower)
  --webroot DIR       Add a web root to inspect (repeatable)
  --root DIR          Offline mode: inspect a mounted disk or extracted image
  --exec              Allow running discovered PHP binaries (-i) for config details
  --no-color          Disable colours (NO_COLOR is honoured too)
  -q, --quiet         Text report: print only the verdict and next steps
  -h, --help          Show this help
  --version           Show the tool and data versions

Exit codes, added together: 1 vulnerable PHP found, 2 incomplete check,
4 high-severity compromise indicators, 64 usage error. 0 means nothing
vulnerable was found and there were no strong indicators.
Run as root for full coverage.
EOF
}

die_usage() {
    printf 'php2shell-check: %s\n\n' "$1" >&2
    usage >&2
    exit 64
}

# ---------------------------------------------------------------- helpers --

have() { command -v "$1" >/dev/null 2>&1; }

# BusyBox grep has no -a; pass it only where it is understood.
if printf 'x\n' | grep -a -q x 2>/dev/null; then GREP_A=-a; else GREP_A=''; fi

# Replace every control character (tabs, newlines, the record separator,
# ESC and the rest of C0, DEL) with a space, so a value fits in one field and
# attacker-chosen names cannot send terminal escape sequences to the report.
clean() { printf '%s' "$1" | tr '\001-\037\177' ' '; }

# Limited coverage (exit bit 2). Also recorded in a file, because many
# callers run in pipeline subshells.
set_limited() { COV_LIMITED=1; : > "$TMPD/limited"; }

# redact_cmd < command line: hide values that look like secrets (passwords,
# tokens, keys, URL credentials) before a command line goes into the report.
redact_cmd() {
    awk -v q="'" '{
        n = split($0, w, " "); out = ""; prev = ""; hdr = 0
        my = ($0 ~ /mysql|mariadb/); sp = ($0 ~ /sshpass/); rd = ($0 ~ /redis-cli/)
        for (i = 1; i <= n; i++) {
            x = w[i]; lx = tolower(x); t = lx; gsub("^[\"" q "]+", "", t)
            if (hdr) {
                # Value of a secret header: keep an auth scheme word, hide the credential.
                if (t ~ /^(bearer|basic|token|digest|negotiate)$/) { out = out (i > 1 ? " " : "") x; continue }
                x = "***"; hdr = 0
            }
            else if (prev ~ /^-+(pass|passwd|password|pwd|token|secret|key|apikey|api-key|api_key|auth|auth-token)$/) x = "***"
            else if ((sp && prev == "-p") || (rd && prev == "-a")) x = "***"
            else if ((prev == "-u" || prev == "--user") && index(x, ":")) x = substr(x, 1, index(x, ":")) "***"
            else if (my && lx ~ /^-p[^ ]/) x = "-p***"
            else if (t ~ /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token|token|password|secret):$/) hdr = 1
            else if (match(lx, /(pass(word|wd)?|pwd|token|secret|key|auth)[a-z0-9_.-]*[=:]/)) x = substr(x, 1, RSTART + RLENGTH - 1) "***"
            # Credentials in a URL: user:pass@ or token@.
            if (match(x, /:\/\/[^\/@ ]+@/)) x = substr(x, 1, RSTART + 2) "***@" substr(x, RSTART + RLENGTH)
            out = out (i > 1 ? " " : "") x; prev = lx
        }
        print out
    }'
}

# trunc N < line: the first N bytes, without a UTF-8 sequence cut in half.
trunc() { awk -v n="$1" '{ s = substr($0, 1, n); if (length($0) > n) sub(/[\300-\377][\200-\277]*$/, "", s); print s }'; }

# rec FIELD...: print one record, the fields joined with SEP.
rec() {
    REC_OUT=$1
    shift
    for REC_F in "$@"; do REC_OUT="$REC_OUT$SEP$REC_F"; done
    printf '%s\n' "$REC_OUT"
}

# strip_root ROOT < paths: remove a literal ROOT prefix from each line. ROOT
# may contain regex characters or "|", so this is not done with sed.
strip_root() {
    P2S_STRIP=$1 awk 'BEGIN { r = ENVIRON["P2S_STRIP"]; n = length(r) }
        { if (n > 0 && index($0, r) == 1) print substr($0, n + 1); else print }'
}

# run_limited CMD...: run a discovered binary with no stdin, under a timeout.
run_limited() {
    if have timeout; then
        timeout 10 "$@" < /dev/null
    else
        "$@" < /dev/null
    fi
}

add_cov() { clean "$1" >> "$TMPD/cov.txt"; printf '\n' >> "$TMPD/cov.txt"; }

# add_finding SEVERITY CATEGORY TITLE LOCATION COUNT DETAIL
add_finding() {
    rec "$1" "$2" "$(clean "$3")" "$(clean "$4")" "${5:-0}" "$(clean "${6:-}")" >> "$TMPD/find.tsv"
}

if stat -c %Y / >/dev/null 2>&1; then
    mtime() { stat -c %Y "$1" 2>/dev/null; }
    file_id() { stat -L -c '%d:%i' "$1" 2>/dev/null; }
else
    mtime() { stat -f %m "$1" 2>/dev/null; }
    file_id() { stat -L -f '%d:%i' "$1" 2>/dev/null; }
fi
# file_dev PATH: the device the path (followed if a symlink) lives on.
file_dev() { FD_ID=$(file_id "$1"); printf '%s' "${FD_ID%%:*}"; }

# start_path ROOT PATH: sets START_P to where a search of PATH inside ROOT
# should start. find does not descend into a symlinked start point without
# -H, and -H would resolve an absolute target such as /opt -> /data/opt in
# the scanner's own filesystem instead of ROOT, so such links are resolved
# against ROOT here.
start_path() {
    START_P="$1$2"
    if [ -n "$1" ] && [ -h "$START_P" ]; then
        # A relative target already resolves inside ROOT (find -H follows it).
        SPT_T=$(readlink "$START_P" 2>/dev/null)
        case $SPT_T in /*) START_P="$1$SPT_T" ;; esac
    fi
}

# is_php_sapi_name BASENAME: exactly the name of a PHP SAPI binary or module
# (php-fpm8.3, php83, php-8.3, libphp.so ...), not tools such as
# php-fpm_exporter or php-fpm-healthcheck.
is_php_sapi_name() {
    printf '%s\n' "$1" | grep -q -x -E 'php|php-cli|php-fpm|php-cgi|phpdbg|lsphp|frankenphp|(php|php-|php-fpm|php-cgi|phpdbg|lsphp)[0-9][0-9.]*|php[0-9][0-9.]*-(fpm|cgi)|(libphp[0-9.]*|mod_php[0-9]*)\.so(\.[0-9.]+)?'
}

# First four bytes as hex, to recognise ELF and Mach-O executables.
magic_of() { dd if="$1" bs=4 count=1 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n'; }

is_native_binary() {
    case $(magic_of "$1") in
        7f454c46|cffaedfe|cefaedfe|cafebabe|feedfacf|feedface) return 0 ;;
    esac
    return 1
}

# scan_binary FILE: sets SB_VERSION (PHP_VERSION baked into the build) and
# SB_FP (yes when the build carries the fix's patch fingerprint). The file is
# read as bytes, never executed.
scan_binary() {
    SB_VERSION=''
    SB_FP=no
    # Keep only the characters the searched strings use, given as an explicit
    # set: BusyBox tr's [:print:] (and its -c -s handling) differs from GNU and
    # BSD tr and split "X-Powered-By: PHP/x.y.z" apart on Alpine. \055 is "-".
    SB_OUT=$(tr -c 'A-Za-z0-9 ./:%+~_\055' '\n' 2>/dev/null < "$1" |
        grep -o -E "X-Powered-By: PHP/[0-9][0-9A-Za-z.+~_-]*|$FINGERPRINT|$FINGERPRINT_ALT" 2>/dev/null |
        sort -u)
    [ -n "$SB_OUT" ] || return 1
    SB_VERSION=$(printf '%s\n' "$SB_OUT" | sed -n 's|^X-Powered-By: PHP/||p' | head -n 1)
    case $SB_OUT in
        *"$FINGERPRINT"*|*"$FINGERPRINT_ALT"*) SB_FP=yes ;;
    esac
    [ -n "$SB_VERSION" ]
}

os_field() {  # os_field ROOT FIELD -> value from ROOT/etc/os-release
    sed -n "s/^$2=//p" "$1/etc/os-release" 2>/dev/null | head -n 1 | tr -d '"'
}

# --------------------------------------------------------------- versions --

# parse_version V: sets VP_MAJ VP_MIN VP_PAT VP_SUF and VP_KIND
# (release | pre | vendor). Returns 1 if V is not x.y.z[suffix].
parse_version() {
    VP_T=$(printf '%s' "$1" | sed -n 's/^\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\)\(.*\)$/\1 \2 \3 \4/p')
    [ -n "$VP_T" ] || return 1
    VP_MAJ=${VP_T%% *}; VP_T=${VP_T#* }
    VP_MIN=${VP_T%% *}; VP_T=${VP_T#* }
    VP_PAT=${VP_T%% *}
    VP_SUF=${VP_T#"$VP_PAT"}; VP_SUF=${VP_SUF# }
    case $(printf '%s' "$VP_SUF" | tr 'A-Z' 'a-z') in
        '') VP_KIND=release ;;
        dev|-dev|alpha*|-alpha*|beta*|-beta*|rc*|-rc*) VP_KIND=pre ;;
        *) VP_KIND=vendor ;;
    esac
    return 0
}

# ver_lt A B: true when upstream version A sorts before release B.
ver_lt() {
    parse_version "$2" || return 1
    VL_MAJ=$VP_MAJ; VL_MIN=$VP_MIN; VL_PAT=$VP_PAT
    parse_version "$1" || return 1
    [ "$VP_MAJ" -lt "$VL_MAJ" ] && return 0
    [ "$VP_MAJ" -gt "$VL_MAJ" ] && return 1
    [ "$VP_MIN" -lt "$VL_MIN" ] && return 0
    [ "$VP_MIN" -gt "$VL_MIN" ] && return 1
    [ "$VP_PAT" -lt "$VL_PAT" ] && return 0
    [ "$VP_PAT" -gt "$VL_PAT" ] && return 1
    [ "$VP_KIND" = pre ]
}

# classify_branch: uses VP_* from parse_version; sets BR BR_STATUS BR_FIXED.
classify_branch() {
    BR="$VP_MAJ.$VP_MIN"
    BR_FIXED=''
    if [ "$VP_MAJ" -lt 8 ]; then
        BR_STATUS=eol
    elif [ "$VP_MAJ" -gt 8 ]; then
        BR_STATUS=newer
    else
        case $VP_MIN in
            0|1) BR_STATUS=eol ;;
            2) BR_STATUS=supported; BR_FIXED=$FIXED_8_2 ;;
            3) BR_STATUS=supported; BR_FIXED=$FIXED_8_3 ;;
            4) BR_STATUS=supported; BR_FIXED=$FIXED_8_4 ;;
            5) BR_STATUS=supported; BR_FIXED=$FIXED_8_5 ;;
            # 8.6 pre-releases and master (8.7.0-dev) do not have the fix yet.
            6|7) if [ "$VP_KIND" = pre ]; then BR_STATUS=prerelease; else BR_STATUS=newer; fi ;;
            *) BR_STATUS=newer ;;
        esac
    fi
}

# decide VERSION FINGERPRINT CHANGELOG VENDORDATA BACKPORTER
#   FINGERPRINT yes|no; CHANGELOG yes|no|unavailable|n/a; VENDORDATA yes|no;
#   BACKPORTER yes when the package comes from a vendor that backports fixes.
# Sets VD_VERDICT VD_EVIDENCE VD_REASON VD_REMEDIATION VD_BRANCH VD_BSTATUS
# VD_FIXED, following the evidence order in docs/SPEC.md section 3.
decide() {
    VD_VERDICT=UNKNOWN; VD_EVIDENCE=none; VD_REASON=''; VD_REMEDIATION=''
    VD_BRANCH=''; VD_BSTATUS=unknown; VD_FIXED=''
    if [ -z "$1" ] || ! parse_version "$1"; then
        VD_REASON=version-unreadable
        VD_REMEDIATION="Could not read the PHP version from this file: run it with -v and compare against 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12"
        return 0
    fi
    classify_branch
    VD_BRANCH=$BR; VD_BSTATUS=$BR_STATUS; VD_FIXED=$BR_FIXED
    if [ "$2" = yes ]; then
        VD_VERDICT=FIXED; VD_EVIDENCE=fingerprint; VD_REASON=patch-fingerprint-present
        return 0
    fi
    if [ "$BR_STATUS" = supported ] && ! ver_lt "$1" "$BR_FIXED"; then
        VD_VERDICT=FIXED; VD_EVIDENCE=version; VD_REASON=at-or-above-fixed-version,fingerprint-missing
        return 0
    fi
    if [ "$3" = yes ]; then
        VD_VERDICT=FIXED; VD_EVIDENCE=changelog; VD_REASON=vendor-changelog-names-cve
        return 0
    fi
    if [ "$4" = yes ]; then
        VD_VERDICT=FIXED; VD_EVIDENCE=vendor-data; VD_REASON=vendor-fixed-package-version
        return 0
    fi
    case $BR_STATUS in
        eol)
            VD_VERDICT=VULNERABLE; VD_REASON=eol-no-upstream-fix
            VD_REMEDIATION="PHP $BR is end-of-life and gets no fix from PHP: upgrade to a supported branch (8.3 or later recommended; 8.2 security support ends 2026-12-31) or install a vendor backport, then restart every PHP worker" ;;
        prerelease)
            VD_VERDICT=VULNERABLE; VD_REASON=prerelease-unpatched
            VD_REMEDIATION="Pre-release build without the fix: move to a patched stable release (8.5.12 or later)" ;;
        newer)
            VD_VERDICT=UNKNOWN; VD_REASON=branch-newer-than-data
            VD_REMEDIATION="PHP $BR is newer than this tool's data and has no patch fingerprint: update php2shell-check or check the PHP release notes" ;;
        *)
            VD_VERDICT=VULNERABLE; VD_REASON=below-fixed-version
            VD_REMEDIATION="Upgrade to PHP $BR_FIXED or later, then restart every PHP worker" ;;
    esac
    if [ "$VD_VERDICT" = VULNERABLE ] && [ "$5" = yes ]; then
        VD_REASON="$VD_REASON,vendor-may-backport"
        VD_REMEDIATION="$VD_REMEDIATION. This is a distribution build: install your vendor's patched package if one exists"
        [ "$3" = unavailable ] && VD_REMEDIATION="$VD_REMEDIATION (the package changelog was not available to check)"
    fi
    return 0
}

# sapi_of_name BASENAME: guess the SAPI from a file or process name.
sapi_of_name() {
    case $1 in
        php-fpm*|php[0-9]*-fpm*|php*fpm) printf 'fpm' ;;
        php-cgi*|php[0-9]*-cgi*) printf 'cgi' ;;
        lsphp*) printf 'litespeed' ;;
        frankenphp*) printf 'frankenphp' ;;
        phpdbg*) printf 'phpdbg' ;;
        libphp*|mod_php*) printf 'mod_php' ;;
        php|php[0-9]*|php-[0-9]*|php-cli) printf 'cli' ;;
        *) printf 'unknown' ;;
    esac
}

# sapi_of_path PATH: like sapi_of_name, but Debian's CGI binary
# /usr/lib/cgi-bin/phpX.Y is named like the CLI.
sapi_of_path() {
    case $1 in
        */cgi-bin/php*) printf 'cgi' ;;
        *) sapi_of_name "${1##*/}" ;;
    esac
}

exposure_of() {
    case $1 in
        mod_php) printf 'highest' ;;
        frankenphp|fpm) printf 'high' ;;
        litespeed|cgi|embed) printf 'elevated' ;;
        *) printf 'low' ;;
    esac
}

# --------------------------------------------------------------- packages --

# Native version comparison for vendor package versions: vercmp_ge A B.
vercmp_ge() {
    # Versions come from the scanned package database; never pass anything
    # but version characters to rpm's Lua evaluator.
    case "$2$3" in *[!A-Za-z0-9.+~:_-]*) return 1 ;; esac
    case $1 in
        dpkg) have dpkg && dpkg --compare-versions "$2" ge "$3" < /dev/null ;;
        rpm) have rpm && [ "$(rpm --eval "%{lua: print(rpm.vercmp('$2', '$3'))}" < /dev/null 2>/dev/null)" -ge 0 ] 2>/dev/null ;;
        apk) have apk && case $(apk version -t "$2" "$3" < /dev/null 2>/dev/null) in '>'|'=') true ;; *) false ;; esac ;;
        *) false ;;
    esac
}

# vendor_data_hit ROOT MANAGER PACKAGE VERSION: rule 5 of the spec.
vendor_data_hit() {
    [ -n "$VENDOR_BACKPORTS" ] || return 1
    VH_ID=$(os_field "$1" ID)
    VH_VER=$(os_field "$1" VERSION_ID)
    VH_LINES=$(printf '%s\n' "$VENDOR_BACKPORTS" | awk -F'|' -v id="$VH_ID" -v ver="$VH_VER" -v pkg="$3" \
        '$1 == id && ($2 == ver || $2 == "*") && $3 == pkg { print $4 }')
    for VH_FIX in $VH_LINES; do
        vercmp_ge "$2" "$4" "$VH_FIX" && return 0
    done
    return 1
}

# pkg_lookup ROOT PATH: which package owns PATH inside ROOT?
# Sets PK_MGR PK_NAME PK_VER PK_ORIGIN PK_CHANGELOG PK_BACKPORTER.
pkg_lookup() {
    PK_MGR=none; PK_NAME=''; PK_VER=''; PK_ORIGIN=''; PK_CHANGELOG=n/a; PK_BACKPORTER=no
    PL_R=$1
    PL_P=$2
    if [ -d "$PL_R/var/lib/dpkg/info" ]; then
        PL_LIST=$(grep -l -x -F -e "$PL_P" "$PL_R"/var/lib/dpkg/info/*.list 2>/dev/null | head -n 1)
        if [ -n "$PL_LIST" ]; then
            PK_MGR=dpkg
            PK_NAME=${PL_LIST##*/}; PK_NAME=${PK_NAME%.list}; PK_NAME=${PK_NAME%%:*}
            PL_STAT=$(awk -v p="$PK_NAME" '
                /^Package: / { ok = ($2 == p); next }
                ok && /^Source: / { src = $2 }
                ok && /^Version: / { ver = $2 }
                /^$/ { if (ok && ver != "") { print ver "\t" src; exit } ok = 0 }
                END { if (ok && ver != "") print ver "\t" src }' "$PL_R/var/lib/dpkg/status" 2>/dev/null | head -n 1)
            PK_VER=${PL_STAT%%"$TAB"*}
            PL_SRC=${PL_STAT#*"$TAB"}
            [ -n "$PL_SRC" ] || PL_SRC=$PK_NAME
            case $PK_VER in
                *deb.sury.org*) PK_ORIGIN=sury ;;
                *ubuntu*|*esm*) PK_ORIGIN=ubuntu; PK_BACKPORTER=yes ;;
                *) PK_ORIGIN=$(os_field "$PL_R" ID); [ -n "$PK_ORIGIN" ] || PK_ORIGIN=debian
                   case $PK_ORIGIN in debian|ubuntu|raspbian|linuxmint|pop) PK_BACKPORTER=yes ;; esac ;;
            esac
            PK_CHANGELOG=unavailable
            for PL_C in "$PL_R/usr/share/doc/$PK_NAME"/changelog.Debian*.gz \
                        "$PL_R/usr/share/doc/$PL_SRC-common"/changelog.Debian*.gz \
                        "$PL_R/usr/share/doc/$PL_SRC"/changelog.Debian*.gz; do
                [ -f "$PL_C" ] || continue
                if gzip -dc "$PL_C" 2>/dev/null | grep -q -E "$CVE_RE"; then
                    PK_CHANGELOG=yes; break
                fi
                PK_CHANGELOG=no
            done
            return 0
        fi
    fi
    if [ -f "$PL_R/lib/apk/db/installed" ]; then
        PL_HIT=$(awk -v want="${PL_P#/}" '
            /^P:/ { p = substr($0, 3) } /^V:/ { v = substr($0, 3) } /^F:/ { f = substr($0, 3) }
            /^R:/ { if (f "/" substr($0, 3) == want) { print p "\t" v; exit } }
            /^$/ { p = ""; v = ""; f = "" }' "$PL_R/lib/apk/db/installed" 2>/dev/null)
        if [ -n "$PL_HIT" ]; then
            PK_MGR=apk; PK_NAME=${PL_HIT%%"$TAB"*}; PK_VER=${PL_HIT#*"$TAB"}
            PK_ORIGIN=$(os_field "$PL_R" ID); [ -n "$PK_ORIGIN" ] || PK_ORIGIN=alpine
            PK_CHANGELOG=unavailable
            return 0
        fi
    fi
    if have rpm && { [ -d "$PL_R/var/lib/rpm" ] || [ -d "$PL_R/usr/lib/sysimage/rpm" ]; }; then
        if [ -z "$PL_R" ]; then
            PL_Q=$(rpm -qf --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n' "$PL_P" < /dev/null 2>/dev/null | head -n 1)
        else
            PL_Q=$(rpm --root "$PL_R" -qf --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n' "$PL_P" < /dev/null 2>/dev/null | head -n 1)
        fi
        case $PL_Q in
            *"$TAB"*"$TAB"*)
                PK_MGR=rpm; PK_NAME=${PL_Q%%"$TAB"*}; PL_Q=${PL_Q#*"$TAB"}
                PK_VER=${PL_Q%%"$TAB"*}; PL_VENDOR=${PL_Q#*"$TAB"}
                case "$PK_VER $PL_VENDOR" in
                    *remi*|*Remi*) PK_ORIGIN=remi ;;
                    *cPanel*|ea-php*) PK_ORIGIN=cpanel ;;
                    *Plesk*) PK_ORIGIN=plesk ;;
                    *CloudLinux*) PK_ORIGIN=cloudlinux; PK_BACKPORTER=yes ;;
                    *.amzn*) PK_ORIGIN=amazon; PK_BACKPORTER=yes ;;
                    *.fc[0-9]*) PK_ORIGIN=fedora ;;
                    *.el[0-9]*|*"Red Hat"*|*Rocky*|*Alma*|*Oracle*|*CentOS*) PK_ORIGIN=rhel-family; PK_BACKPORTER=yes ;;
                    *SUSE*) PK_ORIGIN=suse; PK_BACKPORTER=yes ;;
                    *) PK_ORIGIN=rpm ;;
                esac
                if [ -z "$PL_R" ]; then
                    PL_CL=$(rpm -q --changelog "$PK_NAME" < /dev/null 2>/dev/null)
                else
                    PL_CL=$(rpm --root "$PL_R" -q --changelog "$PK_NAME" < /dev/null 2>/dev/null)
                fi
                if [ -z "$PL_CL" ]; then PK_CHANGELOG=unavailable
                elif printf '%s\n' "$PL_CL" | grep -q -E "$CVE_RE"; then PK_CHANGELOG=yes
                else PK_CHANGELOG=no; fi
                return 0 ;;
        esac
    elif [ -d "$PL_R/var/lib/rpm" ] || [ -d "$PL_R/usr/lib/sysimage/rpm" ]; then
        PK_MGR=rpm; PK_ORIGIN=unknown; PK_CHANGELOG=unavailable; PK_BACKPORTER=yes
        add_cov "rpm database at ${PL_R:-/} could not be read (no rpm tool): package backports were not checked"
        return 0
    fi
    case $PL_P in
        /opt/remi/*) PK_ORIGIN=remi ;;
        /opt/cpanel/*) PK_ORIGIN=cpanel ;;
        /opt/plesk/*) PK_ORIGIN=plesk ;;
        /opt/alt/*) PK_ORIGIN=cloudlinux; PK_BACKPORTER=yes ;;
        /opt/homebrew/*|/usr/local/Cellar/*) PK_ORIGIN=homebrew ;;
        /usr/local/lsws/*) PK_ORIGIN=litespeed ;;
        /usr/local/*) PK_ORIGIN=source-build ;;
        *) PK_ORIGIN='' ;;
    esac
    return 0
}

# ------------------------------------------------------------ discovery ----

PHP_NAME_EXPR='-name php -o -name php[0-9]* -o -name php-[0-9]* -o -name php-fpm* -o -name php-cgi* -o -name php-cli -o -name phpdbg* -o -name lsphp* -o -name frankenphp* -o -name libphp* -o -name mod_php*'

# Where PHP builds live when --deep is not given (pkgsrc, aaPanel, cPanel's
# own PHP and DirectAdmin's /usr/local/phpXX included).
FC_DIRS='/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /bin /sbin /usr/lib /usr/lib64 /usr/libexec /usr/local/lib /usr/local/libexec /usr/local/lsws /usr/local/php /usr/local/Cellar /usr/local/cpanel/3rdparty /usr/pkg /www/server /opt /srv/php /Applications/MAMP /Applications/XAMPP'

# Per-user PHP installs, relative to a home directory: Laravel Herd,
# herd-lite (php.new), asdf, mise, phpenv, phpbrew. One per line.
USER_PHP_DIRS='Library/Application Support/Herd/bin
.config/herd-lite/bin
.asdf/installs/php
.local/share/mise/installs/php
.phpenv/versions
.phpbrew/php'

# fc_find ROOT START NAMETEST...: one find run, skipping pseudo filesystems,
# container storage and source trees. -H follows START when it is a symlink.
fc_find() {
    FF_R=$1; FF_S=$2
    shift 2
    find -H "$FF_S" \( -path "$FF_R/proc" -o -path "$FF_R/sys" -o -path "$FF_R/dev" \
        -o -path "$FF_R/var/lib/docker" -o -path "$FF_R/var/lib/containers" -o -path "$FF_R/var/lib/containerd" \
        -o -path "$FF_R/usr/share" -o -path "$FF_R/usr/include" -o -path "$FF_R/usr/src" \
        -o -name node_modules -o -name .git \) -prune -o \
        -type f \( "$@" \) -print 2>/dev/null
}

# find_candidates ROOT: prints candidate PHP executables/modules under ROOT.
find_candidates() {
    FC_R=$1
    # Split the name tests into words with globbing off, so php[0-9]* is
    # passed to find and not matched against the current directory.
    set -f
    # shellcheck disable=SC2086 # PHP_NAME_EXPR is a deliberate word list
    set -- $PHP_NAME_EXPR
    set +f
    if [ "$OPT_DEEP" -eq 1 ]; then
        # Each top-level directory on its own: ROOT itself may be a symlink
        # (/proc/<pid>/root), and find does not descend into a symlink it is
        # started on. Top-level symlinks (/bin -> usr/bin) are covered by
        # their targets.
        for FC_START in "$FC_R"/*; do
            [ -d "$FC_START" ] && [ ! -h "$FC_START" ] || continue
            fc_find "$FC_R" "$FC_START" "$@"
        done
    else
        for FC_D in $FC_DIRS; do
            start_path "$FC_R" "$FC_D"
            [ -d "$START_P" ] || continue
            fc_find "$FC_R" "$START_P" "$@"
        done
        # DirectAdmin-style /usr/local/php83, /usr/local/php74 ...
        for FC_D in "$FC_R"/usr/local/php[0-9]*; do
            [ -d "$FC_D" ] && fc_find "$FC_R" "$FC_D" "$@"
        done
        # Nix: only the bin/sbin/lib directories of PHP store paths.
        if [ -d "$FC_R/nix/store" ]; then
            find "$FC_R/nix/store" -maxdepth 1 -type d -name '*-php-*' -print 2>/dev/null |
            while IFS= read -r FC_N; do
                for FC_S in "$FC_N/bin" "$FC_N/sbin" "$FC_N/lib" "$FC_N/modules"; do
                    [ -d "$FC_S" ] && find "$FC_S" -maxdepth 2 -type f \( "$@" \) -print 2>/dev/null
                done
            done
        fi
    fi
    # Per-user installs: the current user's home on a live host, plus every
    # home directory under ROOT that can be read.
    {
        [ -z "$FC_R" ] && [ -n "${HOME:-}" ] && [ "$HOME" != / ] && printf '%s\n' "$HOME"
        for FC_B in "$FC_R"/root "$FC_R"/home/* "$FC_R"/Users/*; do
            [ -d "$FC_B" ] && printf '%s\n' "$FC_B"
        done
    } | while IFS= read -r FC_B; do
        printf '%s\n' "$USER_PHP_DIRS" | while IFS= read -r FC_U; do
            [ -d "$FC_B/$FC_U" ] || continue
            find -H "$FC_B/$FC_U" -type f \( "$@" \) -print 2>/dev/null
        done
    done
}

# Without Linux /proc (macOS, BSD): name the PHP and web server processes ps
# can see, so the report can say what to restart. PHP2SHELL_PS_FILE (a test
# hook) replaces the output of ps.
ps_fallback() {
    if [ -n "${PHP2SHELL_PS_FILE:-}" ]; then
        cat "$PHP2SHELL_PS_FILE" 2>/dev/null
    elif have ps; then
        ps -axo pid=,comm= 2>/dev/null
    fi | awk '{
            c = $2; for (i = 3; i <= NF; i++) c = c " " $i
            sub(/.*\//, "", c)
            if (c ~ /^(php|php[0-9.]*|php-[0-9.]+|php-fpm.*|php[0-9.]*-fpm.*|php-cgi.*|php[0-9.]*-cgi.*|lsphp.*|frankenphp.*|phpdbg.*|httpd|apache2)$/) { if (!(c in n)) o[++k] = c; n[c]++ }
        }
        END { for (i = 1; i <= k; i++) printf "%s%s x%d", (i > 1 ? ", " : ""), o[i], n[o[i]] }'
}

# Running process groups. One record per distinct running PHP image:
# scope root image deleted sapi count samplepid runver runfp restart comm
scan_processes() {
    if [ -n "$OPT_ROOT" ]; then
        add_cov "offline mode (--root): running processes and restarts were not checked"
        return 0
    fi
    PS_DENIED=0
    : > "$TMPD/cand2.tsv"
    if [ -r "$PROC/self/stat" ]; then
        PROC_MODE=procfs
        collect_procfs || return 0
    elif collect_ps; then
        PROC_MODE='ps'
    else
        # Never report "fixed" for code that may still be running from an old
        # build: without a process inventory the running image cannot be read
        # (SPEC 1, 6).
        PROC_UNCHECKED=1
        set_limited
        PS_LIST=$(ps_fallback)
        if [ -n "$PS_LIST" ]; then
            add_cov "Couldn't check which PHP programs are running (no /proc, and ps/lsof gave nothing usable). PHP or web server programs are running ($PS_LIST): restart them after patching, because this tool cannot tell whether they still run an old build"
        else
            add_cov "Couldn't check which PHP programs are running (no /proc, and ps/lsof gave nothing usable): a PHP service still running an old build after an upgrade cannot be detected, so restart PHP services after patching"
        fi
        return 0
    fi
    group_processes
}

# collect_procfs: Linux process inventory from /proc. Writes ps.tsv
# (pid ppid start comm), uid.tsv and one cand2.tsv line per PHP candidate.
# Returns 1 when the process table could not be read.
collect_procfs() {
    SELF_MNT=$(readlink "$PROC/self/ns/mnt" 2>/dev/null)
    HOST_RID=$(file_id "${HOSTROOT:-}/")
    PS_BTIME=$(awk '/^btime /{ print $2 }' "$PROC/stat" 2>/dev/null)
    PS_HZ=$(getconf CLK_TCK 2>/dev/null)
    [ -n "$PS_HZ" ] || PS_HZ=100

    # pid ppid start_epoch comm, parsed after the last ')' because comm may
    # contain spaces. Each file is opened with getline, so a process that
    # exits during the scan is skipped (awk stops at an unreadable operand),
    # and printf (a builtin) passes the names without an argument list limit.
    printf '%s\n' "$PROC"/[0-9]*/stat | awk -v bt="${PS_BTIME:-0}" -v hz="$PS_HZ" -v S="$SEP" '
        {
            f = $0
            if ((getline line < f) <= 0) { close(f); next }
            close(f)
            p = index(line, " (")
            if (p == 0) next
            q = 0
            for (i = length(line); i > p; i--) if (substr(line, i, 1) == ")") { q = i; break }
            if (q == 0) next
            pid = substr(line, 1, p - 1); comm = substr(line, p + 2, q - p - 2)
            gsub(/[\001-\037\177]/, " ", comm)
            n = split(substr(line, q + 2), f2, " ")
            if (n < 20) next
            printf "%s%s%s%s%d%s%s\n", pid, S, f2[2], S, bt + int(f2[20] / hz), S, comm
        }' > "$TMPD/ps.tsv"
    printf '%s\n' "$PROC"/[0-9]*/status | awk -v S="$SEP" '
        {
            f = $0; p = f; sub(/\/status$/, "", p); sub(/.*\//, "", p)
            while ((getline l < f) > 0) if (l ~ /^Uid:/) { split(l, a, " "); print p S a[2]; break }
            close(f)
        }' > "$TMPD/uid.tsv"
    if [ ! -s "$TMPD/ps.tsv" ]; then
        PROC_UNCHECKED=1
        set_limited
        add_cov "running processes were not checked: the process table under $PROC could not be read"
        return 1
    fi
    grep -l -E '(libphp|mod_php)[0-9.]*\.so' "$PROC"/[0-9]*/maps 2>/dev/null |
        sed 's|/maps$||; s|.*/||' > "$TMPD/mappids.txt"

    # Candidates: PHP-looking process names, plus processes mapping libphp.
    # The pid list is loaded in BEGIN: with "NR == FNR" an empty list would
    # swallow the whole process table.
    awk -F "$SEP" -v mf="$TMPD/mappids.txt" '
        BEGIN { while ((getline l < mf) > 0) m[l] = 1; close(mf) }
        ($4 ~ /^(php|php[0-9.]*|php-[0-9.]+|php-fpm.*|php[0-9.]*-fpm.*|php-cgi.*|php[0-9.]*-cgi.*|lsphp.*|frankenphp.*|phpdbg.*)$/) || ($1 in m) { print }' \
        "$TMPD/ps.tsv" > "$TMPD/cand.tsv"

    while IFS="$SEP" read -r PS_PID _ PS_START PS_COMM; do
        PS_EXE=$(readlink "$PROC/$PS_PID/exe" 2>/dev/null)
        if [ -z "$PS_EXE" ]; then
            # Exited since the snapshot (its entries are gone): nothing to
            # inspect. Only a process that still exists was denied.
            [ -e "$PROC/$PS_PID/stat" ] && [ -h "$PROC/$PS_PID/exe" ] || continue
            PS_DENIED=$((PS_DENIED + 1))
            continue
        fi
        PS_MNT=$(readlink "$PROC/$PS_PID/ns/mnt" 2>/dev/null)
        PS_UID=$(awk -F "$SEP" -v p="$PS_PID" '$1 == p { print $2; exit }' "$TMPD/uid.tsv")
        PS_DEL=no
        case $PS_EXE in *' (deleted)') PS_DEL=yes; PS_EXE=${PS_EXE% (deleted)} ;; esac
        PS_BASE=${PS_EXE##*/}
        PS_KIND=exe; PS_RANGE=-
        PS_IMAGE=$PS_EXE
        PS_SAPI=$(sapi_of_path "$PS_EXE")
        case $PS_SAPI in
            unknown|frankenphp)
                # mod_php, embed and dynamically linked FrankenPHP run PHP from
                # a mapped libphp: that library is the running PHP build.
                PS_MAPLINE=$(grep -m 1 -E '(libphp|mod_php)[0-9.]*\.so' "$PROC/$PS_PID/maps" 2>/dev/null)
                if [ -n "$PS_MAPLINE" ]; then
                    PS_KIND=map
                    PS_RANGE=${PS_MAPLINE%% *}
                    PS_IMAGE=$(printf '%s\n' "$PS_MAPLINE" | awk '{ p = $6; for (i = 7; i <= NF; i++) p = p " " $i; print p }')
                    PS_DEL=no
                    case $PS_IMAGE in *' (deleted)') PS_DEL=yes; PS_IMAGE=${PS_IMAGE% (deleted)} ;; esac
                    if [ "$PS_SAPI" = unknown ]; then
                        case $PS_BASE in apache2*|httpd*) PS_SAPI=mod_php ;; *) PS_SAPI=embed ;; esac
                    fi
                elif [ "$PS_SAPI" = unknown ]; then
                    continue
                fi ;;
        esac
        case $PS_SAPI in
            fpm|cgi|litespeed|frankenphp|mod_php|embed) [ -n "$PS_UID" ] && [ "$PS_UID" != 0 ] && printf '%s\n' "$PS_UID" >> "$TMPD/webuids.txt"
                printf '%s\n' "$PS_PID" >> "$TMPD/webpids.txt" ;;
        esac
        rec "$PS_PID" "$PS_START" "$PS_COMM" "${PS_MNT:-none}" "$PS_KIND" "$PS_IMAGE" "$PS_DEL" "$PS_RANGE" \
            "$PS_SAPI" "${PS_UID:-}" >> "$TMPD/cand2.tsv"
    done < "$TMPD/cand.tsv"
    return 0
}

# collect_ps: process inventory without /proc (macOS, BSD). ps gives the
# process table; one lsof call (or FreeBSD's procstat) gives each process's
# executable and any mapped libphp with their inodes, so a running image that
# is no longer the file on disk is caught exactly. Writes the same files as
# collect_procfs, with the lsof inode as "ino:<n>" in the range field.
# Returns 1 when ps is missing, prints nothing, or PHP2SHELL_NO_PS=1 (a test
# hook that keeps the real process table out of fixture runs).
collect_ps() {
    [ "${PHP2SHELL_NO_PS:-0}" = 1 ] && return 1
    have ps || return 1
    SELF_MNT=''
    HOST_RID=''
    CP_NOW=$(date +%s)
    # pid ppid start name uid path; etime is [[dd-]hh:]mm:ss.
    ps -axo pid=,ppid=,uid=,etime=,comm= 2>/dev/null | awk -v now="$CP_NOW" -v S="$SEP" '
        function secs(e,   d, n, a, s, i) {
            d = 0
            if (index(e, "-")) { d = substr(e, 1, index(e, "-") - 1) + 0; e = substr(e, index(e, "-") + 1) }
            n = split(e, a, ":"); s = 0
            for (i = 1; i <= n; i++) s = s * 60 + a[i]
            return d * 86400 + s
        }
        NF >= 5 && $1 ~ /^[0-9]+$/ {
            line = $0
            for (i = 1; i <= 4; i++) sub(/^[ \t]*[^ \t]+/, "", line)
            sub(/^[ \t]+/, "", line)
            gsub(/[\001-\037\177]/, " ", line)
            name = line; sub(/.*\//, "", name)
            print $1 S $2 S (now - secs($4)) S name S $3 S line
        }' > "$TMPD/ps_full.tsv"
    [ -s "$TMPD/ps_full.tsv" ] || return 1
    cut -d "$SEP" -f 1-4 "$TMPD/ps_full.tsv" > "$TMPD/ps.tsv"
    cut -d "$SEP" -f 1,5 "$TMPD/ps_full.tsv" > "$TMPD/uid.tsv"
    # kind pid inode path. The first txt entry of a process is its executable.
    if have lsof; then
        lsof -n -P -w -d txt -F pin 2>/dev/null | awk -v S="$SEP" '
            /^p/ { pid = substr($0, 2); n = 0; ino = ""; next }
            /^i/ { ino = substr($0, 2); next }
            /^n/ {
                n++; path = substr($0, 2)
                if (n == 1) print "exe" S pid S ino S path
                if (path ~ /(libphp|mod_php)[0-9.]*\.so/) print "map" S pid S ino S path
                ino = ""
            }' > "$TMPD/ps_img.tsv"
    elif have procstat; then
        {
            procstat -b -a 2>/dev/null | awk -v S="$SEP" 'NR > 1 && $NF ~ /^\// { print "exe" S $1 S "" S $NF }'
            procstat -v -a 2>/dev/null | awk -v S="$SEP" '$NF ~ /(libphp|mod_php)[0-9.]*\.so/ { print "map" S $1 S "" S $NF }'
        } > "$TMPD/ps_img.tsv"
    else
        : > "$TMPD/ps_img.tsv"
        add_cov "Neither lsof nor procstat is available, so PHP loaded inside web servers (mod_php) was not checked"
    fi
    # Candidates: PHP-looking names, plus processes mapping libphp. A
    # FrankenPHP linked against libphp runs PHP from the library, not the exe.
    awk -F "$SEP" -v imf="$TMPD/ps_img.tsv" -v S="$SEP" '
        BEGIN {
            while ((getline l < imf) > 0) {
                split(l, a, S)
                if (a[1] == "exe") { ep[a[2]] = a[4]; ei[a[2]] = a[3] }
                else if (!(a[2] in mp)) { mp[a[2]] = a[4]; mi[a[2]] = a[3] }
            }
            close(imf)
        }
        {
            pid = $1; name = $4
            php = (name ~ /^(php|php[0-9.]*|php-[0-9.]+|php-fpm.*|php[0-9.]*-fpm.*|php-cgi.*|php[0-9.]*-cgi.*|lsphp.*|frankenphp.*|phpdbg.*)$/)
            # A web server lsof cannot see (run by another user, when not root)
            # may have libphp loaded: it counts as not inspected, never as clean.
            web = (name ~ /^(httpd|apache2|lsws|lshttpd|litespeed|unitd)/)
            if (!php && !(pid in mp) && !(web && !(pid in ep))) next
            if (!php && !(pid in mp)) { print pid S $3 S name S "map" S "" S "" S $5; next }
            if (php && !(name ~ /^frankenphp/ && (pid in mp))) {
                kind = "exe"
                # No lsof record: ps only shows argv[0] (e.g. "./bin/php-fpm"
                # or a retitled "php-fpm: master pr"), so the image is unknown.
                if (pid in ep) { img = ep[pid]; ino = ei[pid] } else { img = ""; ino = "" }
            } else {
                kind = "map"; img = mp[pid]; ino = mi[pid]
            }
            print pid S $3 S name S kind S img S ino S $5
        }' "$TMPD/ps_full.tsv" > "$TMPD/cand.tsv"
    while IFS="$SEP" read -r CP_PID CP_START CP_NAME CP_KIND CP_IMG CP_INO CP_UID; do
        if [ -z "$CP_IMG" ]; then
            PS_DENIED=$((PS_DENIED + 1))
            continue
        fi
        # The running image is not the file on disk (replaced or removed).
        CP_DEL=no
        CP_DISKID=$(file_id "$HOSTROOT$CP_IMG")
        if [ -z "$CP_DISKID" ]; then
            CP_DEL=yes
        elif [ -n "$CP_INO" ] && [ "$CP_INO" != "${CP_DISKID##*:}" ]; then
            CP_DEL=yes
        fi
        if [ "$CP_KIND" = exe ]; then
            CP_SAPI=$(sapi_of_path "$CP_IMG")
            [ "$CP_SAPI" = unknown ] && CP_SAPI=$(sapi_of_name "$CP_NAME")
        else
            case $CP_NAME in httpd*|apache2*) CP_SAPI=mod_php ;; frankenphp*) CP_SAPI=frankenphp ;; *) CP_SAPI=embed ;; esac
        fi
        # Only service accounts count as web users here: on macOS a Homebrew
        # php-fpm runs as the logged-in user, whose every process is not suspect.
        case $CP_SAPI in
            fpm|cgi|litespeed|frankenphp|mod_php|embed)
                [ -n "$CP_UID" ] && [ "$CP_UID" != 0 ] && [ "$CP_UID" -lt 500 ] 2>/dev/null && printf '%s\n' "$CP_UID" >> "$TMPD/webuids.txt"
                printf '%s\n' "$CP_PID" >> "$TMPD/webpids.txt" ;;
        esac
        CP_RANGE=-
        [ -n "$CP_INO" ] && CP_RANGE="ino:$CP_INO"
        rec "$CP_PID" "$CP_START" "$CP_NAME" none "$CP_KIND" "$CP_IMG" "$CP_DEL" "$CP_RANGE" "$CP_SAPI" "$CP_UID" >> "$TMPD/cand2.tsv"
    done < "$TMPD/cand.tsv"
    return 0
}

# group_processes: turns cand2.tsv into groups.tsv, one record per distinct
# running image, and adds each container's root to roots.tsv.
group_processes() {
    if [ "$PS_DENIED" -gt 0 ]; then
        set_limited
        if [ "$(id -u 2>/dev/null)" = 0 ]; then
            add_cov "$PS_DENIED PHP-looking processes could not be inspected (permission denied, possibly by a security module)"
        else
            add_cov "$PS_DENIED PHP-looking processes could not be inspected (permission denied): run as root"
        fi
    fi
    [ -s "$TMPD/cand2.tsv" ] || return 0

    # Group by namespace + image + deleted + kind.
    awk -F "$SEP" -v S="$SEP" '{
            k = $4 SUBSEP $6 SUBSEP $7 SUBSEP $5
            if (!(k in n)) { order[++o] = k; pid[k] = $1; start[k] = $2; sapi[k] = $9; rng[k] = $8; comm[k] = $3 }
            n[k]++
            if ($2 < start[k]) start[k] = $2
        }
        END {
            for (i = 1; i <= o; i++) {
                k = order[i]; split(k, a, SUBSEP)
                printf "%s%s%s%s%s%s%s%s%s%s%d%s%s%s%s%s%s%s%s\n", a[1], S, a[2], S, a[3], S, a[4], S, pid[k], S, n[k], S, start[k], S, sapi[k], S, rng[k], S, comm[k]
            }
        }' "$TMPD/cand2.tsv" > "$TMPD/grp_raw.tsv"

    : > "$TMPD/grp_scoped.tsv"
    while IFS="$SEP" read -r G_MNT G_IMAGE G_DEL G_KIND G_PID G_N G_START G_SAPI G_RANGE G_COMM; do
        G_SCOPE=''
        if [ "$G_MNT" = "${SELF_MNT:-x}" ] || [ "$G_MNT" = none ]; then
            G_SCOPE=host
        else
            # A service with a private mount namespace (systemd PrivateTmp,
            # ProtectSystem) still has the host's root directory as its root.
            G_RID=$(file_id "$PROC/$G_PID/root/")
            [ -n "$G_RID" ] && [ "$G_RID" = "$HOST_RID" ] && G_SCOPE=host
        fi
        if [ "$G_SCOPE" = host ]; then
            G_ROOT=$HOSTROOT
        else
            G_CID=$(grep -o -E '[0-9a-f]{64}' "$PROC/$G_PID/cgroup" 2>/dev/null | head -n 1 | cut -c1-12)
            if [ -n "$G_CID" ]; then G_SCOPE="container:$G_CID"; else G_SCOPE="mntns:$(printf '%s' "$G_MNT" | tr -cd '0-9')"; fi
            G_ROOT="$PROC/$G_PID/root"
        fi
        G_DISK="$G_ROOT$G_IMAGE"
        # The image the process is actually running, even if deleted on disk.
        if [ "$G_KIND" = exe ]; then
            G_RUNFILE="$PROC/$G_PID/exe"
            # Under the PHP2SHELL_PROC test hook the exe entry is a plain
            # symlink to an in-namespace path that may exist on the test
            # machine itself (GitHub's runners ship PHP), so it is not read:
            # the image is judged from <root><image> below instead.
            [ -n "${PHP2SHELL_PROC:-}" ] && G_RUNFILE="$TMPD/p2s-no-such-exe"
        elif [ "$G_DEL" = yes ]; then
            G_RUNFILE="$PROC/$G_PID/map_files/$G_RANGE"
        else
            G_RUNFILE=$G_DISK
        fi
        G_RUNVER=''; G_RUNFP=no
        if scan_binary "$G_RUNFILE"; then
            G_RUNVER=$SB_VERSION; G_RUNFP=$SB_FP
        elif [ "$G_DEL" = no ] && [ "$G_RUNFILE" != "$G_DISK" ] && scan_binary "$G_DISK"; then
            # /proc/<pid>/exe not readable (or a link into another namespace):
            # the image is not deleted, so the file at its path is what runs.
            G_RUNVER=$SB_VERSION; G_RUNFP=$SB_FP
        fi
        # Identity of the running image: the inode in the process's memory
        # map. When it is the inode of the file on disk, the process runs that
        # very file (an FPM reload or Apache graceful keeps the start time).
        if [ "$PROC_MODE" = ps ]; then
            # lsof reported the inode of the file the process runs.
            G_RUN_INO=${G_RANGE#ino:}
            [ "$G_RUN_INO" = "$G_RANGE" ] && G_RUN_INO=''
        else
            G_RUN_INO=$(P2S_IMG=$G_IMAGE awk '{ p = $6; for (i = 7; i <= NF; i++) p = p " " $i
                    if (p == ENVIRON["P2S_IMG"] || p == ENVIRON["P2S_IMG"] " (deleted)") { print $5; exit } }' "$PROC/$G_PID/maps" 2>/dev/null)
        fi
        G_SAME=no
        if [ "$G_DEL" = no ] && [ -n "$G_RUN_INO" ] && [ "$G_RUN_INO" != 0 ]; then
            G_DISK_ID=$(file_id "$G_DISK")
            [ -n "$G_DISK_ID" ] && [ "${G_DISK_ID##*:}" = "$G_RUN_INO" ] && G_SAME=yes
        fi
        G_RESTART=no
        [ "$G_DEL" = yes ] && G_RESTART=yes
        if [ "$G_RESTART" = no ] && [ "$G_SAME" = no ] && [ -f "$G_DISK" ]; then
            G_MT=$(mtime "$G_DISK")
            [ -n "$G_MT" ] && [ "$G_MT" -gt "$G_START" ] && G_RESTART=yes
            if [ "$G_RESTART" = no ] && scan_binary "$G_DISK"; then
                if [ "$SB_VERSION" != "$G_RUNVER" ] || [ "$SB_FP" != "$G_RUNFP" ]; then G_RESTART=yes; fi
            fi
        fi
        rec "$G_SCOPE" "$G_ROOT" "$G_IMAGE" "$G_DEL" "$G_SAPI" "$G_N" "$G_PID" "$G_RUNVER" "$G_RUNFP" \
            "$G_RESTART" "$G_COMM" >> "$TMPD/grp_scoped.tsv"
        if [ "$G_SCOPE" != host ] && [ "$OPT_SKIP_CONTAINERS" -eq 0 ]; then
            if ! awk -F "$SEP" -v s="$G_SCOPE" '$1 == s { f = 1 } END { exit !f }' "$TMPD/roots.tsv"; then
                rec "$G_SCOPE" "$G_ROOT" >> "$TMPD/roots.tsv"
            fi
        fi
    done < "$TMPD/grp_raw.tsv"
    # Host-scope groups from several mount namespaces (PrivateTmp services)
    # running the same image are one group.
    awk -F "$SEP" -v S="$SEP" '{
            k = $1 SUBSEP $3 SUBSEP $4
            if (!(k in row)) { order[++o] = k; row[k] = $0; rs[k] = $10; rv[k] = $8 SUBSEP $9 }
            cnt[k] += $6
            if ($10 == "yes" || ($8 SUBSEP $9) != rv[k]) rs[k] = "yes"
        }
        END {
            for (i = 1; i <= o; i++) {
                k = order[i]; m = split(row[k], f, S); f[6] = cnt[k]; f[10] = rs[k]
                out = f[1]; for (j = 2; j <= m; j++) out = out S f[j]
                print out
            }
        }' "$TMPD/grp_scoped.tsv" > "$TMPD/groups.tsv"
    return 0
}

# record_installation SCOPE ROOT PATH: inspect one file and append a record.
record_installation() {
    RI_SCOPE=$1; RI_ROOT=$2; RI_PATH=$3
    RI_FILE="$RI_ROOT$RI_PATH"
    if scan_binary "$RI_FILE"; then
        RI_VER=$SB_VERSION; RI_FP=$SB_FP
    else
        # No readable version (packed, stripped or unusual build). A file
        # named exactly like a PHP SAPI is still reported, as UNKNOWN (SPEC 3
        # rule 1), unless it is a dynamically linked binary whose PHP lives in
        # libphp (FrankenPHP): the library is then the PHP build.
        is_php_sapi_name "${RI_PATH##*/}" || return 1
        case ${RI_PATH##*/} in
            libphp*|mod_php*) ;;
            *) tr -c 'A-Za-z0-9._' '\n' 2>/dev/null < "$RI_FILE" | grep -q -E '^libphp[0-9.]*\.so' && return 1 ;;
        esac
        RI_VER=''; RI_FP=$SB_FP
        add_cov "PHP version could not be read from $RI_PATH (packed or stripped build?): reported as UNKNOWN; run it with -v to check"
    fi
    RI_SAPI=$(sapi_of_path "$RI_PATH")
    pkg_lookup "$RI_ROOT" "$RI_PATH"
    # A vendor build (SPEC section 3): owned by a package, or a vendor suffix
    # in the version. Its vendor may have backported the fix.
    if [ "$PK_MGR" != none ]; then
        PK_BACKPORTER=yes
    elif parse_version "$RI_VER" && [ "$VP_KIND" = vendor ]; then
        PK_BACKPORTER=yes
    fi
    RI_VDATA=no
    [ "$PK_MGR" != none ] && vendor_data_hit "$RI_ROOT" "$PK_MGR" "$PK_NAME" "$PK_VER" && RI_VDATA=yes
    decide "$RI_VER" "$RI_FP" "$PK_CHANGELOG" "$RI_VDATA" "$PK_BACKPORTER"

    # Join with every running process group for the same file. Several groups
    # can share a path (a restarted master next to one still running the
    # deleted old image), so they are summed, and the stalest image is the
    # one judged: a group that needs a restart always wins.
    RI_RUN=0; RI_RESTART=no; RI_RUNVER=''; RI_RUNVERDICT=''
    RI_G=$(P2S_PATH=$RI_PATH P2S_VER=$RI_VER P2S_FP=$RI_FP awk -F "$SEP" -v S="$SEP" -v s="$RI_SCOPE" '
        $1 == s && $3 == ENVIRON["P2S_PATH"] {
            nrs = nrs (nrs == "" ? "" : ",") NR
            if (sapi == "") sapi = $5
            n += $6
            stale = ($10 == "yes" || $8 != ENVIRON["P2S_VER"] || $9 != ENVIRON["P2S_FP"])
            if (pick == "" || (stale && !pstale)) { pick = $8 S $9; pstale = stale }
            if ($10 == "yes") rs = "yes"
        }
        END { if (nrs != "") print nrs S sapi S n S pick S (rs == "" ? "no" : rs) }' "$TMPD/groups.tsv")
    if [ -n "$RI_G" ]; then
        IFS="$SEP" read -r RI_GNS RI_GSAPI RI_RUN RI_RUNVER RI_RUNFP RI_RESTART <<EOF
$RI_G
EOF
        printf '%s\n' "$RI_GNS" | tr ',' '\n' >> "$TMPD/matched.txt"
        # A libphp is mod_php in Apache and FrankenPHP's PHP in frankenphp.
        case $RI_SAPI in unknown|mod_php|embed) RI_SAPI=$RI_GSAPI ;; esac
        if [ "$RI_RESTART" != yes ] && [ "$RI_RUNVER" = "$RI_VER" ] && [ "$RI_RUNFP" = "$RI_FP" ]; then
            RI_RUNVERDICT=$VD_VERDICT
        else
            # A different build is running (or a stale one that only looks
            # the same, e.g. a deleted image after a package upgrade). The
            # package's changelog and vendor data describe the build on disk.
            RI_S_V=$VD_VERDICT; RI_S_E=$VD_EVIDENCE; RI_S_R=$VD_REASON; RI_S_M=$VD_REMEDIATION
            RI_S_B=$VD_BRANCH; RI_S_BS=$VD_BSTATUS; RI_S_F=$VD_FIXED
            decide "$RI_RUNVER" "$RI_RUNFP" n/a no "$PK_BACKPORTER"
            RI_RUNVERDICT=$VD_VERDICT
            VD_VERDICT=$RI_S_V; VD_EVIDENCE=$RI_S_E; VD_REASON=$RI_S_R; VD_REMEDIATION=$RI_S_M
            VD_BRANCH=$RI_S_B; VD_BSTATUS=$RI_S_BS; VD_FIXED=$RI_S_F
        fi
    fi
    case $RI_SAPI in
        mod_php) case $RI_PATH in *apache*|*httpd*|*/modules/*) ;; *) [ "$RI_RUN" -gt 0 ] || RI_SAPI=embed ;; esac ;;
    esac
    rec "$RI_SCOPE" "$(clean "$RI_PATH")" "$RI_SAPI" "$(clean "$RI_VER")" "$VD_BRANCH" "$VD_BSTATUS" "$VD_FIXED" "$RI_FP" \
        "$PK_MGR" "$(clean "$PK_NAME")" "$(clean "$PK_VER")" "$(clean "$PK_ORIGIN")" "$VD_EVIDENCE" "$VD_VERDICT" "$VD_REASON" \
        "$(clean "$VD_REMEDIATION")" "$RI_RUN" "$RI_RESTART" "$(clean "$RI_RUNVER")" "$RI_RUNVERDICT" "$(exposure_of "$RI_SAPI")" \
        >> "$TMPD/inst.tsv"
    rec "$RI_ROOT" "$RI_VER" >> "$TMPD/versions.tsv"
    return 0
}

scan_root() {  # scan_root SCOPE ROOT
    SR_SCOPE=$1; SR_ROOT=$2
    : > "$TMPD/seen.txt"
    find_candidates "$SR_ROOT" | while IFS= read -r SR_F; do
        [ -f "$SR_F" ] || continue
        SR_REL=${SR_F#"$SR_ROOT"}
        if [ ! -r "$SR_F" ]; then
            if is_php_sapi_name "${SR_F##*/}"; then
                set_limited
                add_cov "PHP build not readable: $SR_REL (run as root)"
            fi
            continue
        fi
        is_native_binary "$SR_F" || continue
        # Duplicates (hard links, /bin -> usr/bin) by device and inode: the
        # inode alone repeats across filesystems.
        SR_ID=$(file_id "$SR_F")
        [ -n "$SR_ID" ] || SR_ID="path:$SR_F"
        if grep -q -x -F -e "$SR_ID" "$TMPD/seen.txt" 2>/dev/null; then continue; fi
        printf '%s\n' "$SR_ID" >> "$TMPD/seen.txt"
        record_installation "$SR_SCOPE" "$SR_ROOT" "$SR_REL" < /dev/null || true
    done
}

# Running images with no matching file on disk (deleted and not replaced).
add_unmatched_groups() {
    awk -v S="$SEP" -v mf="$TMPD/matched.txt" 'BEGIN { while ((getline l < mf) > 0) m[l] = 1; close(mf) }
        !(NR in m) { print NR S $0 }' "$TMPD/groups.tsv" > "$TMPD/unmatched.tsv"
    while IFS="$SEP" read -r U_NR U_SCOPE U_ROOT U_IMAGE U_DEL U_SAPI U_N _ U_RUNVER U_RUNFP U_RESTART U_COMM; do
        # Already joined by an earlier record_installation for the same path.
        grep -q -x -F "$U_NR" "$TMPD/matched.txt" 2>/dev/null && continue
        # Outside the scanned folders but still on disk: report it like any
        # other installation, joined with its running processes.
        if [ -f "$U_ROOT$U_IMAGE" ] && record_installation "$U_SCOPE" "$U_ROOT" "$U_IMAGE" < /dev/null; then
            continue
        fi
        printf '%s\n' "$U_NR" >> "$TMPD/matched.txt"
        decide "$U_RUNVER" "$U_RUNFP" n/a no no
        U_REM=$VD_REMEDIATION
        [ "$U_DEL" = yes ] && U_REM="The running image was deleted from disk (upgraded or removed): restart '$U_COMM'. $U_REM"
        rec "$U_SCOPE" "$(clean "$U_IMAGE")" "$U_SAPI" "$(clean "$U_RUNVER")" "$VD_BRANCH" "$VD_BSTATUS" "$VD_FIXED" "$U_RUNFP" \
            none '' '' '' "$VD_EVIDENCE" "$VD_VERDICT" "$VD_REASON,running-image-only" "$(clean "$U_REM")" \
            "$U_N" "$U_RESTART" "$(clean "$U_RUNVER")" "$VD_VERDICT" "$(exposure_of "$U_SAPI")" >> "$TMPD/inst.tsv"
    done < "$TMPD/unmatched.tsv"
}

# ------------------------------------------------------- config context ----

ini_files() {  # ini_files ROOT
    for IF_F in "$1"/etc/php/*/*/php.ini "$1"/etc/php/*/*/conf.d/*.ini "$1"/etc/php.ini "$1"/etc/php.d/*.ini \
        "$1"/etc/php[0-9]*/php.ini "$1"/etc/php[0-9]*/conf.d/*.ini "$1"/usr/local/etc/php/php.ini \
        "$1"/usr/local/etc/php/conf.d/*.ini "$1"/etc/opt/remi/php*/php.ini "$1"/etc/opt/remi/php*/php.d/*.ini \
        "$1"/opt/cpanel/ea-php*/root/etc/php.ini "$1"/opt/cpanel/ea-php*/root/etc/php.d/*.ini \
        "$1"/opt/plesk/php/*/etc/php.ini "$1"/opt/plesk/php/*/etc/php.d/*.ini "$1"/opt/alt/php*/etc/php.ini \
        "$1"/opt/alt/php*/etc/php.d/*.ini "$1"/opt/homebrew/etc/php/*/php.ini "$1"/opt/homebrew/etc/php/*/conf.d/*.ini \
        "$1"/usr/local/etc/php/*/php.ini "$1"/usr/local/lib/php.ini; do
        [ -f "$IF_F" ] && printf '%s\n' "$IF_F"
    done
}

pool_files() {  # pool_files ROOT
    for PF_F in "$1"/etc/php/*/fpm/pool.d/*.conf "$1"/etc/php/*/fpm/php-fpm.conf "$1"/etc/php-fpm.d/*.conf \
        "$1"/etc/php-fpm.conf "$1"/etc/php[0-9]*/php-fpm.d/*.conf "$1"/usr/local/etc/php-fpm.d/*.conf \
        "$1"/usr/local/etc/php-fpm.conf "$1"/etc/opt/remi/php*/php-fpm.d/*.conf \
        "$1"/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf "$1"/opt/plesk/php/*/etc/php-fpm.d/*.conf \
        "$1"/opt/cpanel/ea-php*/root/etc/php-fpm.conf "$1"/opt/plesk/php/*/etc/php-fpm.conf \
        "$1"/opt/remi/php*/root/etc/php-fpm.conf "$1"/etc/opt/remi/php*/php-fpm.conf \
        "$1"/opt/homebrew/etc/php/*/php-fpm.d/*.conf; do
        [ -f "$PF_F" ] && printf '%s\n' "$PF_F"
    done
}

web_conf_files() {  # web_conf_files ROOT: nginx and Apache configuration files
    for WC_F in "$1"/etc/nginx/nginx.conf "$1"/etc/nginx/conf.d/*.conf "$1"/etc/nginx/sites-enabled/* \
        "$1"/etc/nginx/snippets/*.conf "$1"/etc/nginx/fastcgi_params "$1"/etc/nginx/fastcgi.conf \
        "$1"/usr/local/nginx/conf/*.conf "$1"/usr/local/etc/nginx/*.conf "$1"/usr/local/etc/nginx/servers/* \
        "$1"/opt/homebrew/etc/nginx/*.conf "$1"/opt/homebrew/etc/nginx/servers/* \
        "$1"/etc/apache2/apache2.conf "$1"/etc/apache2/conf-enabled/* "$1"/etc/apache2/sites-enabled/* \
        "$1"/etc/apache2/mods-enabled/*.conf "$1"/etc/httpd/conf/httpd.conf "$1"/etc/httpd/conf.d/*.conf \
        "$1"/usr/local/apache/conf/httpd.conf "$1"/usr/local/apache/conf/includes/* "$1"/usr/local/apache2/conf/httpd.conf \
        "$1"/usr/local/etc/apache24/httpd.conf "$1"/usr/local/etc/apache24/Includes/*.conf \
        "$1"/usr/local/lsws/conf/httpd_config.conf "$1"/usr/local/lsws/conf/vhosts/*/*.conf; do
        [ -f "$WC_F" ] && printf '%s\n' "$WC_F"
    done
}

# Per-request INI overrides that the advisory says can emit a diagnostic
# before request initialization (CVE-2026-109619 consumer path).
FLAGGED_INI_RE='auto_detect_line_endings|filter\.default|assert\.[a-z_]+|session\.(sid_length|sid_bits_per_character|use_trans_sid|trans_sid_tags|trans_sid_hosts|referer_check|use_only_cookies)|report_memleaks|intl\.error_level|mbstring\.(http_input|http_output|internal_encoding)|iconv\.(input_encoding|output_encoding|internal_encoding)'

check_config() {  # check_config SCOPE ROOT
    CC_SCOPE=$1; CC_ROOT=$2
    ini_files "$CC_ROOT" > "$TMPD/ini.txt"
    pool_files "$CC_ROOT" > "$TMPD/pool.txt"
    [ -s "$TMPD/ini.txt" ] || [ -s "$TMPD/pool.txt" ] || return 0
    CC_LABEL=$CC_SCOPE
    # Last assignment wins in INI files; pool php_admin_* overrides php.ini.
    cat "$TMPD/ini.txt" "$TMPD/pool.txt" | while IFS= read -r CC_F; do
        grep -H -E '^[[:space:]]*(php_admin_value\[|php_value\[|php_admin_flag\[|php_flag\[)?(session\.upload_progress\.enabled|fatal_error_backtraces|memory_limit)\]?[[:space:]]*=' "$CC_F" 2>/dev/null
    done | strip_root "$CC_ROOT" > "$TMPD/ini_hits.txt"

    CC_UP=$(grep -E 'session\.upload_progress\.enabled' "$TMPD/ini_hits.txt" | tail -n 1)
    case $(printf '%s' "${CC_UP#*=}" | tr -d ' "' | tr 'A-Z' 'a-z') in
        0|off|false|no) add_finding INFO config "session.upload_progress.enabled is Off (partial mitigation for CVE-2026-109619's session path)" \
            "$CC_LABEL: ${CC_UP%%:*}" 0 "Restart every worker after changing it. Not a fix." ;;
        *) add_finding INFO config "session.upload_progress.enabled is On (default): the confirmed CVE-2026-109619 session path is reachable on unpatched PHP" \
            "$CC_LABEL" 0 "Interim only: set session.upload_progress.enabled=0 in php.ini or the FPM pool (not ini_set or .user.ini) and restart every worker. Patching is the only fix." ;;
    esac
    # PHP 8.5 present in this root? Compared as plain strings, so the root
    # path never becomes part of a regex.
    if P2S_ROOT=$CC_ROOT awk -F "$SEP" '$1 == ENVIRON["P2S_ROOT"] && index($2, "8.5.") == 1 { f = 1 } END { exit !f }' \
        "$TMPD/versions.tsv" 2>/dev/null; then
        CC_FB=$(grep -E 'fatal_error_backtraces' "$TMPD/ini_hits.txt" | tail -n 1)
        case $(printf '%s' "${CC_FB#*=}" | tr -d ' "' | tr 'A-Z' 'a-z') in
            0|off|false|no) add_finding INFO config "fatal_error_backtraces is Off on PHP 8.5 (blocks the confirmed fatal-backtrace RCE path only)" "$CC_LABEL: ${CC_FB%%:*}" 0 "" ;;
            *) add_finding INFO config "fatal_error_backtraces is On (PHP 8.5 default): the confirmed CVE-2026-109619 RCE producer is active on unpatched 8.5" \
                "$CC_LABEL" 0 "Interim only: set fatal_error_backtraces=0 administratively and restart every worker." ;;
        esac
    fi
    CC_ML=$(grep -E 'memory_limit' "$TMPD/ini_hits.txt" | tail -n 1)
    if [ -n "$CC_ML" ]; then
        case $(printf '%s' "${CC_ML#*=}" | tr -d ' "') in
            -1) add_finding INFO config "memory_limit=-1 is set (partial mitigation for CVE-2026-109618)" "$CC_LABEL: ${CC_ML%%:*}" 0 \
                "Check no pool, directory or application restores a finite limit. Allocation failures can still reach the bug." ;;
            *) add_finding INFO config "memory_limit is finite ($(printf '%s' "${CC_ML#*=}" | tr -d ' "')): the CVE-2026-109618 OOM path is controllable on unpatched PHP" "$CC_LABEL: ${CC_ML%%:*}" 0 "" ;;
        esac
    fi

    # Per-request INI overrides (nginx fastcgi_param PHP_VALUE, Apache php_value).
    # Only file:line and directive names are kept: values can be secrets
    # (license keys, session.save_path with a Redis password).
    web_conf_files "$CC_ROOT" > "$TMPD/webconf.txt"
    : > "$TMPD/overrides.txt"
    while IFS= read -r CC_F; do
        grep -n -E 'fastcgi_param[[:space:]]+PHP_(ADMIN_)?VALUE|^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]' "$CC_F" 2>/dev/null |
            P2S_PFX=${CC_F#"$CC_ROOT"} awk '{
                n = index($0, ":"); ln = substr($0, 1, n - 1); t = substr($0, n + 1)
                sub(/^[[:space:]]+/, "", t)
                if (t ~ /^php_(admin_)?(value|flag)[[:space:]]/) { split(t, w, " "); out = w[1] " " w[2] }
                else if (match(t, /fastcgi_param[[:space:]]+PHP_(ADMIN_)?VALUE/)) {
                    d = substr(t, RSTART, RLENGTH); gsub(/[[:space:]]+/, " ", d)
                    rest = substr(t, RSTART + RLENGTH); gsub(/\\n/, " ", rest); out = d
                    while (match(rest, /[A-Za-z_][A-Za-z0-9_.]*[[:space:]]*=/)) {
                        nm = substr(rest, RSTART, RLENGTH); sub(/[[:space:]]*=$/, "", nm); out = out " " nm
                        rest = substr(rest, RSTART + RLENGTH); sub(/^[^[:space:]";]*/, "", rest)
                    }
                } else out = "(override)"
                print ENVIRON["P2S_PFX"] ":" ln ": " out
            }' >> "$TMPD/overrides.txt"
    done < "$TMPD/webconf.txt"
    if [ -s "$TMPD/overrides.txt" ]; then
        CC_FLAG=$(grep -E "$FLAGGED_INI_RE" "$TMPD/overrides.txt" | head -n 5 | tr '\n' ';')
        CC_N=$(wc -l < "$TMPD/overrides.txt" | tr -d ' ')
        if [ -n "$CC_FLAG" ]; then
            add_finding REVIEW config "Per-request INI overrides set directives that emit diagnostics before request initialization (CVE-2026-109619 consumer)" \
                "$CC_LABEL" "$CC_N" "$CC_FLAG Remove obsolete or invalid directives from per-request configuration."
        else
            add_finding INFO config "Per-request INI overrides found in web server config: make sure none is invalid or deprecated (CVE-2026-109619 consumer)" \
                "$CC_LABEL" "$CC_N" "$(head -n 3 "$TMPD/overrides.txt" | tr '\n' ';')"
        fi
    fi
}

# --exec: ask each host CLI/FPM binary for its effective INI values.
exec_context() {
    [ "$OPT_EXEC" -eq 1 ] || return 0
    awk -F "$SEP" '$1 == "host" && ($3 == "cli" || $3 == "fpm" || $3 == "cgi") { print $2 }' "$TMPD/inst.tsv" | sort -u |
    while IFS= read -r EX_BIN; do
        [ -x "$HOSTROOT$EX_BIN" ] || continue
        EX_OUT=$(run_limited "$HOSTROOT$EX_BIN" -i 2>/dev/null | grep -E '^(session\.upload_progress\.enabled|fatal_error_backtraces|memory_limit|memory_hard_limit_percent) =>' | tr '\n' ';')
        [ -n "$EX_OUT" ] && add_finding INFO config "Effective INI values reported by the binary (php -i)" "$EX_BIN" 0 "$EX_OUT"
    done
}

# ------------------------------------------------------ compromise triage --

# Fast prefilter: every line the classifier below can match contains one of
# these substrings, so large logs only reach awk for candidate lines.
LOG_PREFILTER_RE='exited on signal|exit signal|zend_mm_heap corrupted|free\(\): invalid|double free or corruption|malloc\(\): |corrupted size vs|segfault at|general protection|traps: |exited with code|Hard memory limit of|Allowed memory size of|Out of memory|Maximum execution time of|in Unknown on line 0'

# Date of a log line as YYYYMMDD (0 when it has none); cy/cm: current year and
# month, for syslog dates without a year.
LOG_DATE_FN='
function mon(s,   i) { i = index("JanFebMarAprMayJunJulAugSepOctNovDec", s); return i ? (i + 2) / 3 : 0 }
function ymd(line,   s, m, d, y) {
    if (match(line, /[12][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9][T ][0-9][0-9]:/)) { s = substr(line, RSTART, 10); return (substr(s, 1, 4) substr(s, 6, 2) substr(s, 9, 2)) + 0 }
    if (match(line, /[12][0-9][0-9][0-9]\/[01][0-9]\/[0-3][0-9] [0-9][0-9]:/)) { s = substr(line, RSTART, 10); return (substr(s, 1, 4) substr(s, 6, 2) substr(s, 9, 2)) + 0 }
    if (match(line, /[0-3][0-9]-[A-Z][a-z][a-z]-[12][0-9][0-9][0-9]/)) { s = substr(line, RSTART, 11); m = mon(substr(s, 4, 3)); if (m) return sprintf("%04d%02d%02d", substr(s, 8, 4), m, substr(s, 1, 2)) + 0 }
    if (match(line, /[A-Z][a-z][a-z] [A-Z][a-z][a-z] [ 0-3][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9][.0-9]* [12][0-9][0-9][0-9]/)) { s = substr(line, RSTART, RLENGTH); m = mon(substr(s, 5, 3)); if (m) return sprintf("%04d%02d%02d", substr(s, RLENGTH - 3, 4), m, substr(s, 9, 2) + 0) + 0 }
    if (match(line, /^[A-Z][a-z][a-z] [ 0-3][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) { m = mon(substr(line, 1, 3)); y = cy; if (m > cm) y = cy - 1; if (m) return sprintf("%04d%02d%02d", y, m, substr(line, 5, 2) + 0) + 0 }
    return 0
}
'

# Log-line classifier. Appends to the family records:
#   family SEP category SEP in_window SEP before SEP undated SEP example
# P2S_FAM (environment) is the log family; old=1 marks a file last written
# before the window, whose lines all count as "before".
LOG_AWK="$LOG_DATE_FN"'
{
    c = ""
    if ($0 ~ /exited on signal (4|6|7|8|11) / || $0 ~ /exit signal (Segmentation fault|Aborted|Bus error|Illegal instruction|Floating point exception)/ || $0 ~ /zend_mm_heap corrupted/ || $0 ~ /(free\(\): invalid|double free or corruption|malloc\(\): (corrupted|unaligned|invalid)|corrupted size vs\. prev_size)/) c = "crash"
    else if ($0 ~ /(php|lsphp|httpd|apache2|frankenphp)[^ :]*\[[0-9]+\]: segfault at/) c = "crash"
    else if ($0 ~ /traps: [^ ]*(php|lsphp|httpd|apache2|frankenphp)[^ :]*\[[0-9]+\]/ || $0 ~ /(php|lsphp|httpd|apache2|frankenphp)[^ :]*\[[0-9]+\]:? general protection/) c = "crash"
    else if ($0 ~ /child [0-9]+ exited with code [1-9]/) c = "fpm-exit"
    else if ($0 ~ /Hard memory limit of [0-9]+ bytes exhausted/) c = "hard-oom"
    else if ($0 ~ /Allowed memory size of [0-9]+ bytes exhausted/ || $0 ~ /Out of memory \(allocated/) c = ($0 ~ /in Unknown on line 0/) ? "oom-prescript" : "oom"
    else if ($0 ~ /Maximum execution time of [0-9]+ seconds? exceeded/) c = "timeout"
    else if ($0 ~ /(Warning|Notice|Deprecated|Fatal error|Core Warning|Parse error).*in Unknown on line 0/) c = "prescript"
    if (c == "") next
    seen[c] = 1
    d = ymd($0)
    if (d == 0) { und[c]++; if (!(c in ex)) ex[c] = $0; next }
    if (d >= since) { win[c]++; if (!(c in exw)) exw[c] = $0 } else before[c]++
}
END {
    fam = ENVIRON["P2S_FAM"]
    for (c in seen) {
        e = (c in exw) ? exw[c] : ex[c]
        gsub(/[\001-\037\177]/, " ", e)
        # Cut at 220 bytes without leaving half a UTF-8 character.
        if (length(e) > 220) { e = substr(e, 1, 220); sub(/[\300-\377][\200-\277]*$/, "", e) }
        if (old) { before[c] += win[c] + und[c]; win[c] = 0; und[c] = 0 }
        printf "%s%s%s%s%d%s%d%s%d%s%s\n", fam, S, c, S, win[c], S, before[c], S, und[c], S, e
    }
}'

# classify_log FAMILY [OLD] < log lines: appends category counts for one file
# to the family records. NUL runs (sparse or binary files) become line breaks,
# so a huge file without newlines is never held in memory as one line.
classify_log() {
    tr '\000' '\n' | grep ${GREP_A:+"$GREP_A"} -E "$LOG_PREFILTER_RE" 2>/dev/null |
        P2S_FAM=$1 awk -v old="${2:-0}" -v since="$SINCE_NUM" -v cy="$(date +%Y)" -v cm="$(date +%m | sed 's/^0//')" -v S="$SEP" \
            "$LOG_AWK" >> "$TMPD/logagg.tsv"
}

# first_date < log: YYYYMMDD of the first line (0 if it has no date).
first_date() {
    dd bs=4096 count=1 2>/dev/null | head -n 1 |
        awk -v cy="$(date +%Y)" -v cm="$(date +%m | sed 's/^0//')" "$LOG_DATE_FN"'NR == 1 { d = ymd($0) } END { print d + 0 }'
}

# log_cat FILE: the file's text, decompressed by extension.
log_cat() {
    case $1 in
        *.gz) gzip -dc "$1" 2>/dev/null ;;
        *.xz) if have xz; then xz -dc "$1" 2>/dev/null; fi ;;
        *.bz2) if have bzip2; then bzip2 -dc "$1" 2>/dev/null; fi ;;
        *.zst) if have zstd; then zstd -dc "$1" 2>/dev/null; fi ;;
        *) cat "$1" 2>/dev/null ;;
    esac
}

# log_family PATH: the log a rotated file belongs to (error.log.1,
# error.log.2.gz and error_log-20261020 belong to error.log / error_log).
log_family() { printf '%s\n' "$1" | sed -E 's/\.(gz|xz|bz2|zst)$//; s/\.[0-9]+$//; s/-[0-9]{8}$//'; }

# date_minus DATE DAYS: YYYY-MM-DD, DAYS before DATE (civil-calendar arithmetic).
date_minus() {
    awk -v s="$1" -v n="$2" '
        function dfc(y, m, d,   era, yoe, doy) { y -= (m <= 2); era = int((y >= 0 ? y : y - 399) / 400); yoe = y - era * 400
            doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1; return era * 146097 + yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy - 719468 }
        function cfd(z,   era, doe, yoe, doy, mp, d, m) { z += 719468; era = int((z >= 0 ? z : z - 146096) / 146097); doe = z - era * 146097
            yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365); doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
            mp = int((5 * doy + 2) / 153); d = doy - int((153 * mp + 2) / 5) + 1; m = mp + (mp < 10 ? 3 : -9)
            return sprintf("%04d-%02d-%02d", yoe + era * 400 + (m <= 2), m, d) }
        BEGIN { split(s, a, "-"); print cfd(dfc(a[1] + 0, a[2] + 0, a[3] + 0) - n) }'
}

log_files() {  # log_files ROOT
    for LF_F in "$1"/var/log/php*-fpm.log* "$1"/var/log/php-fpm/* "$1"/var/log/php/* "$1"/var/log/php[0-9]*/* \
        "$1"/var/log/php*error*log* "$1"/var/log/apache2/*error*log* "$1"/var/log/httpd/*error*log* \
        "$1"/usr/local/apache/logs/error_log* "$1"/var/www/vhosts/*/logs/*error*log* \
        "$1"/var/www/vhosts/system/*/logs/*error*log* "$1"/var/log/nginx/*error*log* \
        "$1"/usr/local/lsws/logs/*error*log* "$1"/usr/local/lsws/logs/stderr.log* "$1"/var/log/kern.log* \
        "$1"/var/log/messages* "$1"/var/log/syslog* "$1"/opt/cpanel/ea-php*/root/usr/var/log/php-fpm.log* \
        "$1"/opt/cpanel/ea-php*/root/usr/var/log/php-fpm/* "$1"/var/log/plesk-php*-fpm/* \
        "$1"/opt/alt/php*/usr/var/log/php-fpm* "$1"/opt/alt/php*/var/log/php-fpm* \
        "$1"/var/opt/remi/php*/log/php-fpm/* "$1"/opt/homebrew/var/log/php-fpm.log* "$1"/usr/local/var/log/php-fpm.log*; do
        [ -f "$LF_F" ] && printf '%s\n' "$LF_F"
    done
    # error_log destinations configured in php.ini or FPM pools. A relative
    # FPM error_log is relative to the build's prefix, e.g.
    # /opt/cpanel/ea-php83/root/etc/php-fpm.conf -> /opt/cpanel/ea-php83/root/usr/var/.
    { ini_files "$1"; pool_files "$1"; } | while IFS= read -r LF_INI; do
        LF_PFX=${LF_INI#"$1"}; LF_PFX=${LF_PFX%/etc/*}
        sed -n 's/^[[:space:]]*\(php_admin_value\[\)\{0,1\}error_log\]\{0,1\}[[:space:]]*=[[:space:]]*//p' "$LF_INI" 2>/dev/null |
            tr -d '"' | sed 's/[[:space:]]*$//' | while IFS= read -r LF_P; do
                case $LF_P in
                    '') ;;
                    /*) [ -f "$1$LF_P" ] && printf '%s\n' "$1$LF_P" ;;
                    syslog) ;;
                    *) for LF_C in "$1$LF_PFX/usr/var/$LF_P" "$1$LF_PFX/var/$LF_P"; do
                           [ -f "$LF_C" ] && printf '%s\n' "$LF_C"
                       done ;;
                esac
            done
    done
}

scan_logs() {  # scan_logs SCOPE ROOT
    SL_SCOPE=$1; SL_ROOT=$2
    {
        log_files "$SL_ROOT"
        # Container runtime logs on a live host only (not inside an offline image).
        if [ "$SL_SCOPE" = host ] && [ -z "$OPT_ROOT" ]; then
            for SL_F in "$SL_ROOT"/var/lib/docker/containers/*/*-json.log* "$SL_ROOT"/var/log/pods/*/*/*.log* \
                "$SL_ROOT"/var/lib/containers/storage/overlay-containers/*/userdata/ctr.log; do
                [ -f "$SL_F" ] && printf '%s\n' "$SL_F"
            done
        fi
    } | sort -u > "$TMPD/logs.txt"
    : > "$TMPD/logagg.tsv"    # family category win before undated example, one per file
    : > "$TMPD/logfirst.tsv"  # family first-line-date, one per file read
    : > "$TMPD/logold.tsv"    # family mtime path: files last written before the window
    SL_COUNT=0
    while IFS= read -r SL_F; do
        SL_LABEL=${SL_F#"$SL_ROOT"}
        SL_FAM=$(log_family "$SL_LABEL")
        # Only files written since the window started can hold window events.
        if [ -z "$(find "$SL_F" -newer "$TMPD/since.ref" 2>/dev/null)" ]; then
            # An older rotated file shows the log covers time before the
            # window; it is read only when its family's baseline is needed.
            [ -r "$SL_F" ] && rec "$SL_FAM" "$(mtime "$SL_F")" "$SL_F" >> "$TMPD/logold.tsv"
            continue
        fi
        if [ ! -r "$SL_F" ]; then
            set_limited; add_cov "log not readable: $SL_LABEL (run as root)"; continue
        fi
        # Large logs are read in full: the grep prefilter streams them.
        SL_COUNT=$((SL_COUNT + 1))
        rec "$SL_FAM" "$(log_cat "$SL_F" | first_date)" >> "$TMPD/logfirst.tsv"
        log_cat "$SL_F" | classify_log "$SL_FAM" 0
    done < "$TMPD/logs.txt"
    if [ "$SL_SCOPE" = host ] && [ -z "$OPT_ROOT" ] && have journalctl; then
        # One family for the whole journal, read from two weeks before the
        # window so crashes in the window can be compared with the time before.
        SL_BASE=$(date_minus "$OPT_SINCE" 14)
        journalctl _TRANSPORT=kernel --since "$SL_BASE" -o short-iso --no-pager -q < /dev/null 2>/dev/null | classify_log journald 0
        journalctl --since "$SL_BASE" -o short-iso --no-pager -q -u 'php*' -u apache2 -u httpd -u nginx -u lsws -u 'litespeed*' -u frankenphp < /dev/null 2>/dev/null |
            classify_log journald 0
        rec journald "$(journalctl -o short-iso --no-pager -q < /dev/null 2>/dev/null | first_date)" >> "$TMPD/logfirst.tsv"
        SL_COUNT=$((SL_COUNT + 1))
        if have coredumpctl; then
            SL_CD=$(coredumpctl list --since "$OPT_SINCE" --no-pager -q < /dev/null 2>/dev/null | grep -c -E 'php|httpd|apache2|lsphp|frankenphp')
            [ "${SL_CD:-0}" -gt 0 ] && add_finding HIGH crash "$SL_CD core dumps from PHP or web server processes since $OPT_SINCE" "coredumpctl" "$SL_CD" "Inspect with: coredumpctl list --since $OPT_SINCE"
        fi
    fi
    # Crashes only in the window so far: read the newest older file of that
    # log, so routine crashes from before the window are not reported as new.
    awk -F "$SEP" '$2 == "crash" { w[$1] += $3; b[$1] += $4 } END { for (f in w) if (w[f] > 0 && b[f] == 0) print f }' \
        "$TMPD/logagg.tsv" > "$TMPD/logneed.txt"
    if [ -s "$TMPD/logneed.txt" ] && [ -s "$TMPD/logold.tsv" ]; then
        awk -F "$SEP" -v S="$SEP" -v nf="$TMPD/logneed.txt" 'BEGIN { while ((getline l < nf) > 0) need[l] = 1; close(nf) }
            ($1 in need) && (!($1 in best) || $2 + 0 > bm[$1]) { best[$1] = $3; bm[$1] = $2 + 0 }
            END { for (f in best) print f S best[f] }' "$TMPD/logold.tsv" |
        while IFS="$SEP" read -r SL_FAM SL_F; do
            log_cat "$SL_F" | classify_log "$SL_FAM" 1
        done
    fi
    # Sum the counts per family and category. A family has a baseline when it
    # covers time before the window: an older rotated file, a first line
    # dated before the window, or any line counted before it.
    awk -F "$SEP" -v S="$SEP" -v since="$SINCE_NUM" -v ff="$TMPD/logfirst.tsv" -v of="$TMPD/logold.tsv" '
        BEGIN {
            while ((getline l < ff) > 0) { split(l, a, S); if (a[2] + 0 > 0 && a[2] + 0 < since + 0) base[a[1]] = 1 }
            close(ff)
            while ((getline l < of) > 0) { split(l, a, S); base[a[1]] = 1 }
            close(of)
        }
        {
            k = $1 S $2
            if (!(k in w)) { order[++o] = k; ex[k] = ""; exw[k] = 0 }
            w[k] += $3; b[k] += $4; u[k] += $5
            if ($4 + 0 > 0) base[$1] = 1
            if ($6 != "" && (ex[k] == "" || (!exw[k] && $3 + 0 > 0))) { ex[k] = $6; exw[k] = ($3 + 0 > 0) }
        }
        END {
            for (i = 1; i <= o; i++) {
                k = order[i]; split(k, a, S)
                print a[1] S a[2] S w[k] S b[k] S u[k] S (base[a[1]] ? "yes" : "no") S ex[k]
            }
        }' "$TMPD/logagg.tsv" > "$TMPD/logfam.tsv"
    while IFS="$SEP" read -r CL_FAM CL_C CL_W CL_B CL_U CL_BASE CL_EX; do
        CL_N=$((CL_W + CL_U))
        [ "$CL_N" -gt 0 ] || continue
        CL_LABEL=$CL_FAM
        [ "$SL_SCOPE" = host ] || CL_LABEL="$SL_SCOPE:$CL_FAM"
        CL_CTX="since $OPT_SINCE ($CL_B before)"
        [ "$CL_U" -gt 0 ] && CL_CTX="$CL_CTX, $CL_U undated in a file changed since then"
        case $CL_C in
            crash) if [ "$CL_W" -gt 0 ] && [ "$CL_B" -eq 0 ] && [ "$CL_BASE" = yes ]; then CL_S=HIGH; else CL_S=REVIEW; fi
                   [ "$CL_B" -eq 0 ] && [ "$CL_BASE" = no ] && CL_CTX="$CL_CTX; this log has nothing from before $OPT_SINCE to compare with"
                   CL_T="$CL_N PHP worker crashes (segfault/abort/heap corruption) $CL_CTX" ;;
            oom-prescript) CL_S=HIGH; CL_C=oom
                   CL_T="$CL_N out-of-memory errors before any script ran ('in Unknown on line 0'): matches the CVE-2026-109618 attack pattern, $CL_CTX" ;;
            oom) CL_S=REVIEW; CL_T="$CL_N out-of-memory fatal errors $CL_CTX" ;;
            fpm-exit) CL_S=REVIEW; CL_T="$CL_N FPM children exited with an error code (FPM exits a child when request startup fails) $CL_CTX" ;;
            prescript) CL_S=REVIEW; CL_T="$CL_N diagnostics before scripts ran ('in Unknown on line 0') $CL_CTX" ;;
            timeout) CL_S=INFO; CL_T="$CL_N 'Maximum execution time exceeded' errors $CL_CTX" ;;
            hard-oom) CL_S=INFO; CL_T="$CL_N 'Hard memory limit' stops: a patched PHP cut off runaway requests $CL_CTX" ;;
            *) continue ;;
        esac
        add_finding "$CL_S" "$CL_C" "$CL_T" "$CL_LABEL" "$CL_N" "e.g. $CL_EX"
    done < "$TMPD/logfam.tsv"
    if [ "$SL_COUNT" -eq 0 ]; then
        SL_WHERE=''
        [ "$SL_SCOPE" = host ] || [ "$SL_SCOPE" = image ] || SL_WHERE=" in $SL_SCOPE"
        SL_WHEN=$OPT_SINCE
        [ "$OPT_SINCE" = "$DEFAULT_SINCE" ] && SL_WHEN="$OPT_SINCE (the day the bugs leaked)"
        add_cov "Couldn't find any PHP or web server logs written since $SL_WHEN$SL_WHERE. If your logs are kept somewhere else (for example a central logging service), search there for PHP worker crashes and 'Allowed memory size' errors."
    fi
}

# Web roots: well-known locations plus nginx/Apache configuration.
webroots_for() {  # webroots_for ROOT
    WR_R=$1
    {
        for WR_D in /var/www /srv/www /srv/http /usr/share/nginx/html /usr/local/apache/htdocs /usr/local/apache2/htdocs \
            /usr/local/lsws/Example/html /app /Library/WebServer/Documents /opt/homebrew/var/www; do
            printf '%s\n' "$WR_D"
        done
        for WR_D in "$WR_R"/home/*/public_html "$WR_R"/home/*/domains/*/public_html "$WR_R"/var/www/vhosts/*/httpdocs; do
            printf '%s\n' "${WR_D#"$WR_R"}"
        done
        web_conf_files "$WR_R" | while IFS= read -r WR_F; do
            sed -n 's/^[[:space:]]*root[[:space:]][[:space:]]*\([^;]*\);.*/\1/p; s/^[[:space:]]*[Dd]ocument[Rr]oot[[:space:]][[:space:]]*\(.*\)$/\1/p; s/^[[:space:]]*docRoot[[:space:]][[:space:]]*\(.*\)$/\1/p' "$WR_F" 2>/dev/null
        done
        [ "$WR_R" = "$HOSTROOT" ] && printf '%s' "$OPT_WEBROOTS"
    } | tr -d '"'"'" | sed 's/[[:space:]]*$//; s|/*$||' | grep -v -e '\$' -e '^$' | sort -u |
    while IFS= read -r WR_D; do
        start_path "$WR_R" "$WR_D"
        [ -d "$START_P" ] && printf '%s%s%s\n' "$(file_dev "$START_P")" "$SEP" "$WR_D"
    done | awk -F "$SEP" '
        # A root nested in one already kept is scanned with it, unless it is on
        # another device (its own volume or mount): find -xdev would skip it.
        { for (i = 1; i <= n; i++) if (kd[i] == $1 && index($2 "/", kp[i] "/") == 1) next
          n++; kp[n] = $2; kd[n] = $1; print $2 }'
}

PHP_EXT_EXPR='-name *.php -o -name *.phtml -o -name *.pht -o -name *.php[0-9] -o -name *.phar -o -name *.inc'
WEBSHELL_RE='(eval|assert)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|hex2bin|convert_uudecode)[[:space:]]*\(|(eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*@?\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)|\$_(GET|POST|REQUEST|COOKIE)[[:space:]]*\[[^]]{1,40}\][[:space:]]*\([[:space:]]*@?\$_(GET|POST|REQUEST|COOKIE)|FilesMan|b374k|WSO_VERSION|c99sh_|r57shell|IndoXploit|AnonymousFox|ALFA_DATA|alfacgiapi|p0wny'

# PHP code in an image or icon: an opening tag followed by code. A bare "<?="
# is only 3 bytes and turns up by chance in compressed image data.
IMG_CODE_RE='<\?(php[[:space:]]+|=[[:space:]]*)@?(eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec|include|include_once|require|require_once|file_put_contents|base64_decode|gzinflate|str_rot13|create_function|call_user_func)[[:space:]]*\(|<\?=[[:space:]]*@?\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
# Handler remapping of non-PHP extensions to PHP, on one line in either order.
HANDLER_RE='(AddType|AddHandler|SetHandler)[^#]*php[^#]*\.(jpe?g|png|gif|ico|txt|html?|svg|css|js)([[:space:]"]|$)|(AddType|AddHandler|SetHandler)[^#]*\.(jpe?g|png|gif|ico|txt|html?|svg|css|js)[[:space:]][^#]*php'

# examples FILE: up to 5 lines of a path list, joined with "; ".
examples() { head -n 5 "$1" | tr '\n' ';' | sed 's/;$//; s/;/; /g'; }

scan_webroots() {  # scan_webroots SCOPE ROOT
    SW_SCOPE=$1; SW_ROOT=$2
    # The extension tests as find arguments, split with globbing off so
    # *.php is not matched against the current directory.
    set -f
    # shellcheck disable=SC2086 # PHP_EXT_EXPR is a deliberate word list
    set -- $PHP_EXT_EXPR
    set +f
    webroots_for "$SW_ROOT" > "$TMPD/webroots.txt"
    if [ ! -s "$TMPD/webroots.txt" ]; then
        SW_WHERE=''
        [ "$SW_SCOPE" = host ] || [ "$SW_SCOPE" = image ] || SW_WHERE=" in $SW_SCOPE"
        add_cov "No website folders found in the usual places$SW_WHERE. If your site lives elsewhere, add it with --webroot /path/to/site."
        return 0
    fi
    : > "$TMPD/htaccess_ov.txt"
    while IFS= read -r SW_D; do
        start_path "$SW_ROOT" "$SW_D"
        SW_ABS=$START_P
        SW_LOC="$SW_SCOPE:$SW_D"
        [ "$SW_SCOPE" = host ] && SW_LOC=$SW_D
        # Every find starts with -H, so a symlinked web root (/var/www ->
        # /data/www) is searched; -xdev then applies to the target.
        find -H "$SW_ABS" -xdev \( -name node_modules -o -name .git \) -prune -o -type f \( "$@" \) \
            -newer "$TMPD/since.ref" -print 2>/dev/null | strip_root "$SW_ROOT" > "$TMPD/wr_new.txt"
        if [ -s "$TMPD/wr_new.txt" ]; then
            add_finding REVIEW webroot "$(wc -l < "$TMPD/wr_new.txt" | tr -d ' ') PHP files modified since $OPT_SINCE (compare with your deployments)" \
                "$SW_LOC" "$(wc -l < "$TMPD/wr_new.txt" | tr -d ' ')" "$(examples "$TMPD/wr_new.txt")"
        fi
        find -H "$SW_ABS" -xdev \( -name node_modules -o -name .git \) -prune -o -type f \( "$@" \) \
            \( -path '*/uploads/*' -o -path '*/upload/*' -o -path '*/pub/media/*' -o -path '*/media/*' \
               -o -path '*/images/*' -o -path '*/sites/*/files/*' \) ! -path '*/files/php/twig/*' -print 2>/dev/null |
            while IFS= read -r SW_F; do
                # Skip the empty "Silence is golden" index.php files many plugins drop into uploads.
                SW_SZ=$(wc -c 2>/dev/null < "$SW_F" | tr -d ' ')
                if [ "${SW_SZ:-0}" -lt 120 ] && grep -q -i 'silence is golden' "$SW_F" 2>/dev/null; then continue; fi
                printf '%s\n' "${SW_F#"$SW_ROOT"}"
            done > "$TMPD/wr_up.txt"
        if [ -s "$TMPD/wr_up.txt" ]; then
            add_finding REVIEW webroot "$(wc -l < "$TMPD/wr_up.txt" | tr -d ' ') PHP files inside upload or media directories" \
                "$SW_LOC" "$(wc -l < "$TMPD/wr_up.txt" | tr -d ' ')" "$(examples "$TMPD/wr_up.txt")"
        fi
        # Webshell patterns in the changed and upload-directory files (up to
        # 5 MiB each), grepped straight from find: no cap on the number of
        # files, one grep per batch, and names with newlines still match.
        {
            find -H "$SW_ABS" -xdev \( -name node_modules -o -name .git \) -prune -o -type f \( "$@" \) \
                -newer "$TMPD/since.ref" -size -5121k -exec grep -l -E "$WEBSHELL_RE" {} + 2>/dev/null
            find -H "$SW_ABS" -xdev \( -name node_modules -o -name .git \) -prune -o -type f \( "$@" \) \
                \( -path '*/uploads/*' -o -path '*/upload/*' -o -path '*/pub/media/*' -o -path '*/media/*' \
                   -o -path '*/images/*' -o -path '*/sites/*/files/*' \) ! -path '*/files/php/twig/*' \
                -size -5121k -exec grep -l -E "$WEBSHELL_RE" {} + 2>/dev/null
        } | sort -u | strip_root "$SW_ROOT" > "$TMPD/wr_shell.txt"
        if [ -s "$TMPD/wr_shell.txt" ]; then
            add_finding HIGH webshell "$(wc -l < "$TMPD/wr_shell.txt" | tr -d ' ') files match strong webshell patterns" \
                "$SW_LOC" "$(wc -l < "$TMPD/wr_shell.txt" | tr -d ' ')" "$(examples "$TMPD/wr_shell.txt")"
        fi
        # PHP or per-directory config files with a newline or other control
        # character in their path: legitimate files never have one, and it
        # hides them from tools that read file lists line by line.
        find -H "$SW_ABS" -xdev -type f \( "$@" -o -name .htaccess -o -name .user.ini \) -path '*[[:cntrl:]]*' \
            -exec printf '%s\037' {} \; 2>/dev/null > "$TMPD/wr_cntrl.raw"
        if [ -s "$TMPD/wr_cntrl.raw" ]; then
            SW_CN=$(tr -cd '\037' < "$TMPD/wr_cntrl.raw" | wc -c | tr -d ' ')
            tr '\n\037' '?\n' < "$TMPD/wr_cntrl.raw" | strip_root "$SW_ROOT" > "$TMPD/wr_cntrl.txt"
            add_finding HIGH webshell "$SW_CN PHP or per-directory config files have control characters (such as a newline) in their path, a way to hide from file listings" \
                "$SW_LOC" "$SW_CN" "$(examples "$TMPD/wr_cntrl.txt")"
        fi
        # PHP code hidden in icons (any time) or images changed in the window.
        # HIGH needs code after the opening tag; a bare "<?php " is REVIEW.
        {
            find -H "$SW_ABS" -xdev -type f -name '*.ico' -size -2048k \
                -exec grep ${GREP_A:+"$GREP_A"} -l -E "$IMG_CODE_RE|$WEBSHELL_RE" {} + 2>/dev/null
            find -H "$SW_ABS" -xdev -type f \( -name '*.jpg' -o -name '*.jpeg' -o -name '*.png' -o -name '*.gif' \) \
                -newer "$TMPD/since.ref" -size -10240k -exec grep ${GREP_A:+"$GREP_A"} -l -E "$IMG_CODE_RE|$WEBSHELL_RE" {} + 2>/dev/null
        } | strip_root "$SW_ROOT" > "$TMPD/wr_img.txt"
        if [ -s "$TMPD/wr_img.txt" ]; then
            add_finding HIGH webroot "$(wc -l < "$TMPD/wr_img.txt" | tr -d ' ') image or icon files contain PHP code" \
                "$SW_LOC" "$(wc -l < "$TMPD/wr_img.txt" | tr -d ' ')" "$(examples "$TMPD/wr_img.txt")"
        fi
        {
            find -H "$SW_ABS" -xdev -type f -name '*.ico' -size -2048k \
                -exec grep ${GREP_A:+"$GREP_A"} -l -E '<\?php[[:space:]]' {} + 2>/dev/null
            find -H "$SW_ABS" -xdev -type f \( -name '*.jpg' -o -name '*.jpeg' -o -name '*.png' -o -name '*.gif' \) \
                -newer "$TMPD/since.ref" -size -10240k -exec grep ${GREP_A:+"$GREP_A"} -l -E '<\?php[[:space:]]' {} + 2>/dev/null
        } | strip_root "$SW_ROOT" > "$TMPD/wr_img_tag.txt"
        if [ -s "$TMPD/wr_img.txt" ]; then
            grep -v -x -F -f "$TMPD/wr_img.txt" "$TMPD/wr_img_tag.txt" > "$TMPD/wr_img_rev.txt"
        else
            cat "$TMPD/wr_img_tag.txt" > "$TMPD/wr_img_rev.txt"
        fi
        if [ -s "$TMPD/wr_img_rev.txt" ]; then
            add_finding REVIEW webroot "$(wc -l < "$TMPD/wr_img_rev.txt" | tr -d ' ') image or icon files contain a PHP opening tag" \
                "$SW_LOC" "$(wc -l < "$TMPD/wr_img_rev.txt" | tr -d ' ')" "$(examples "$TMPD/wr_img_rev.txt")"
        fi
        # Configuration-based persistence: auto_prepend_file and handler
        # remapping, grepped straight from find.
        find -H "$SW_ABS" -xdev -type f \( -name '.user.ini' -o -name '.htaccess' \) \
            -exec grep -l -i -E 'auto_(prepend|append)_file' {} + 2>/dev/null |
            while IFS= read -r SW_F; do
                grep -q -i 'wordfence-waf\.php' "$SW_F" 2>/dev/null && continue
                SW_REL=${SW_F#"$SW_ROOT"}
                if [ -n "$(find "$SW_F" -newer "$TMPD/since.ref" 2>/dev/null)" ]; then
                    add_finding HIGH persistence "auto_prepend_file/auto_append_file set in a file changed since $OPT_SINCE" "$SW_LOC" 1 "$SW_REL"
                else
                    add_finding REVIEW persistence "auto_prepend_file/auto_append_file set in per-directory configuration" "$SW_LOC" 1 "$SW_REL"
                fi
            done
        find -H "$SW_ABS" -xdev -type f \( -name '.user.ini' -o -name '.htaccess' \) \
            -exec grep -l -i -E "$HANDLER_RE" {} + 2>/dev/null |
            while IFS= read -r SW_F; do
                add_finding HIGH persistence "Web server told to execute non-PHP files as PHP (handler remapping)" "$SW_LOC" 1 "${SW_F#"$SW_ROOT"}"
            done
        find -H "$SW_ABS" -xdev -type f -name '.htaccess' \
            -exec grep -l -E '^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]' {} + 2>/dev/null |
            strip_root "$SW_ROOT" >> "$TMPD/htaccess_ov.txt"
    done < "$TMPD/webroots.txt"
    if [ -s "$TMPD/htaccess_ov.txt" ]; then
        SW_FL=$(while IFS= read -r SW_F; do
                grep -q -E "$FLAGGED_INI_RE" "$SW_ROOT$SW_F" 2>/dev/null && printf '%s\n' "$SW_F"
            done < "$TMPD/htaccess_ov.txt" | head -n 5 | tr '\n' ';')
        if [ -n "$SW_FL" ]; then
            add_finding REVIEW config ".htaccess files set INI directives that emit diagnostics before request initialization (CVE-2026-109619 consumer with mod_php)" \
                "$SW_SCOPE" "$(wc -l < "$TMPD/htaccess_ov.txt" | tr -d ' ')" "$SW_FL"
        fi
    fi
    rm -f "$TMPD/htaccess_ov.txt"
}

SUSP_CMD_RE='/dev/tcp/|/dev/udp/|bash -i|sh -i|nc .*-e |ncat .*-e |socat .*exec|python[0-9.]* -c|perl -e|base64 -d|(curl|wget) .*\| *(ba|da)?sh'

scan_proc_tree() {
    [ -s "$TMPD/ps.tsv" ] || return 0
    [ -s "$TMPD/webpids.txt" ] || return 0
    awk -F "$SEP" -v S="$SEP" -v wf="$TMPD/webpids.txt" '
        BEGIN { while ((getline l < wf) > 0) web[l] = 1; close(wf) }
        { pp[$1] = $2; comm[$1] = $4 }
        END {
            for (p in comm) {
                if (comm[p] !~ /^(sh|bash|dash|ash|zsh|ksh|mksh|csh|tcsh|fish|busybox|python[0-9.]*|perl|ruby|lua|nc|ncat|netcat|socat|curl|wget|telnet|openssl|nohup|base64|xmrig|kinsing|kdevtmpfsi|minerd|cpuminer)$/) continue
                if (p in web) continue
                a = pp[p]
                for (i = 0; i < 8 && a != "" && a != "0" && a != "1"; i++) {
                    if (a in web) { print p S a S comm[p]; break }
                    a = pp[a]
                }
            }
        }' "$TMPD/ps.tsv" > "$TMPD/susp.tsv"
    while IFS="$SEP" read -r ST_PID ST_ANC ST_COMM; do
        # NULs and every other control character become spaces, so an argv
        # cannot carry terminal escape sequences into the report.
        if [ "$PROC_MODE" = ps ]; then
            ST_CMD=$(ps -o command= -p "$ST_PID" 2>/dev/null | tr '\000-\037\177' ' ' | cut -c1-4096)
        else
            ST_CMD=$(tr '\000-\037\177' ' ' 2>/dev/null < "$PROC/$ST_PID/cmdline" | cut -c1-4096)
        fi
        case $ST_CMD in *sendmail*|*exim*|*postfix*|*msmtp*|*ssmtp*|*nullmailer*) continue ;; esac
        if printf '%s' "$ST_CMD" | grep -q -E "$SUSP_CMD_RE" || printf '%s' "$ST_COMM" | grep -q -E '^(xmrig|kinsing|kdevtmpfsi|minerd|cpuminer)$'; then
            ST_S=HIGH
        else
            ST_S=REVIEW
        fi
        # Passwords and tokens passed as arguments are not printed.
        ST_SHOW=$(printf '%s\n' "$ST_CMD" | redact_cmd | trunc 160)
        add_finding "$ST_S" process "'$ST_COMM' (pid $ST_PID) running under PHP web worker pid $ST_ANC" "pid $ST_PID" 1 "cmdline: $ST_SHOW"
    done < "$TMPD/susp.tsv"
    # Web-user processes running from temp dirs or from deleted files.
    sort -u "$TMPD/webuids.txt" > "$TMPD/webuids.u"
    [ -s "$TMPD/webuids.u" ] || return 0
    awk -F "$SEP" -v uf="$TMPD/webuids.u" 'BEGIN { while ((getline l < uf) > 0) u[l] = 1; close(uf) }
        ($2 in u) { print $1 }' "$TMPD/uid.tsv" |
    while IFS= read -r ST_PID; do
        grep -q -x -F "$ST_PID" "$TMPD/webpids.txt" 2>/dev/null && continue
        if [ "$PROC_MODE" = ps ]; then
            # The executable lsof saw (ps only knows argv[0], which a process sets itself).
            ST_EXE=$(awk -F "$SEP" -v p="$ST_PID" '$1 == "exe" && $2 == p { print $4; exit }' "$TMPD/ps_img.tsv" 2>/dev/null)
            [ -n "$ST_EXE" ] || continue
        else
            ST_EXE=$(readlink "$PROC/$ST_PID/exe" 2>/dev/null) || continue
        fi
        case $ST_EXE in
            /tmp/*|/var/tmp/*|/dev/shm/*|/private/tmp/*|/private/var/tmp/*)
                add_finding HIGH process "Web-user process running from a temp directory" "pid $ST_PID" 1 "exe: $ST_EXE" ;;
            *' (deleted)')
                case ${ST_EXE##*/} in php*|lsphp*|frankenphp*|httpd*|apache2*) continue ;; esac
                ST_P=${ST_EXE% (deleted)}
                # A system binary replaced by a package upgrade (nginx after
                # apt upgrade) still runs the old file until restarted.
                case $ST_P in
                    /usr/*|/bin/*|/sbin/*|/lib*/*|/opt/*)
                        if [ -f "$PROC/$ST_PID/root$ST_P" ]; then
                            add_finding REVIEW process "Web-user process runs a binary that was replaced on disk (package upgrade?): restart it" "pid $ST_PID" 1 "exe: $ST_EXE"
                            continue
                        fi ;;
                esac
                add_finding HIGH process "Web-user process running from a deleted file" "pid $ST_PID" 1 "exe: $ST_EXE" ;;
        esac
    done
}

scan_persistence() {  # scan_persistence SCOPE ROOT
    SP_SCOPE=$1; SP_ROOT=$2
    SP_LOC=$SP_SCOPE
    : > "$TMPD/pers_new.txt"
    for SP_F in "$SP_ROOT"/var/spool/cron/crontabs/* "$SP_ROOT"/var/spool/cron/* "$SP_ROOT"/etc/crontab \
        "$SP_ROOT"/etc/cron.d/* "$SP_ROOT"/etc/cron.hourly/* "$SP_ROOT"/etc/cron.daily/*; do
        [ -f "$SP_F" ] || continue
        if grep -q -E '(curl|wget)[^|;]*\|[[:space:]]*(ba|da|z)?sh|/dev/tcp/|base64[[:space:]]+-d|/dev/shm/|/tmp/\.|bash[[:space:]]+-i|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e' "$SP_F" 2>/dev/null; then
            add_finding HIGH persistence "Cron entry with download-and-run or reverse-shell pattern" "$SP_LOC" 1 "${SP_F#"$SP_ROOT"}"
        elif [ -n "$(find "$SP_F" -newer "$TMPD/since.ref" 2>/dev/null)" ]; then
            printf '%s\n' "${SP_F#"$SP_ROOT"}" >> "$TMPD/pers_new.txt"
        fi
    done
    for SP_F in "$SP_ROOT"/etc/passwd "$SP_ROOT"/etc/shadow "$SP_ROOT"/etc/sudoers "$SP_ROOT"/etc/sudoers.d/* \
        "$SP_ROOT"/root/.ssh/authorized_keys* "$SP_ROOT"/home/*/.ssh/authorized_keys*; do
        [ -f "$SP_F" ] || continue
        [ -n "$(find "$SP_F" -newer "$TMPD/since.ref" 2>/dev/null)" ] && printf '%s\n' "${SP_F#"$SP_ROOT"}" >> "$TMPD/pers_new.txt"
    done
    if [ -d "$SP_ROOT/etc/systemd/system" ]; then
        find "$SP_ROOT/etc/systemd/system" -type f \( -name '*.service' -o -name '*.timer' \) -newer "$TMPD/since.ref" -print 2>/dev/null |
            strip_root "$SP_ROOT" >> "$TMPD/pers_new.txt"
    fi
    if [ -s "$TMPD/pers_new.txt" ]; then
        add_finding REVIEW persistence "$(wc -l < "$TMPD/pers_new.txt" | tr -d ' ') cron, systemd, account or SSH key files changed since $OPT_SINCE" \
            "$SP_LOC" "$(wc -l < "$TMPD/pers_new.txt" | tr -d ' ')" "$(examples "$TMPD/pers_new.txt")"
    fi
    # SSH keys planted for the web server account. HIGH when the file changed
    # in the window, or when the account is a service account (no login
    # shell, or a system uid). Per-user pools (Forge, cPanel, Plesk) run as
    # login users that legitimately have keys: an old file there is INFO.
    sort -u "$TMPD/webuids.txt" 2>/dev/null | while IFS= read -r SP_UID; do
        awk -F: -v u="$SP_UID" '$3 == u { print $3 ":" $7 ":" $6 }' "$SP_ROOT/etc/passwd" 2>/dev/null
    done | sort -u | while IFS=: read -r SP_U SP_SH SP_HOME; do
        [ -n "$SP_HOME" ] && [ -f "$SP_ROOT$SP_HOME/.ssh/authorized_keys" ] || continue
        SP_K="$SP_HOME/.ssh/authorized_keys"
        if [ -n "$(find "$SP_ROOT$SP_K" -newer "$TMPD/since.ref" 2>/dev/null)" ]; then
            add_finding HIGH persistence "SSH authorized_keys of the web server account changed since $OPT_SINCE" "$SP_LOC" 1 "$SP_K"
            continue
        fi
        case $SP_SH in
            ''|*/nologin|*/false|*/sync) SP_SVC=yes ;;
            *) if [ "$SP_U" -lt 500 ] 2>/dev/null || [ "$SP_U" = 65534 ]; then SP_SVC=yes; else SP_SVC=no; fi ;;
        esac
        if [ "$SP_SVC" = yes ]; then
            add_finding HIGH persistence "SSH authorized_keys exists for the web server's service account" "$SP_LOC" 1 "$SP_K"
        else
            add_finding INFO persistence "Web workers run as a login account (uid $SP_U) that has SSH keys: make sure every key is expected" "$SP_LOC" 1 "$SP_K"
        fi
    done
    SP_UID0=$(awk -F: '$3 == 0 && $1 != "root" && $1 != "toor" { printf "%s ", $1 }' "$SP_ROOT/etc/passwd" 2>/dev/null)
    [ -n "$SP_UID0" ] && add_finding HIGH persistence "Accounts other than root with UID 0" "$SP_LOC" 1 "$SP_UID0"
    if [ -s "$SP_ROOT/etc/ld.so.preload" ]; then
        if [ -n "$(find "$SP_ROOT/etc/ld.so.preload" -newer "$TMPD/since.ref" 2>/dev/null)" ]; then SP_S=HIGH; else SP_S=REVIEW; fi
        add_finding "$SP_S" persistence "/etc/ld.so.preload is set (a common rootkit technique)" "$SP_LOC" 1 "/etc/ld.so.preload"
    fi
    # Native files dropped into temp directories during the window. Java and
    # Python runtimes (Netty, JNA, PyInstaller) extract shared libraries there,
    # usually without an execute bit: those are REVIEW, executables HIGH.
    : > "$TMPD/pers_lib.txt"
    : > "$TMPD/pers_cand.txt"
    for SP_D in /tmp /var/tmp /dev/shm; do
        [ -d "$SP_ROOT$SP_D" ] || continue
        # -H: /tmp is a symlink on macOS. PHP session files are skipped up front:
        # hosts that keep sessions in /tmp can have tens of thousands.
        find -H "$SP_ROOT$SP_D" -maxdepth 3 -xdev -type f -newer "$TMPD/since.ref" ! -name 'sess_*' -print 2>/dev/null >> "$TMPD/pers_cand.txt"
    done
    if [ "$(wc -l < "$TMPD/pers_cand.txt" | tr -d ' ')" -gt 20000 ]; then
        add_cov "more than 20000 files changed in /tmp, /var/tmp and /dev/shm for $SP_SCOPE since $OPT_SINCE: only the first 20000 were checked for dropped executables"
    fi
    head -n 20000 "$TMPD/pers_cand.txt" |
        while IFS= read -r SP_F; do
            is_native_binary "$SP_F" || continue
            SP_REL=${SP_F#"$SP_ROOT"}
            SP_LIB=no
            case ${SP_F##*/} in *.so|*.so.*|*.dylib|*.node|jna*.tmp|libnetty_*) SP_LIB=yes ;; esac
            case $SP_F in */_MEI*/*|*/hsperfdata_*/*|*/jna-*/*) SP_LIB=yes ;; esac
            if [ "$SP_LIB" = no ] && [ -n "$(find "$SP_F" -prune \( -perm -100 -o -perm -010 -o -perm -001 \) -print 2>/dev/null)" ]; then
                printf '%s\n' "$SP_REL"
            else
                printf '%s\n' "$SP_REL" >> "$TMPD/pers_lib.txt"
            fi
        done > "$TMPD/pers_tmp.txt"
    if [ -s "$TMPD/pers_tmp.txt" ]; then
        add_finding HIGH persistence "$(wc -l < "$TMPD/pers_tmp.txt" | tr -d ' ') executables written to temp directories since $OPT_SINCE" \
            "$SP_LOC" "$(wc -l < "$TMPD/pers_tmp.txt" | tr -d ' ')" "$(examples "$TMPD/pers_tmp.txt")"
    fi
    if [ -s "$TMPD/pers_lib.txt" ]; then
        add_finding REVIEW persistence "$(wc -l < "$TMPD/pers_lib.txt" | tr -d ' ') native libraries or non-executable binaries written to temp directories since $OPT_SINCE (often extracted by Java or Python runtimes)" \
            "$SP_LOC" "$(wc -l < "$TMPD/pers_lib.txt" | tr -d ' ')" "$(examples "$TMPD/pers_lib.txt")"
    fi
}

vendor_notes() {
    if awk -F "$SEP" '$12 == "remi" { f = 1 } END { exit !f }' "$TMPD/inst.tsv"; then
        add_finding REVIEW vendor "PHP from rpms.remirepo.net (Remi): php.net says this repository will not have updates on 2026-10-21" \
            "packages" 0 "Switch to distribution packages or build from source so you can patch immediately."
    fi
}

# ------------------------------------------------------------------ report --

JSON_AWK='
BEGIN { for (i = 1; i < 256; i++) ORD[sprintf("%c", i)] = i }
# Keep valid UTF-8 sequences; any other byte >= 0x80 (a cut character, a
# Latin-1 file name) becomes "?", so the report is always valid JSON text.
function utf8(s,   r, i, n, c, k, j, b, ok) {
    if (s !~ /[\200-\377]/) return s
    r = ""; n = length(s); i = 1
    while (i <= n) {
        c = ORD[substr(s, i, 1)]
        if (c < 128) { r = r substr(s, i, 1); i++; continue }
        k = (c >= 194 && c <= 223) ? 1 : ((c >= 224 && c <= 239) ? 2 : ((c >= 240 && c <= 244) ? 3 : 0))
        ok = (k > 0 && i + k <= n)
        for (j = 1; ok && j <= k; j++) { b = ORD[substr(s, i + j, 1)]; if (b < 128 || b > 191) ok = 0 }
        if (ok) { r = r substr(s, i, k + 1); i += k + 1 } else { r = r "?"; i++ }
    }
    return r
}
function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); gsub(/[\001-\037\177]/, " ", s); return utf8(s) }
function str(s) { return "\"" esc(s) "\"" }
function num(s) { return (s ~ /^[0-9]+$/) ? s : 0 }
function bool(s) { return (s == "yes") ? "true" : ((s == "no") ? "false" : "null") }
FILENAME == meta { m[$1] = $2; next }
FILENAME == inst {
    ni++
    I[ni] = sprintf("{\"scope\":%s,\"path\":%s,\"sapi\":%s,\"version\":%s,\"branch\":%s,\"branch_status\":%s,\"fixed_version\":%s,\"patch_fingerprint\":%s,\"package\":{\"manager\":%s,\"name\":%s,\"version\":%s,\"origin\":%s},\"evidence\":%s,\"verdict\":%s,\"reason\":%s,\"remediation\":%s,\"running\":{\"processes\":%d,\"restart_required\":%s,\"version\":%s,\"verdict\":%s},\"exposure\":%s}",
        str($1), str($2), str($3), str($4), str($5), str($6), str($7), bool($8), str($9), str($10), str($11), str($12), str($13), str($14), str($15), str($16), num($17), bool($18), str($19), str($20), str($21))
    next
}
FILENAME == find {
    nf++
    F[nf] = sprintf("{\"severity\":%s,\"category\":%s,\"title\":%s,\"location\":%s,\"count\":%d,\"detail\":%s}", str($1), str($2), str($3), str($4), num($5), str($6))
    next
}
FILENAME == cov { if ($0 != "") { nc++; C[nc] = str($0) } next }
END {
    printf "{\"tool\":\"php2shell-check\",\"tool_version\":%s,\"checker\":\"sh\",\"data_version\":%s,\"scanned_at\":%s,", str(m["tool_version"]), str(m["data_version"]), str(m["scanned_at"])
    printf "\"host\":{\"hostname\":%s,\"platform\":%s,\"os\":%s,\"is_root\":%s},", str(m["hostname"]), str(m["platform"]), str(m["os"]), (m["is_root"] == "yes") ? "true" : "false"
    ncv = split(m["cves"], cv, " ")
    printf "\"cves\":["; for (i = 1; i <= ncv; i++) printf "%s%s", (i > 1 ? "," : ""), str(cv[i]); printf "],\"since\":%s,", str(m["since"])
    printf "\"summary\":{\"verdict\":%s,\"installations\":%d,\"vulnerable\":%d,\"fixed\":%d,\"unknown\":%d,\"restart_required\":%d,\"high_findings\":%d,\"review_findings\":%d,\"exit_code\":%d},", str(m["verdict"]), m["n"], m["vuln"], m["fixed"], m["unknown"], m["restart"], m["high"], m["review"], m["exit"]
    printf "\"installations\":["; for (i = 1; i <= ni; i++) printf "%s%s", (i > 1 ? "," : ""), I[i]; printf "],"
    printf "\"findings\":["; for (i = 1; i <= nf; i++) printf "%s%s", (i > 1 ? "," : ""), F[i]; printf "],"
    printf "\"coverage\":["; for (i = 1; i <= nc; i++) printf "%s%s", (i > 1 ? "," : ""), C[i]; printf "]}\n"
}'

json_report() {
    awk -F "$SEP" -v meta="$TMPD/meta.tsv" -v inst="$TMPD/inst.tsv" -v find="$TMPD/find.tsv" -v cov="$TMPD/cov.txt" \
        "$JSON_AWK" "$TMPD/meta.tsv" "$TMPD/inst.tsv" "$TMPD/find.tsv" "$TMPD/cov.txt"
}

colour_of() {
    case $1 in
        VULNERABLE|HIGH|RESTART) printf '%s' "$C_RED" ;;
        FIXED|NO_PHP_FOUND) printf '%s' "$C_GRN" ;;
        UNKNOWN|INCOMPLETE|REVIEW) printf '%s' "$C_YEL" ;;
        *) printf '%s' "$C_DIM" ;;
    esac
}

text_report() {
    T_CVES=$(printf '%s' "$CVE_LIST" | sed 's/ /, /g')
    printf '%sphp2shell-check %s%s · PHP2Shell (%s) · data %s\n' "$C_BLD" "$TOOL_VERSION" "$C_OFF" "$T_CVES" "$DATA_VERSION"
    printf 'Host %s · %s · root: %s · %s\n\n' "$R_HOST" "$R_OS" "$R_ISROOT" "$R_WHEN"
    printf '%sVERDICT: %s%s  %s vulnerable · %s fixed · %s unknown · %s restart required · %s high / %s review findings\n\n' \
        "$(colour_of "$R_VERDICT")$C_BLD" "$R_VERDICT" "$C_OFF" "$R_VULN" "$R_FIXED" "$R_UNKNOWN" "$R_RESTART" "$R_HIGH" "$R_REVIEW"
    if [ "$OPT_QUIET" -eq 0 ]; then
        printf '%sPHP installations%s\n' "$C_BLD" "$C_OFF"
        if [ ! -s "$TMPD/inst.tsv" ]; then
            printf '  none found (try --deep, or check containers and other hosts)\n'
        fi
        awk -F "$SEP" -v S="$SEP" '{ r = ($14 == "VULNERABLE" || $20 == "VULNERABLE" || $18 == "yes") ? 0 : (($14 == "UNKNOWN") ? 1 : 2); print r S $0 }' "$TMPD/inst.tsv" |
            sort -t "$SEP" -k1,1n | cut -d "$SEP" -f 2- |
        while IFS="$SEP" read -r T_SCOPE T_PATH T_SAPI T_VER _ _ _ _ T_PM T_PN T_PV T_PO T_EV T_VERDICT T_REASON T_REM T_RUN T_RESTART T_RUNVER T_RUNVERDICT T_EXPO; do
            T_SHOW=$T_VERDICT
            [ "$T_RUNVERDICT" = VULNERABLE ] && T_SHOW=VULNERABLE
            printf '  %s%-10s%s  %s %s  %s  [%s]\n' "$(colour_of "$T_SHOW")" "$T_SHOW" "$C_OFF" "$T_SAPI" "${T_VER:-?}" "$T_PATH" "$T_SCOPE"
            [ "$T_PM" != none ] && [ -n "$T_PN" ] && printf '              package %s %s (%s)\n' "$T_PN" "$T_PV" "${T_PO:-?}"
            if [ "$T_RUN" -gt 0 ] 2>/dev/null; then
                if [ "$T_RUN" -eq 1 ]; then T_PW=process; else T_PW=processes; fi
                printf '              running: %s %s · exposure: %s' "$T_RUN" "$T_PW" "$T_EXPO"
                [ -n "$T_RUNVER" ] && [ "$T_RUNVER" != "$T_VER" ] && printf ' · running build %s' "$T_RUNVER"
                printf '\n'
            elif [ "$PROC_UNCHECKED" = 1 ] && [ "$T_SCOPE" != image ]; then
                printf '              running processes not checked (no /proc) · exposure if serving web requests: %s\n' "$T_EXPO"
            else
                printf '              not running · exposure if serving web requests: %s\n' "$T_EXPO"
            fi
            [ "$T_RESTART" = yes ] && printf '              %sRESTART REQUIRED%s: the running code is not what is on disk\n' "$C_RED" "$C_OFF"
            printf '              %swhy: %s (evidence: %s)%s\n' "$C_DIM" "$T_REASON" "$T_EV" "$C_OFF"
            [ -n "$T_REM" ] && [ "$T_VERDICT" != FIXED ] && printf '              fix: %s\n' "$T_REM"
            if [ "$T_VERDICT" = FIXED ] && { [ "$T_RESTART" = yes ] || [ "$T_RUNVERDICT" = VULNERABLE ]; }; then
                printf '              fix: restart every process using this build\n'
            fi
        done
        printf '\n'
        if [ "$OPT_SKIP_IOC" -eq 0 ] || [ -s "$TMPD/find.tsv" ]; then
            printf '%sFindings%s (compromise window since %s)\n' "$C_BLD" "$C_OFF" "$OPT_SINCE"
            if [ ! -s "$TMPD/find.tsv" ]; then
                printf '  none\n'
            fi
            awk -F "$SEP" -v S="$SEP" '{ r = ($1 == "HIGH") ? 0 : (($1 == "REVIEW") ? 1 : 2); print r S $0 }' "$TMPD/find.tsv" |
                sort -t "$SEP" -k1,1n | cut -d "$SEP" -f 2- |
            while IFS="$SEP" read -r T_SEV T_CAT T_TITLE T_LOC _ T_DET; do
                printf '  %s%-6s%s  %-11s %s\n' "$(colour_of "$T_SEV")" "$T_SEV" "$C_OFF" "$T_CAT" "$T_TITLE"
                printf '          %s%s%s\n' "$C_DIM" "$T_LOC" "$C_OFF"
                [ -n "$T_DET" ] && printf '          %s%s%s\n' "$C_DIM" "$(printf '%s\n' "$T_DET" | trunc 240)" "$C_OFF"
            done
            [ "$OPT_SKIP_IOC" -eq 0 ] && printf '  %sNo finding is not proof of no compromise: logs rotate, and attackers clean up.%s\n' "$C_DIM" "$C_OFF"
            printf '\n'
        fi
        if [ -s "$TMPD/cov.txt" ]; then
            printf '%sCoverage gaps%s\n' "$C_BLD" "$C_OFF"
            sed 's/^/  - /' "$TMPD/cov.txt"
            printf '\n'
        fi
    fi
    printf '%sNext steps%s\n' "$C_BLD" "$C_OFF"
    T_I=1
    if [ "$R_VULN" -gt 0 ]; then
        printf '  %s. Patch: update to PHP 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or your vendor'"'"'s patched package). PHP 8.1 and older get no fix from PHP.\n' "$T_I"; T_I=$((T_I + 1))
        printf '  %s. Restart every PHP worker after patching (php-fpm, apache2/httpd, lsws, frankenphp), then re-run this check.\n' "$T_I"; T_I=$((T_I + 1))
        if awk -F "$SEP" '$3 == "mod_php" && ($14 == "VULNERABLE" || $20 == "VULNERABLE") { f = 1 } END { exit !f }' "$TMPD/inst.tsv"; then
            printf '  %s. mod_php is the highest-risk setup (pre-application RCE demonstrated): patch it first.\n' "$T_I"; T_I=$((T_I + 1))
        fi
        printf '  %s. If you cannot patch right now (partial only): memory_limit=-1 and session.upload_progress.enabled=0\n     set administratively, fatal_error_backtraces=0 on 8.5, block multipart uploads you do not need, restart workers.\n' "$T_I"; T_I=$((T_I + 1))
    elif [ "$R_RESTART" -gt 0 ]; then
        printf '  %s. Restart the processes marked RESTART REQUIRED, then re-run this check.\n' "$T_I"; T_I=$((T_I + 1))
    elif [ "$PROC_UNCHECKED" = 1 ] && [ "$R_N" -gt 0 ]; then
        printf '  %s. Restart every PHP service (php-fpm, httpd/apache, lsws, frankenphp) after patching; this system cannot show whether running code is stale.\n' "$T_I"; T_I=$((T_I + 1))
    fi
    if [ "$R_HIGH" -gt 0 ]; then
        printf '  %s. Treat HIGH findings as a possible compromise: isolate the host, preserve logs, look for webshells and new accounts.\n' "$T_I"; T_I=$((T_I + 1))
    fi
    if [ $(( (R_EXIT / 2) % 2 )) -eq 1 ]; then
        if [ "$R_UNKNOWN" -gt 0 ]; then
            printf "  %s. Some PHP builds could not be classified (UNKNOWN): run '<binary> -v' and compare against 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, or update php2shell-check.\n" "$T_I"; T_I=$((T_I + 1))
        fi
        if [ "$COV_LIMITED" -eq 1 ]; then
            if [ "$R_ISROOT" = no ] && [ "$R_PLATFORM" = linux ]; then
                printf '  %s. Coverage was limited (see Coverage gaps): re-run as root for full coverage.\n' "$T_I"
            else
                printf '  %s. Coverage was limited (see Coverage gaps): check what is listed there by hand.\n' "$T_I"
            fi
            T_I=$((T_I + 1))
        fi
    fi
    if [ "$R_EXIT" -eq 0 ]; then
        printf '  %s. Nothing to do on this host. Check your other hosts and container images too.\n' "$T_I"
    fi
    printf '\n%sExit code %s%s (1 vulnerable, 2 incomplete, 4 high-severity indicators). Advisory: https://www.php.net/archive/2026.php#2026-10-21-5\n' "$C_DIM" "$R_EXIT" "$C_OFF"
}

# Tests source the file with PHP2SHELL_SOURCE_ONLY=1 to get the functions only.
[ "${PHP2SHELL_SOURCE_ONLY:-0}" = 1 ] && return 0 2>/dev/null

# ------------------------------------------------------------------- main --

set -u
umask 077

while [ $# -gt 0 ]; do
    case $1 in
        --json) OPT_JSON=1 ;;
        --json-file) [ $# -ge 2 ] || die_usage "--json-file needs a file"; OPT_JSON_FILE=$2; shift ;;
        --json-file=*) OPT_JSON_FILE=${1#*=} ;;
        --since) [ $# -ge 2 ] || die_usage "--since needs a date"; OPT_SINCE=$2; shift ;;
        --since=*) OPT_SINCE=${1#*=} ;;
        --skip-ioc) OPT_SKIP_IOC=1 ;;
        --skip-containers) OPT_SKIP_CONTAINERS=1 ;;
        --deep) OPT_DEEP=1 ;;
        --webroot) [ $# -ge 2 ] || die_usage "--webroot needs a directory"; OPT_WEBROOTS="$OPT_WEBROOTS$2$NL"; shift ;;
        --webroot=*) OPT_WEBROOTS="$OPT_WEBROOTS${1#*=}$NL" ;;
        --root) [ $# -ge 2 ] || die_usage "--root needs a directory"; OPT_ROOT=$2; shift ;;
        --root=*) OPT_ROOT=${1#*=} ;;
        --exec) OPT_EXEC=1 ;;
        --no-color) OPT_NO_COLOR=1 ;;
        -q|--quiet) OPT_QUIET=1 ;;
        -h|--help) usage; exit 0 ;;
        --version) printf 'php2shell-check %s (data %s)\n' "$TOOL_VERSION" "$DATA_VERSION"; exit 0 ;;
        *) die_usage "unknown option: $1" ;;
    esac
    shift
done

case $OPT_SINCE in
    [12][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]) ;;
    *) die_usage "--since must look like 2026-10-20" ;;
esac
SINCE_NUM=$(printf '%s' "$OPT_SINCE" | tr -d '-')

if [ -n "$OPT_ROOT" ]; then
    [ -d "$OPT_ROOT" ] || die_usage "--root: not a directory: $OPT_ROOT"
    HOSTROOT=${OPT_ROOT%/}
fi

if [ "$OPT_NO_COLOR" -eq 0 ] && [ -z "${NO_COLOR:-}" ] && [ -t 1 ] && [ "$OPT_JSON" -eq 0 ]; then
    C_RED=$(printf '\033[1;31m'); C_GRN=$(printf '\033[1;32m'); C_YEL=$(printf '\033[1;33m')
    C_BLD=$(printf '\033[1m'); C_DIM=$(printf '\033[2m'); C_OFF=$(printf '\033[0m')
fi

TMPD=$(mktemp -d 2>/dev/null || mktemp -d -t php2shell 2>/dev/null) || {
    printf 'php2shell-check: cannot create a temporary directory\n' >&2
    exit 2
}
trap 'rm -rf "$TMPD"' EXIT
trap 'exit 130' INT TERM HUP

: > "$TMPD/inst.tsv"      # installations
: > "$TMPD/find.tsv"      # findings
: > "$TMPD/cov.txt"       # coverage notes
: > "$TMPD/groups.tsv"    # running PHP process groups
: > "$TMPD/matched.txt"   # process groups already joined to an installation
: > "$TMPD/roots.tsv"     # scope SEP root prefix, one per filesystem to inspect
: > "$TMPD/webuids.txt"   # uids of PHP web workers
: > "$TMPD/webpids.txt"   # pids of PHP web workers
: > "$TMPD/versions.tsv"  # root SEP PHP version, one per installation

# Reference file for "modified since the window start" checks (POSIX touch -t).
touch -t "${SINCE_NUM}0000" "$TMPD/since.ref" 2>/dev/null || touch "$TMPD/since.ref"

if [ -n "$OPT_ROOT" ]; then
    R_PLATFORM=offline
    R_OS="$(os_field "$HOSTROOT" PRETTY_NAME) (offline image at $OPT_ROOT)"
else
    R_PLATFORM=$(uname -s 2>/dev/null | tr 'A-Z' 'a-z')
    R_OS="$(uname -sr 2>/dev/null)"
    R_PRETTY=$(os_field "$HOSTROOT" PRETTY_NAME)
    [ -n "$R_PRETTY" ] && R_OS="$R_OS · $R_PRETTY"
    if [ "$R_PLATFORM" = darwin ]; then R_OS="$R_OS · macOS $(sw_vers -productVersion 2>/dev/null)"; fi
fi
R_HOST=$(clean "$(hostname 2>/dev/null || uname -n)")
R_OS=$(clean "$R_OS")
R_WHEN=$(date -u '+%Y-%m-%d %H:%M UTC')
if [ "$(id -u 2>/dev/null)" = 0 ]; then R_ISROOT=yes; else R_ISROOT=no; fi
if [ "$R_ISROOT" = no ] && [ -z "$OPT_ROOT" ] && [ "$R_PLATFORM" = linux ]; then
    COV_LIMITED=1
    add_cov "not running as root: other users' processes, some logs and container filesystems could not be inspected"
fi

# The filesystem to inspect is the live host, or with --root an offline image.
if [ -n "$OPT_ROOT" ]; then
    rec image "$HOSTROOT" > "$TMPD/roots.tsv"
else
    rec host "$HOSTROOT" > "$TMPD/roots.tsv"
fi
scan_processes
[ "$OPT_SKIP_CONTAINERS" -eq 1 ] && add_cov "--skip-containers: running containers were not inspected"

# Loop bodies get stdin from /dev/null so nothing they run can eat roots.tsv.
while IFS="$SEP" read -r M_SCOPE M_ROOT; do
    scan_root "$M_SCOPE" "$M_ROOT" < /dev/null
done < "$TMPD/roots.tsv"
add_unmatched_groups
vendor_notes

while IFS="$SEP" read -r M_SCOPE M_ROOT; do
    check_config "$M_SCOPE" "$M_ROOT" < /dev/null
done < "$TMPD/roots.tsv"
exec_context

R_FOUND=$(wc -l < "$TMPD/inst.tsv" | tr -d ' ')
if [ "$R_FOUND" -eq 0 ] && [ "$OPT_DEEP" -eq 0 ]; then
    add_cov "Only the usual install locations were searched and no PHP build was found there: run with --deep to search the whole filesystem."
fi
if [ "$OPT_SKIP_IOC" -eq 1 ]; then
    add_cov "--skip-ioc: compromise triage was skipped"
elif [ "$R_FOUND" -eq 0 ] && [ -z "$OPT_WEBROOTS" ]; then
    # No PHP means PHP2Shell can't have been exploited here, so skip the attack
    # checks instead of reporting missing PHP logs and web roots.
    add_cov "No PHP was found on this machine, so the checks for signs of attack were skipped. If PHP runs in containers or virtual machines, run this tool inside them."
else
    [ -n "$OPT_ROOT" ] && add_cov "offline mode (--root): journald, core dumps and container runtime logs were not read"
    while IFS="$SEP" read -r M_SCOPE M_ROOT; do
        scan_logs "$M_SCOPE" "$M_ROOT" < /dev/null
        scan_webroots "$M_SCOPE" "$M_ROOT" < /dev/null
        scan_persistence "$M_SCOPE" "$M_ROOT" < /dev/null
    done < "$TMPD/roots.tsv"
    [ -z "$OPT_ROOT" ] && scan_proc_tree
fi

# Summary and exit code (docs/SPEC.md sections 6 and 7).
[ -f "$TMPD/limited" ] && COV_LIMITED=1
R_N=$(wc -l < "$TMPD/inst.tsv" | tr -d ' ')
R_VULN=$(awk -F "$SEP" '$14 == "VULNERABLE" || $20 == "VULNERABLE" || ($18 == "yes" && $20 != "FIXED") { n++ } END { print n + 0 }' "$TMPD/inst.tsv")
R_RESTART=$(awk -F "$SEP" '$18 == "yes" { n++ } END { print n + 0 }' "$TMPD/inst.tsv")
R_UNKNOWN=$(awk -F "$SEP" '$14 == "UNKNOWN" && $20 != "VULNERABLE" { n++ } END { print n + 0 }' "$TMPD/inst.tsv")
R_FIXED=$(awk -F "$SEP" '$14 == "FIXED" && $20 != "VULNERABLE" && $18 != "yes" { n++ } END { print n + 0 }' "$TMPD/inst.tsv")
R_HIGH=$(awk -F "$SEP" '$1 == "HIGH" { n++ } END { print n + 0 }' "$TMPD/find.tsv")
R_REVIEW=$(awk -F "$SEP" '$1 == "REVIEW" { n++ } END { print n + 0 }' "$TMPD/find.tsv")
R_EXIT=0
[ "$R_VULN" -gt 0 ] || [ "$R_RESTART" -gt 0 ] && R_EXIT=$((R_EXIT + 1))
{ [ "$R_UNKNOWN" -gt 0 ] || [ "$COV_LIMITED" -eq 1 ]; } && R_EXIT=$((R_EXIT + 2))
[ "$R_HIGH" -gt 0 ] && R_EXIT=$((R_EXIT + 4))
if [ "$R_VULN" -gt 0 ] || [ "$R_RESTART" -gt 0 ]; then R_VERDICT=VULNERABLE
elif [ "$R_UNKNOWN" -gt 0 ] || [ "$COV_LIMITED" -eq 1 ]; then R_VERDICT=INCOMPLETE
elif [ "$R_N" -gt 0 ]; then R_VERDICT=FIXED
else R_VERDICT=NO_PHP_FOUND; fi

{
    rec tool_version "$TOOL_VERSION"
    rec data_version "$DATA_VERSION"
    rec scanned_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    rec hostname "$(clean "$R_HOST")"
    rec platform "$R_PLATFORM"
    rec os "$(clean "$R_OS")"
    rec is_root "$R_ISROOT"
    rec cves "$CVE_LIST"
    rec since "$OPT_SINCE"
    rec verdict "$R_VERDICT"
    rec n "$R_N"; rec vuln "$R_VULN"; rec fixed "$R_FIXED"; rec unknown "$R_UNKNOWN"
    rec restart "$R_RESTART"; rec high "$R_HIGH"; rec review "$R_REVIEW"; rec exit "$R_EXIT"
} > "$TMPD/meta.tsv"

if [ -n "$OPT_JSON_FILE" ]; then
    json_report > "$OPT_JSON_FILE" || printf 'php2shell-check: could not write %s\n' "$OPT_JSON_FILE" >&2
fi
if [ "$OPT_JSON" -eq 1 ]; then
    json_report
else
    text_report
fi
exit "$R_EXIT"
