# php2shell-check: detection specification

This document is the contract shared by every checker in this repository
(`php2shell-check.sh`, `php2shell-check.ps1`, `probe/php2shell-probe.php`).
If you change verdict logic, change it here first.

Vulnerability data lives in `data/php2shell.json`. The scripts embed a copy of
the same values; `tests/run.sh` fails if they drift apart.

## 1. Three separate questions

| Question | Answered by |
|---|---|
| **Vulnerable?** Is a vulnerable PHP build present? | Installation verdicts (section 3) |
| **Exposed?** Is it serving web requests, and is the running code the patched code? | SAPI role, running processes, restart check (section 4) |
| **Compromised?** Are there signs of exploitation? | Findings (section 5) |

A checker never reports "safe" because it could not see something. Anything it
could not inspect is listed under `coverage`.

## 2. Reading a PHP build without running it

Every PHP build (CLI, FPM, CGI, phpdbg, `libphp*.so` for mod_php, FrankenPHP,
`php8ts.dll`/`php8.dll` on Windows) contains this compile-time string, defined
as `SAPI_PHP_VERSION_HEADER` in `main/SAPI.h` and present since at least 5.6:

    X-Powered-By: PHP/<PHP_VERSION>

`<PHP_VERSION>` may carry a vendor suffix (`8.1.2-1ubuntu2.20`) or a
pre-release suffix (`8.6.0RC3`, `8.7.0-dev`).

Patched builds (8.2.35, 8.3.36, 8.4.27, 8.5.12 and any vendor build carrying the
full fix) also contain the **patch fingerprint**:

    Hard memory limit of 

This comes from `zend_mm_hard_limit_error()`, added by fix commit `506e87fa7dcd`.
`memory_hard_limit_percent` (new INI entry) is a secondary fingerprint.
PHP's minimal source backports for 7.4, 8.0 and 8.1 do **not** contain either
string and keep the old version number.

Checkers extract both strings by scanning the file's bytes. They do not execute
the binary unless the user opts in (`--exec`).

## 3. Installation verdict

Inputs: upstream version `V` (from section 2), branch `B` = `major.minor`,
fingerprint `F` (present / absent), optional package metadata and changelog.

Version comparison: compare the numeric `major.minor.patch` triple. A
pre-release suffix (`alpha`, `beta`, `RC`, `dev`, case-insensitive, with or
without a leading `-`) sorts **before** the release. Any other suffix is a
vendor build suffix and does not change the upstream triple.

Evidence is evaluated in this order; the first match wins:

| # | Condition | Verdict | `evidence` |
|---|---|---|---|
| 1 | `V` unreadable | `UNKNOWN` | `none` |
| 2 | `F` present | `FIXED` | `fingerprint` |
| 3 | `B` supported (8.2–8.5) and `V` >= fixed(`B`) | `FIXED` | `version` |
| 4 | Package changelog names CVE-2026-109618 or CVE-2026-109619 | `FIXED` | `changelog` |
| 5 | Package version >= a vendor fixed version in `vendor_backports` | `FIXED` | `vendor-data` |
| 6 | `B` is end-of-life (5.x, 7.x, 8.0, 8.1) | `VULNERABLE` | reason `eol-no-upstream-fix` |
| 7 | `B` is 8.6 or 8.7 (master) and `V` is a pre-release | `VULNERABLE` | reason `prerelease-unpatched` |
| 8 | `B` newer than any known branch | `UNKNOWN` | reason `branch-newer-than-data` |
| 9 | otherwise (supported branch below the fixed version) | `VULNERABLE` | reason `below-fixed-version` |

Notes:

* Rule 1: a native file named exactly like a PHP SAPI (`php`, `phpX.Y`,
  `php-X.Y`, `php-fpm*`, `php-cgi*`, `lsphp*`, `phpdbg*`, `frankenphp`,
  `libphp*.so`, `mod_php*.so`, but not `php-fpm_exporter` and similar tools)
  whose version string cannot be read (packed or stripped) is reported as
  `UNKNOWN`, never dropped. Exception: a binary that dynamically links
  `libphp*.so` (FrankenPHP) is represented by that library. A PHP build that
  cannot be read at all is listed under `coverage` and limits coverage.
* Rule 7: master (8.7.0-dev) does not have the fix yet (`data/php2shell.json`
  lists 8.7 with status `development`). A release or vendor build of 8.6/8.7,
  or any newer branch, falls under rule 8.
* Rule 3 with `F` absent is still `FIXED` (version evidence), with a
  `fingerprint-missing` note, because unusual builds may compile the message out.
* For vendor builds (package present, or vendor suffix in `V`) below the fixed
  version without rule 4/5 evidence, the reason adds `vendor-may-backport` and
  advises checking the vendor's advisory.
* Remediation target: fixed(`B`) for supported branches; "upgrade to a supported
  branch (8.3+ recommended; 8.2 security support ends 2026-12-31) or obtain a
  vendor backport" for EOL; "move to a stable release" for pre-releases.

## 4. Exposure and running code

SAPI role, from process type or file name, with the PHP advisory's risk:

| `sapi` | Detected from | `exposure` |
|---|---|---|
| `mod_php` | `libphp*.so` / `mod_php*.so` (also mapped into apache2/httpd), `php*apache*.dll` | `highest` |
| `frankenphp` | `frankenphp` binary | `high` |
| `fpm` | `php-fpm*` | `high` |
| `litespeed` | `lsphp*` | `elevated` |
| `cgi` | `php-cgi*`, and `php*` under a `cgi-bin/` directory (Debian `/usr/lib/cgi-bin/phpX.Y`) | `elevated` |
| `cli` | `php`, `phpX.Y`, `php.exe` | `low` |
| `phpdbg` | `phpdbg*` | `low` |

Running code on Linux: a running process uses its own image, which may differ
from the file now on disk. Checkers read the running image via
`/proc/<pid>/exe` (or the mapped `libphp` for mod_php and dynamically linked
FrankenPHP) and set `restart_required` when:

* the executable or mapped `libphp` is marked `(deleted)`, or
* the on-disk file is newer than the process start time and the running image
  cannot be identified by inode as that same file (the inode in
  `/proc/<pid>/maps` equal to the file's inode means it runs that very file,
  as after an FPM reload or Apache graceful restart), or
* the running image's version or fingerprint differs from the on-disk file.

A running image that is vulnerable while the on-disk file is fixed counts as
**vulnerable** until restarted. When a restart is required, the running
image's verdict uses only its own version and fingerprint, even if they look
the same as the file on disk (section 6).

A process in its own mount namespace whose root directory is the host's root
(systemd `PrivateTmp=`/`ProtectSystem=` services) belongs to the `host` scope.
A process that exits during the scan is skipped; only a process that still
exists and cannot be read counts as denied (limited coverage).

Running code without `/proc` (macOS, BSD): the process table comes from
`ps -axo pid,ppid,uid,etime,comm`, and the file each process runs, plus any
mapped `libphp`, comes from one `lsof -d txt` call (or FreeBSD's `procstat -b`
and `procstat -v`). lsof reports the inode of the running file: an inode
different from the file now at that path, or a missing file, means the process
runs a replaced image, so `restart_required` is set. The running image itself
cannot be read once replaced, so its version is empty and its verdict is
`UNKNOWN`. Without inodes (procstat), the start-time rule above applies. Only
service accounts (uid below 500) count as web users for the temp-directory
process check, because on macOS a Homebrew php-fpm runs as the logged-in user.

When neither source can list the running programs, coverage is limited and the
summary is never `FIXED` or `NO_PHP_FOUND`: a service upgraded on disk but not
restarted may still run vulnerable code. Checkers may name the PHP and web
server processes `ps` can see.

Context (never changes a verdict, reported as findings with category `config`):

* `session.upload_progress.enabled` (default On) – CVE-2026-109619 session path.
* `fatal_error_backtraces` on PHP 8.5 (default On) – confirmed RCE producer.
* `memory_limit` (finite limit makes the CVE-2026-109618 OOM controllable).
* Per-request INI overrides that can emit diagnostics before request
  initialization (CVE-2026-109619 consumer): Apache `php_value`/`php_flag`/
  `php_admin_*` and `.htaccess` (mod_php), nginx `fastcgi_param PHP_VALUE` /
  `PHP_ADMIN_VALUE` (FPM). Directives named in the advisory are flagged:
  `auto_detect_line_endings`, `filter.default`, `assert.*`, legacy `session.*`
  (`sid_length`, `sid_bits_per_character`, `use_trans_sid`, `trans_sid_tags`,
  `trans_sid_hosts`, `referer_check`, `use_only_cookies`), `report_memleaks`,
  `intl.error_level`, `mbstring.http_input`, `mbstring.http_output`,
  `mbstring.internal_encoding`, `iconv.input_encoding`, `iconv.output_encoding`,
  `iconv.internal_encoding`.
* Packages from `rpms.remirepo.net` (no updates on 2026-10-21 per php.net).

## 5. Compromise triage (findings)

Window: from `--since` (default `2026-10-20`, the day the bugs leaked) to now.
A finding has `severity` `HIGH` (strong indicator), `REVIEW` (needs a human) or
`INFO`. Counts in the window are compared with the period before it when the
log covers it, because some servers crash routinely. A log and its rotated
files (`error.log`, `error.log.1`, `error.log.2.gz`, `error_log-20261020`)
form one family and are counted together; all journald sources form one
family, read from 14 days before `--since`. A family covers the time before
the window when it has a file last written before the window, a first line
dated before it, or any line counted before it. When the window has crashes
and the family has none before, the newest older rotated file is read too.
Logs are read in full whatever their size.

| `category` | What | Severity |
|---|---|---|
| `crash` | FPM `exited on signal 4/6/7/8/11`, Apache `AH00052 ... exit signal`, kernel `segfault at` in a PHP/web process, `zend_mm_heap corrupted`, glibc heap-corruption aborts | HIGH if any in the window, none before, and the log family covers time before the window; else REVIEW (saying so when there is nothing to compare with) |
| `fpm-exit` | FPM `child N exited with code <non-zero>` (FPM exits a child when request startup fails) | REVIEW |
| `oom` | `Allowed memory size of N bytes exhausted` / `Out of memory`; pre-script (`in Unknown on line 0`) counted separately | REVIEW (HIGH if pre-script) |
| `prescript` | Warnings/deprecations/errors `in Unknown on line 0` (diagnostics before scripts run) | REVIEW |
| `timeout` | `Maximum execution time of N seconds exceeded` | INFO |
| `hard-oom` | `Hard memory limit of N bytes exhausted` (patched build stopped an attempt) | INFO |
| `process` | Shells, interpreters or network tools whose ancestor is a PHP web worker; web-user processes running from `/tmp`, `/var/tmp`, `/dev/shm` or from deleted files; known miner names | HIGH or REVIEW (REVIEW for a deleted system binary under `/usr`, `/bin`, `/sbin`, `/lib*` or `/opt` that now exists again on disk: a package upgrade) |
| `webroot` | PHP files modified in the window; PHP files in upload/media directories; PHP code inside image/icon files | REVIEW (HIGH for code in images: an opening tag followed by code, or a webshell pattern; a bare `<?php` tag is REVIEW, and a bare `<?=` is ignored because it occurs by chance in compressed data) |
| `webshell` | Strong webshell patterns in candidate files (no limit on the number of files); PHP or `.htaccess`/`.user.ini` files with a control character such as a newline in their path | HIGH |
| `persistence` | `auto_prepend_file`/`auto_append_file` in `.user.ini`/`.htaccess`; handler remapping of non-PHP extensions; cron, systemd, `authorized_keys`, `/etc/passwd`, `/etc/sudoers*`, `/etc/ld.so.preload` changed in the window; extra UID 0 accounts; executables in temp dirs | HIGH or REVIEW (see below) |

* `authorized_keys` of an account PHP web workers run as: HIGH when it changed
  in the window or the account is a service account (no login shell, or uid
  below 500); INFO for an older file of a login account (per-user pools such
  as Forge, cPanel or Plesk).
* Native files written to temp dirs in the window: HIGH when executable and
  not named like an extracted library; shared libraries and non-executable
  files (Netty, JNA, PyInstaller extract these) are REVIEW.

Checkers print file paths and short log lines only, never file contents, so
reports don't leak secrets. Per-request INI overrides are reported as
`file:line directive name`, never with their values; command lines have
password, token, key and URL-credential values replaced with `***`. Control
characters are replaced in everything printed, so file names and command
lines cannot send terminal escape sequences, and JSON output is always valid
UTF-8 (invalid bytes become `?`).

## 6. JSON report (`--json`)

```json
{
  "tool": "php2shell-check", "tool_version": "1.0.0", "checker": "sh|ps1|probe",
  "data_version": "2026-10-21.1", "scanned_at": "2026-10-21T14:05:00Z",
  "host": { "hostname": "", "platform": "linux|darwin|windows|web|offline", "os": "", "is_root": true },
  "cves": ["CVE-2026-109618", "CVE-2026-109619"], "since": "2026-10-20",
  "summary": {
    "verdict": "VULNERABLE|FIXED|NO_PHP_FOUND|INCOMPLETE",
    "installations": 0, "vulnerable": 0, "fixed": 0, "unknown": 0,
    "restart_required": 0, "high_findings": 0, "review_findings": 0, "exit_code": 0
  },
  "installations": [{
    "scope": "host|image|container:<id>|mntns:<inode>", "path": "", "sapi": "", "version": "",
    "branch": "", "branch_status": "supported|eol|prerelease|newer|unknown",
    "fixed_version": "", "patch_fingerprint": true,
    "package": { "manager": "dpkg|rpm|apk|none", "name": "", "version": "", "origin": "" },
    "evidence": "fingerprint|version|changelog|vendor-data|none",
    "verdict": "VULNERABLE|FIXED|UNKNOWN", "reason": "", "remediation": "",
    "running": { "processes": 0, "restart_required": false, "version": "", "verdict": "" }, "exposure": ""
  }],
  "findings": [{ "severity": "HIGH|REVIEW|INFO", "category": "", "title": "", "location": "", "count": 0, "detail": "" }],
  "coverage": ["what was skipped and why"]
}
```

* `since`: start of the compromise-triage window (`--since`).
* `platform` is `offline` and `scope` is `image` when a mounted disk or
  extracted image is inspected (`--root`). `mntns:<inode>` is a running mount
  namespace that is not a recognisable container.
* `branch_status` `newer`: the branch is newer than the tool's data (rule 8).
* `running.version` / `running.verdict`: the build the processes are actually
  running (empty when none run). When it differs from the file on disk, its
  verdict uses only the running image's own version and fingerprint (no
  changelog or vendor-data evidence, which describe the file on disk).

`summary.verdict`: `VULNERABLE` if any installation or running process is
vulnerable or needs a restart; otherwise `INCOMPLETE` if any verdict is
`UNKNOWN` or coverage is limited; otherwise `FIXED`, or `NO_PHP_FOUND`.

## 7. Exit codes

Bit flags, added together:

| Value | Meaning |
|---|---|
| 0 | No vulnerable PHP found, no high-severity indicators |
| 1 | Vulnerable PHP found (including running code that needs a restart) |
| 2 | Incomplete: an `UNKNOWN` verdict or limited coverage (for example not root) |
| 4 | High-severity compromise indicators found |
| 64 | Usage error |

## 8. Safety rules for every checker

* Read-only: no changes to the system, no service restarts, no automatic mitigation.
* No network access, no telemetry.
* No exploit code and no active probing of remote hosts.
* Do not execute discovered binaries unless `--exec` is given.
* Never print file contents or secrets; paths, counts and short log lines only
  (section 5 lists what is redacted).
