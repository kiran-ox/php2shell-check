# php2shell-check: full guide

New here? Start with the short [README](../README.md). This guide has every detail.

A read-only checker that tells you if your PHP is affected by **PHP2Shell**
(CVE-2026-109618, CVE-2026-109619), if the vulnerable code is actually running,
and if anything suggests someone has already exploited it.

Linux, macOS, BSD and containers: `php2shell-check.sh` (POSIX sh, no dependencies).
Windows, shared hosting, scanners and SIEMs: see [Other checkers](#other-checkers-in-this-repo).

---

## What PHP2Shell is

PHP2Shell is the name for two remote code execution vulnerabilities in the PHP
engine: CVE-2026-109618 (RCE via OOM corruption) and CVE-2026-109619 (RCE via
stale global state). Both are rated CVSS v4.0 **9.2** and were published by the
PHP project on 2026-10-21. The risk depends on how PHP is run: mod_php is highest
(the PHP project demonstrated RCE before any application code runs), FrankenPHP
and FPM are high, and CLI is low.

| CVE | GHSA | Title |
|---|---|---|
| CVE-2026-109618 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | RCE via OOM corruption |
| CVE-2026-109619 | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | RCE via stale global state |

- PHP advisory: <https://www.php.net/archive/2026.php#2026-10-21-5>
- Fix commit: [`506e87fa7dcd`](https://github.com/php/php-src/commit/506e87fa7dcdd306975e5b8f8265ee03527aacbf)

### Fixed versions

| Branch | Status | Fixed in |
|---|---|---|
| 8.5 | supported | **8.5.12** |
| 8.4 | supported | **8.4.27** |
| 8.3 | supported | **8.3.36** |
| 8.2 | supported (security support ends 2026-12-31) | **8.2.35** |
| 8.6 (8.6.0RC1 to RC3, 8.6.0-dev) | pre-release | not fixed yet |
| master (8.7.0-dev) | development | not fixed yet |
| 8.1, 8.0, 7.x, 5.x | end-of-life | **no fix from PHP** |

### End-of-life branches (8.1 and older)

- The PHP project does not ship a fixed release for 8.1 or older.
- PHP did publish minimal **source** backports
  (`PHP-7.4-CVE-2026-109618-109619`, `PHP-8.0-...`, `PHP-8.1-...`). Builds from
  them keep the old version number (7.4.33, 8.0.30, 8.1.34) and carry no
  fingerprint. This tool cannot tell them apart from unpatched builds, so it
  reports them as `VULNERABLE`.
- On 8.1 and older, a build is only reported `FIXED` when it carries the patch
  fingerprint, its package changelog names one of the CVEs, or its package
  version is listed as fixed in `vendor_backports` (empty in data 2026-10-21.1).

---

## What the tool answers

| Question | How it is reported |
|---|---|
| **Vulnerable?** Is a vulnerable PHP build installed? | One verdict per installation: `VULNERABLE`, `FIXED` or `UNKNOWN` |
| **Exposed?** Is it serving web requests, and is the running code the patched code? | SAPI, exposure level, running process count, `RESTART REQUIRED` |
| **Compromised?** Are there signs of exploitation since `--since`? | Findings with severity `HIGH`, `REVIEW` or `INFO` |

### How it decides

The tool reads PHP builds without running them. It checks these pieces of evidence, in this order:

1. **Embedded version string.** Every PHP build (cli, fpm, cgi, phpdbg,
   `libphp*.so` for mod_php, FrankenPHP) contains the literal
   `X-Powered-By: PHP/<version>`. The tool reads it from the file's bytes,
   including vendor suffixes such as `8.1.2-1ubuntu2.20` and pre-release suffixes
   such as `8.6.0RC3`.
2. **Patch fingerprint.** Patched builds contain the string
   `Hard memory limit of ` and the INI name `memory_hard_limit_percent`, both
   added by the fix commit. If the fingerprint is present, the build is `FIXED`,
   whatever its version number says. This catches vendor backports.
3. **Version number.** On a supported branch (8.2 to 8.5), a version at or
   above the fixed release counts as fixed, even without the fingerprint.
4. **Package changelog.** For dpkg and rpm packages, a changelog entry that names
   CVE-2026-109618 or CVE-2026-109619 counts as a fix.
5. **Vendor data.** A package version at or above a vendor fixed version listed
   in `vendor_backports` in [data/php2shell.json](../data/php2shell.json).

On Linux, running processes are read through `/proc/<pid>/exe` (and the `libphp`
mapped into Apache or a dynamically linked FrankenPHP). On macOS and BSD, which
have no `/proc`, the same facts come from `ps` and `lsof` (or FreeBSD's
`procstat`): the file each running program uses, any `libphp` it has loaded,
and their file IDs. If the running code is not the file now on disk, the
installation is marked `RESTART REQUIRED` and counts as vulnerable. Only when
none of these sources can list the running programs is the result `INCOMPLETE`
(exit bit 2), never `FIXED`.

The full contract, including the evidence order, the JSON schema and the exit
codes, is in [docs/SPEC.md](SPEC.md).

---

## Quick start (Linux, macOS, BSD)

Never pipe `curl` into `sh`. Download the files, verify them, read the script, then run it.

```sh
# 1. Download the release assets
base=https://github.com/kiran-ox/php2shell-check/releases/latest/download
for f in php2shell-check.sh php2shell-check.sh.sigstore.json SHA256SUMS; do
  curl -fsSLO "$base/$f"
done

# 2a. Check the hash (use "shasum -a 256 -c -" on macOS)
grep ' php2shell-check.sh$' SHA256SUMS | sha256sum -c -

# 2b. Check the signature (keyless cosign, signed by this repository's release workflow)
cosign verify-blob \
  --bundle php2shell-check.sh.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/kiran-ox/php2shell-check/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  php2shell-check.sh

# 3. Read it. It is one shell script with no dependencies.
less php2shell-check.sh

# 4. Run it as root for full coverage
sudo sh php2shell-check.sh
```

The hash only proves the file matches `SHA256SUMS`. The cosign check proves it
was signed by this repository's release workflow (`.github/workflows/release.yml`)
for a `v*` tag. Every release asset, including `SHA256SUMS` itself, has its own
`<file>.sigstore.json` bundle (and, for older cosign versions, a separate
`<file>.sig` and `<file>.pem`), so the same two commands work for any of them
(see [Releases](#releases)).

Without root the scan still works, but it cannot see other users' processes, some
logs or container filesystems. On Linux it says so under "Coverage gaps" and sets
exit bit 2. On macOS and BSD, bit 2 is set only when something it needed could
not be read, for example when neither `lsof` nor `procstat` can list the
running programs.

---

## Reading the report

### Installation verdicts

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | The build has no fix, or the running process uses an older vulnerable image |
| `FIXED` | Fingerprint present, version at or above the fixed release, or a vendor changelog names the CVE |
| `UNKNOWN` | The version could not be read, or the branch is newer than this tool's data |

### Summary verdict (the `VERDICT:` line)

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | At least one installation or running process is vulnerable or needs a restart |
| `INCOMPLETE` | Nothing vulnerable was seen, but an installation is `UNKNOWN` or coverage was limited (for example not root) |
| `FIXED` | Every PHP build found is fixed and running fixed code |
| `NO_PHP_FOUND` | No PHP build was found in the scanned paths (try `--deep`) |

The tool never reports "safe" because it could not see something. Anything it
skipped is listed under **Coverage gaps**.

### Evidence values

| `evidence` | Meaning |
|---|---|
| `fingerprint` | The patch fingerprint is in the binary. Strongest evidence. |
| `version` | The upstream version is at or above the fixed release (the fingerprint is missing, noted as `fingerprint-missing`) |
| `changelog` | The package changelog names CVE-2026-109618 or CVE-2026-109619 |
| `vendor-data` | The package version is at or above a vendor fixed version listed in `data/php2shell.json` |
| `none` | No evidence of a fix. The `why:` reason says why the build is vulnerable or unknown. |

Reasons for `VULNERABLE` or `UNKNOWN`: `below-fixed-version`,
`eol-no-upstream-fix`, `prerelease-unpatched`, `branch-newer-than-data`,
`version-unreadable`. On a distribution build, `vendor-may-backport` is added:
check your vendor's advisory, because the vendor may have shipped a fix this tool
could not confirm. `running-image-only` means a running process uses a PHP build
that is no longer on disk (for example a package that was removed or replaced).

Reasons for `FIXED`: `patch-fingerprint-present`,
`at-or-above-fixed-version,fingerprint-missing`, `vendor-changelog-names-cve`,
`vendor-fixed-package-version`.

### RESTART REQUIRED

The PHP file on disk was updated, but the running process still uses the old
code. This happens when the executable or `libphp` is marked `(deleted)`, the file
is newer than the process (unless the process maps that very file, as after an
FPM reload), or the running image's version or fingerprint differs.
Until you restart, the installation counts as vulnerable.

### Exposure

| SAPI | Exposure (PHP advisory) |
|---|---|
| `mod_php` (Apache `libphp*.so`) | **highest**: pre-application RCE demonstrated |
| `frankenphp`, `fpm` | **high** |
| `litespeed` (LSAPI), `cgi` | **elevated** |
| `cli`, `phpdbg` | **low**: only at risk if used to serve web requests |

### Finding severities

| Severity | Meaning | Examples |
|---|---|---|
| `HIGH` | Strong indicator. Treat as a possible compromise. | Pre-script OOM (`in Unknown on line 0`), a crash burst in a log that covers the time before the window and shows no crashes there, a shell spawned by a PHP worker, a webshell pattern, PHP code inside an image, a new UID 0 account |
| `REVIEW` | Needs a human to judge | Crashes that also happened before the window, FPM children exiting with an error, PHP files in upload folders, recently changed cron or systemd files |
| `INFO` | Context only, never changes a verdict | `session.upload_progress.enabled` is On, finite `memory_limit`, `Hard memory limit` stops logged by a patched build |

Crash and OOM counts in the window are compared with the period before it, when
the log covers it, because some servers crash routinely. A log and its rotated
files (`error.log`, `error.log.1`, `error.log.2.gz`) are counted together. When
a log has nothing from before the window, crashes are REVIEW and the finding
says there was nothing to compare with.

### Sample text report (annotated)

An Ubuntu 22.04 web server with Apache mod_php 8.1 (end-of-life, distribution
build), PHP-FPM 8.3 from the Sury repository (upgraded on disk but not restarted),
and one container running the official `php:8.4-fpm` image.

```text
php2shell-check 1.0.0 · PHP2Shell (CVE-2026-109618, CVE-2026-109619) · data 2026-10-21.1
Host web01 · Linux 5.15.0-125-generic · Ubuntu 22.04.5 LTS · root: yes · 2026-10-21 15:12 UTC

VERDICT: VULNERABLE  3 vulnerable · 2 fixed · 0 unknown · 1 restart required · 1 high / 2 review findings

PHP installations
  VULNERABLE  mod_php 8.1.2-1ubuntu2.20  /usr/lib/apache2/modules/libphp8.1.so  [host]
              package libapache2-mod-php8.1 8.1.2-1ubuntu2.20 (ubuntu)
              running: 6 processes · exposure: highest
              why: eol-no-upstream-fix,vendor-may-backport (evidence: none)
              fix: PHP 8.1 is end-of-life and gets no fix from PHP: upgrade to a supported branch (8.3 or later recommended; 8.2 security support ends 2026-12-31) or install a vendor backport, then restart every PHP worker. This is a distribution build: install your vendor's patched package if one exists
  VULNERABLE  fpm 8.3.36-1+ubuntu22.04.1+deb.sury.org+1  /usr/sbin/php-fpm8.3  [host]
              package php8.3-fpm 8.3.36-1+ubuntu22.04.1+deb.sury.org+1 (sury)
              running: 4 processes · exposure: high · running build 8.3.35-1+ubuntu22.04.1+deb.sury.org+1
              RESTART REQUIRED: the running code is not what is on disk
              why: patch-fingerprint-present (evidence: fingerprint)
              fix: restart every process using this build
  VULNERABLE  cli 8.1.2-1ubuntu2.20  /usr/bin/php8.1  [host]
              package php8.1-cli 8.1.2-1ubuntu2.20 (ubuntu)
              not running · exposure if serving web requests: low
              why: eol-no-upstream-fix,vendor-may-backport (evidence: none)
              fix: PHP 8.1 is end-of-life ...
  FIXED       fpm 8.4.27  /usr/local/sbin/php-fpm  [container:3f2a9c1d7b4e]
              running: 3 processes · exposure: high
              why: patch-fingerprint-present (evidence: fingerprint)
  FIXED       cli 8.4.27  /usr/local/bin/php  [container:3f2a9c1d7b4e]
              not running · exposure if serving web requests: low
              why: patch-fingerprint-present (evidence: fingerprint)

Findings (compromise window since 2026-10-20)
  HIGH    oom         3 out-of-memory errors before any script ran ('in Unknown on line 0'): matches the CVE-2026-109618 attack pattern, since 2026-10-20 (0 before)
          /var/log/apache2/error.log
          e.g. [Tue Oct 21 03:14:07.482913 2026] [php:error] [pid 23101] [client 203.0.113.7:51234] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
  REVIEW  crash       7 PHP worker crashes (segfault/abort/heap corruption) since 2026-10-20 (2 before)
          /var/log/apache2/error.log
          e.g. [Tue Oct 21 03:14:09.106244 2026] [mpm_prefork:notice] [pid 812] AH00052: child pid 23119 exit signal Segmentation fault (11)
  REVIEW  webroot     2 PHP files inside upload or media directories
          /var/www/shop
          /var/www/shop/wp-content/uploads/2026/10/cache.php; /var/www/shop/wp-content/uploads/wpforms/index.php
  INFO    config      session.upload_progress.enabled is On (default): the confirmed CVE-2026-109619 session path is reachable on unpatched PHP
          host
          Interim only: set session.upload_progress.enabled=0 in php.ini or the FPM pool (not ini_set or .user.ini) and restart every worker. Patching is the only fix.
  No finding is not proof of no compromise: logs rotate, and attackers clean up.

Coverage gaps
  - no PHP or web server logs changed since 2026-10-20 were found for container:3f2a9c1d7b4e (logs may live elsewhere or in a log service)

Next steps
  1. Patch: update to PHP 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or your vendor's patched package). PHP 8.1 and older get no fix from PHP.
  2. Restart every PHP worker after patching (php-fpm, apache2/httpd, lsws, frankenphp), then re-run this check.
  3. mod_php is the highest-risk setup (pre-application RCE demonstrated): patch it first.
  4. If you cannot patch right now (partial only): memory_limit=-1 and session.upload_progress.enabled=0
     set administratively, fatal_error_backtraces=0 on 8.5, block multipart uploads you do not need, restart workers.
  5. Treat HIGH findings as a possible compromise: isolate the host, preserve logs, look for webshells and new accounts.

Exit code 5 (1 vulnerable, 2 incomplete, 4 high-severity indicators). Advisory: https://www.php.net/archive/2026.php#2026-10-21-5
```

How to read it:

- **mod_php 8.1**: end-of-life with no fingerprint and no changelog entry naming the CVEs. It is the
  highest-exposure SAPI and it is running, so fix it first. `vendor-may-backport`
  means: check whether Ubuntu (for example through ESM) has shipped a fixed package.
- **php-fpm 8.3**: the file on disk is 8.3.36 and has the fingerprint, but the 4
  running workers were started from 8.3.35. Restart PHP-FPM.
- **The container's 8.4.27**: fixed (fingerprint found by reading the container
  filesystem through `/proc`).
- **HIGH oom**: out-of-memory errors before any script ran, none before the
  window. This is the CVE-2026-109618 attack pattern. Start incident response
  (see below).
- **Exit code 5** = 1 (vulnerable) + 4 (high-severity indicator).

The JSON report (`--json`) carries the same data. Its schema is in
[docs/SPEC.md, section 6](SPEC.md#6-json-report---json).

---

## Options

| Option | Description |
|---|---|
| `--json` | Print the JSON report instead of the text report |
| `--json-file FILE` | Also write the JSON report to `FILE` (the text report still goes to stdout) |
| `--since YYYY-MM-DD` | Start of the compromise-triage window. Default `2026-10-20`, the day the bugs leaked. |
| `--skip-ioc` | Only check for vulnerable PHP; skip compromise triage |
| `--skip-containers` | Don't look inside running containers |
| `--deep` | Search the whole filesystem for PHP builds (slower) |
| `--webroot DIR` | Add a web root to inspect. Repeatable. |
| `--root DIR` | Offline mode: inspect a mounted disk or an extracted image instead of the live system. Processes and restarts are not checked. |
| `--exec` | Allow running discovered PHP binaries with `-i` to read effective config values. Off by default. |
| `--no-color` | Disable colours. The `NO_COLOR` environment variable is honoured too. |
| `-q`, `--quiet` | Text report: print only the verdict and next steps |
| `-h`, `--help` | Show help |
| `--version` | Show the tool and data versions |

### Exit codes

Bit flags, added together:

| Value | Meaning |
|---|---|
| `0` | No vulnerable PHP found, no high-severity indicators |
| `1` | Vulnerable PHP found (including running code that needs a restart) |
| `2` | Incomplete: an `UNKNOWN` verdict or limited coverage (for example not root) |
| `4` | High-severity compromise indicators found |
| `64` | Usage error (bad option or argument) |

Examples: `3` = vulnerable and incomplete; `5` = vulnerable with HIGH findings.
Test individual bits (`rc & 1`) rather than comparing the whole code.

---

## Recipes

### Containers (Docker, containerd, Podman, Kubernetes nodes)

Run the script **on the node, as root**. It finds running containers through
`/proc`: each container's processes and filesystem are reachable through
`/proc/<pid>/root`, so it does not need the Docker or Kubernetes API, and it
works for any runtime. Results are labelled `[container:<id>]`.

```sh
sudo sh php2shell-check.sh               # host and running containers
sudo sh php2shell-check.sh --skip-containers   # host only
```

Stopped containers and images that are not running are not seen. Scan those with
the image recipe below.

**Kubernetes node without SSH access:**

```sh
kubectl debug node/<node> -it --profile=sysadmin --image=alpine -- sh
# in a second terminal, copy the script into root's home on the node:
kubectl cp php2shell-check.sh <debug-pod-name>:/host/root/php2shell-check.sh
# back in the debug shell:
chroot /host sh /root/php2shell-check.sh
```

Use root's home (or another directory only root can write to), not `/tmp`:
anyone on the node who can write to `/tmp` could swap the file before root runs it.

Or as a single command when the script is already on the node:
`kubectl debug node/<node> -it --image=alpine -- chroot /host sh /path/php2shell-check.sh`

Caveats:

- The node's root filesystem is mounted at `/host` in the debug pod. After
  `chroot /host`, paths are node paths, so the script must be on the node's
  filesystem (for example under `/host/root`), not just inside the debug container.
- Without `--profile=sysadmin` (needs a recent kubectl) the debug container may not be
  allowed to read other processes' `/proc/<pid>/root`. Container coverage is then
  reduced, and the report lists the gap.
- Some node OSes have no usable shell on the host (Bottlerocket) or restrict
  `chroot`. There, run the script against an exported image instead.
- The debug pod stays behind when you exit. Delete it:
  `kubectl delete pod <debug-pod-name>`.
- Your cluster's admission policy may block privileged debug pods. Get approval first.

### Container images

```sh
img=$(mktemp -d)
docker create --name p2s-scan IMAGE && docker export p2s-scan | tar -x -C "$img"
docker rm p2s-scan
sh php2shell-check.sh --root "$img"
rm -rf "$img"
```

Container names need at least two characters, so a name like `t` is refused.

- `--root` is offline: there are no processes, so there are no restart checks.
- Images built on the official `php:*` images compile PHP from source into
  `/usr/local`. They have no package, so the version and fingerprint decide.
- Slim distribution images often strip `/usr/share/doc`. Without the package
  changelog, a vendor backport may show as `VULNERABLE` with `vendor-may-backport`.
- Add `--skip-ioc` when you only want the vulnerability verdict for an image.

### Fleets

SSH loop (needs passwordless `sudo` on the targets). The script is streamed over
SSH into a fresh private directory on each host, so nothing on the target (for
example an attacker who already has the web server account) can swap the file
before it runs as root:

```sh
mkdir -p reports
while read -r h; do
  ssh "$h" 'd=$(mktemp -d) && cat > "$d/p2s.sh" && sudo sh "$d/p2s.sh" --json; rc=$?; rm -rf "$d"; exit $rc' \
    < php2shell-check.sh > "reports/$h.json"
  echo "$h exit $?"
done < hosts.txt
```

Never copy the script to a fixed path such as `/tmp/php2shell-check.sh` and run
it with `sudo`: anyone who can write to `/tmp` first could replace it.

Ansible ad-hoc (the `script` module copies and runs the file; a non-zero exit code
shows as FAILED, but the report is still written):

```sh
ansible web -b -m script -a 'php2shell-check.sh -q --json-file /root/php2shell.json'
ansible web -b -m fetch  -a 'src=/root/php2shell.json dest=reports/'
```

Aggregate with jq:

```sh
# One line per host
jq -r '[.host.hostname, .summary.verdict, .summary.vulnerable,
        .summary.restart_required, .summary.high_findings, .summary.exit_code] | @tsv' \
  $(find reports -name '*.json')

# Every vulnerable or not-yet-restarted installation, most exposed first
jq -r '.host.hostname as $h | .installations[]
       | select(.verdict == "VULNERABLE" or .running.verdict == "VULNERABLE" or .running.restart_required)
       | [({"highest":0,"high":1,"elevated":2,"low":3}[.exposure] // 4),
          $h, .exposure, .sapi, .version, .path, .scope] | @tsv' \
  $(find reports -name '*.json') | sort -n | cut -f 2-

# Every HIGH finding
jq -r '.host.hostname as $h | .findings[] | select(.severity == "HIGH")
       | [$h, .category, .title, .location] | @tsv' $(find reports -name '*.json')
```

### CI gate

Fail the build when bit 1 (vulnerable) is set. Example: scan a built image's
filesystem.

```sh
rc=0
sh php2shell-check.sh --root "$ROOTFS" --skip-ioc --json-file php2shell.json || rc=$?
if [ "$rc" -ge 64 ]; then echo "php2shell-check did not complete (exit $rc)"; exit 1; fi
if [ $((rc & 1)) -ne 0 ]; then echo "Vulnerable PHP in image (see php2shell.json)"; exit 1; fi
```

`|| rc=$?` keeps `set -e` shells from aborting before you can read the code.
Usage errors (64) and interrupts (130) are not results, so they are checked
first. Decide whether bit 2 (incomplete) should also fail your build.

---

## Other checkers in this repo

These follow the same contract ([docs/SPEC.md](SPEC.md)) and produce the
same JSON shape, with the small differences listed below.

| Checker | Where it runs | Notes |
|---|---|---|
| `php2shell-check.ps1` | Windows, Windows PowerShell 5.1 or PowerShell 7 | Parameters: `-Json`, `-Since`, `-SkipIoc`, `-Deep`, `-WebRoot`, `-NoColor`, `-Version`, `-Help` |
| `probe/php2shell-probe.php` | Shared hosting, where you can only upload PHP files | Checks the PHP that serves the site, from the inside. Released as `php2shell-probe.php`. |
| `rules/nuclei/php2shell-version-banner.yaml` | Nuclei | Banner based. Use it on your own assets only. |
| `rules/sigma/*.yml` | Your SIEM | Sigma rules for FPM crashes and pre-script OOM, crash bursts, and shells spawned by PHP workers (Linux and Windows) |

### Windows (`php2shell-check.ps1`)

Download and check the hash (and, if you have cosign, the signature as in the
[quick start](#quick-start-linux-macos-bsd), using the `.ps1`, `.ps1.sig` and
`.ps1.pem` files):

```powershell
$base = 'https://github.com/kiran-ox/php2shell-check/releases/latest/download'
foreach ($f in 'php2shell-check.ps1', 'SHA256SUMS') {
  Invoke-WebRequest -UseBasicParsing -Uri "$base/$f" -OutFile $f
}
$want = ((Select-String -Path SHA256SUMS -Pattern ' php2shell-check\.ps1$').Line -split '\s+')[0]
(Get-FileHash .\php2shell-check.ps1 -Algorithm SHA256).Hash -eq $want   # must print True
```

Run it from an elevated PowerShell (Run as Administrator) for full coverage:

```powershell
powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1
powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1 -Json | Out-File -Encoding utf8 report.json
```

| Parameter | Description |
|---|---|
| `-Json` | Print the JSON report instead of the text report |
| `-Since yyyy-MM-dd` | Start of the compromise-triage window. Default `2026-10-20`. |
| `-SkipIoc` | Only check for vulnerable PHP; skip compromise triage |
| `-Deep` | Also search every fixed drive for PHP builds (slower) |
| `-WebRoot PATH` | Extra web root(s) to triage. A comma-separated list works, also under `powershell -File`; folders that don't exist are listed under coverage gaps. |
| `-NoColor` | Plain text output |
| `-Version` | Print the tool and data versions and exit |
| `-Help` | Show help |

Same exit codes as the shell script. A bad `-Since`, an unknown or mistyped
parameter, or running it on a system that is not Windows exits with `64`.
(An ambiguous abbreviation such as `-S` is rejected by PowerShell itself before
the script starts.)

How it differs from the shell script:

- It finds PHP in well-known folders, `PATH`, IIS (FastCGI and handler
  mappings), Apache configuration and running processes. `-Deep` adds every
  fixed drive.
- It never runs PHP: there is no `-Exec`, `-Root`, `-JsonFile` or `-Quiet`, and
  no container scanning.
- Every installation has `scope` `host` and `package.manager` `none`, so the
  version and the fingerprint decide.
- `RESTART REQUIRED` means a PHP process started before its PHP DLL was last
  changed. `running` also carries `version` and `verdict`: empty when nothing
  runs, and `UNKNOWN` with an empty version when a restart is required.
- A PHP file whose build can't be found or read is reported as `UNKNOWN`,
  never dropped.
- Each installation has two extra JSON fields: `install_dir` (the PHP folder)
  and `found_by` (how it was found, for example `running under IIS FastCGI
  (w3wp.exe)`). The JSON is plain ASCII, with `\u` escapes for anything else.
- 32-bit PowerShell on 64-bit Windows (common with remote-management agents) is
  supported. It can't read 64-bit processes' loaded modules, so configuration
  is used instead, and the report says so.
- Without Administrator rights, coverage is limited and exit bit 2 is set.

### Shared-hosting probe (`probe/php2shell-probe.php`)

Use it only when you cannot run a shell on the server.

1. Set `PROBE_TOKEN` (the `define('PROBE_TOKEN', ...)` line at the top) to a
   random string of at least 16 letters and digits. The probe refuses to run
   with the placeholder `CHANGE-ME-TO-A-LONG-RANDOM-STRING` or a shorter token.
2. Upload it to your web root under a random name, for example `p2s-7f3k9q2m.php`.
3. Request it with the token in a header, so the token never lands in web
   server logs, browser history or chat link previews:

   ```sh
   curl -H 'X-Probe-Token: YOUR_TOKEN' https://your-site.example/p2s-7f3k9q2m.php
   ```

   Opening `https://your-site.example/p2s-7f3k9q2m.php?token=YOUR_TOKEN` in a
   browser also works, but then the token is in the URL. Don't paste that link
   into chat tools: their link previews would run the probe, and it would
   delete itself before you read it.

| Input | Effect |
|---|---|
| `X-Probe-Token: ...` header | Preferred way to pass the token. If present, it wins over `token=`. |
| `token=...` query parameter | Fallback. A missing or wrong token returns `403` and `Forbidden`, and nothing else. |
| `format=json` | JSON report instead of plain text |
| `keep=1` | Do not delete the file. Delete it yourself when you are done. |

- **Self-delete:** without `keep=1`, the probe deletes its own file before it
  prints the result. The report shows `Self-delete: deleted`, `skipped (keep=1)`
  or `failed`. If it failed, the report has a `REVIEW` finding: delete the file
  yourself straight away.
- **How it decides:** it reads `PHP_VERSION`, the server API and a few INI
  values. The fix is detected when the INI setting `memory_hard_limit_percent`
  exists. It never calls `phpinfo()` and sends nothing anywhere.
- **What it sees:** only the PHP build and worker pool that answered the request.
  It cannot see other PHP versions, running processes, restarts, package
  changelogs or logs, so its summary is never `FIXED`: it is `VULNERABLE`, or
  otherwise `INCOMPLETE` (exit bit 2 is always set).
- **INI overrides:** it lists per-request overrides by directive name only,
  never their values. PHP drops invalid values before the probe can see them.
- **JSON differences:** `checker` is `probe`, `host.platform` is `web`, `since`
  is `null` (the probe has no log window), the installation has `scope` `web`,
  an empty `path` and an extra `sapi_raw`, `running` carries `version` and
  `verdict`, and the report has an extra `probe` object (`file`,
  `self_delete`, `ini_available`). A release build of 8.6 or 8.7 without the
  fix marker gets `branch_status` `newer`.
- It runs on PHP 5.2 through 8.x, so it can report on end-of-life versions too.

### Nuclei template (`rules/nuclei/php2shell-version-banner.yaml`)

It sends one GET request and reads the PHP version from the `X-Powered-By` or
`Server` response header. It matches versions below the fixed releases
(`before-fixed-version`, which includes every 8.1 and older version and
pre-releases of a fixed version, such as 8.5.12RC1) and 8.6 or 8.7
alpha/beta/RC/dev builds (`prerelease`).

```sh
nuclei -t rules/nuclei/php2shell-version-banner.yaml -u https://www.example.com
nuclei -t rules/nuclei/php2shell-version-banner.yaml -l my-own-sites.txt
```

- A missing banner proves nothing: many sites hide it (`expose_php=Off`, proxies, CDNs).
- A match can be a false positive: distributions backport fixes without changing
  the version number. Confirm on the host with `php2shell-check.sh`.
- Only scan assets you own or are authorised to test.

### Sigma rules (`rules/sigma/`)

| File | Rule | Log source |
|---|---|---|
| `php2shell_php_fpm_crash_burst.yml` | FPM worker crash (`exited on signal 11/6/7`, `zend_mm_heap corrupted`) or pre-script OOM (`Allowed memory size of` ... `in Unknown on line 0`), level medium | Custom: PHP-FPM and PHP error logs as raw text (`product: php`, `service: php-fpm`) |
| same file, second document | Crash burst: 5 or more of the above in 10 minutes, level high | Sigma correlation (`event_count`). Add a `group-by` on your host field. |
| `php2shell_linux_php_worker_spawns_shell.yml` | php-fpm, php-cgi, lsphp, FrankenPHP or apache2/httpd starts a shell, interpreter, network or recon tool (mail helpers excluded), level high | `linux` / `process_creation` (for example auditd or Sysmon for Linux) |
| `php2shell_windows_php_spawns_shell.yml` | php-cgi.exe, php.exe, httpd.exe or w3wp.exe starts cmd, PowerShell or a common LOLBin, level high | `windows` / `process_creation` (Sysmon or Security 4688) |

Check and convert them with [sigma-cli](https://github.com/SigmaHQ/sigma-cli)
(CI uses `sigma-cli==3.1.0`). Pick the backend and processing pipeline for your SIEM:

```sh
python -m pip install 'sigma-cli==3.1.0'
sigma check rules/sigma
sigma plugin install splunk
sigma convert -t splunk --without-pipeline rules/sigma/php2shell_linux_php_worker_spawns_shell.yml
```

The FPM log rule uses a custom log source, so map it to your PHP-FPM and PHP
error logs in your pipeline.

---

## If you are vulnerable

1. **Patch.** Update to 8.5.12, 8.4.27, 8.3.36 or 8.2.35, or install your
   vendor's package whose changelog names the CVEs.
2. **Restart every PHP worker**: php-fpm, apache2/httpd (mod_php), lsws,
   frankenphp, and any long-running php-cgi. Then re-run this check and confirm
   there is no `RESTART REQUIRED`.
3. **mod_php first.** It has the highest exposure (pre-application RCE
   demonstrated), followed by FrankenPHP and FPM.

### If you cannot patch right away (partial mitigations only)

These narrow the known attack paths. They are not fixes.

| Setting | Notes |
|---|---|
| `memory_limit=-1` | Set it administratively (`php_admin_value` in the FPM pool or Apache config), not from the application |
| `session.upload_progress.enabled=0` | Default is On. Set it in php.ini or the FPM pool, not with `ini_set()` or `.user.ini`. |
| `fatal_error_backtraces=0` | PHP 8.5 only. Default is On, and this is the confirmed RCE producer. |
| Remove invalid or deprecated per-request INI overrides | Apache `php_value` / `.htaccess` with mod_php; nginx `fastcgi_param PHP_VALUE` / `PHP_ADMIN_VALUE` with FPM |
| Never use `RLIMIT_AS` / `RLIMIT_DATA` | These cause the vulnerable allocation failure |
| Restart every worker after any change | Settings only apply to newly started workers |

If you use **rpms.remirepo.net**, it will not have updates on 2026-10-21. Switch
to distribution packages or build from source.

### End-of-life PHP (8.1 and older)

- **Best:** upgrade to a supported branch (8.3 or later recommended; 8.2 security
  support ends 2026-12-31).
- **Vendor backport:** if your distribution or a commercial LTS vendor ships a
  fixed package, install it. This tool accepts it once the package changelog names
  the CVE, or once the vendor's fixed version is added to `vendor_backports`.
- **PHP's minimal source backport branches:** you can build from them, but the
  result keeps the old version number and has no fingerprint, so this tool will
  keep reporting it as vulnerable. Record that exception
  yourself.

### If you have HIGH findings

Treat the host as possibly compromised:

1. **Preserve evidence before you change anything.** Copy the web server, PHP and
   system logs, the JSON report, and if you can, a disk snapshot and memory image.
   Do not reboot first.
2. **Contain.** Take the host out of the load balancer or isolate it at the
   network level.
3. **Look for persistence**: webshells, new or changed PHP files, `.user.ini` /
   `.htaccess` with `auto_prepend_file`, cron jobs, systemd units, SSH keys, new
   accounts, `/etc/ld.so.preload`.
4. **Rotate secrets** the PHP processes could read: database passwords, API keys,
   `.env` files, cloud credentials.
5. **Rebuild** from a known-good image where possible rather than cleaning up in
   place. Patch before returning to service.
6. **Follow your incident process** and notification obligations.

`REVIEW` findings need a human to judge: compare them with your deployments and
the host's normal crash rate.

---

## Limitations

- **Vendor backports without a changelog entry** naming the CVE, and PHP's
  **minimal source backports** for 7.4, 8.0 and 8.1, cannot be verified from the
  binary. They are reported as `VULNERABLE`. Check your vendor's advisory.
- **Binaries outside the scanned paths** (custom prefixes, unusual install
  locations) are missed. The default scan covers the usual system directories,
  `/opt`, `/usr/local/phpXX`, pkgsrc, aaPanel, Nix and per-user installs (Herd,
  herd-lite, asdf, mise, phpenv, phpbrew). Use `--deep` to search the whole
  filesystem.
- **Without root**, coverage is reduced: other users' processes, some logs and
  container filesystems. The report says so under "Coverage gaps" and sets exit
  bit 2 (always on Linux; elsewhere when a read was denied).
- **On macOS and BSD**, running programs are checked with `ps` and `lsof` (or
  `procstat`). If those can't list them, restarts can't be checked and the
  result is `INCOMPLETE` (exit bit 2): restart PHP services after patching. On
  a Mac, Docker containers run inside a hidden Linux virtual machine and can't
  be seen from the Mac itself: scan their images with `--root`.
- **Logs that were rotated away or shipped elsewhere** (journald limits, a SIEM,
  a cloud logging service) are not seen. Search those with the Sigma rules.
- **IoC heuristics are not proof.** No finding does not mean no compromise, and a
  HIGH finding is a strong reason to investigate, not a conviction.
- **No remote scanning, by design.** Run the tool on each host, or use the probe
  or the Nuclei template for what you own.

---

## Safety guarantees

- **Read-only.** No changes to the system, no service restarts, no automatic mitigation.
- **No network access and no telemetry.**
- **No exploit code** and no probing of remote hosts.
- **Nothing is executed** unless you pass `--exec` to the shell script (it then
  runs `php -i` with no input, under a 10-second timeout when `timeout` is
  available). Otherwise discovered PHP binaries
  are only read as bytes. The Windows script never runs PHP.
- **No file contents are printed.** Reports contain paths, counts and short log lines only.

The shell script creates one private temporary directory (`mktemp -d`, mode 700)
and deletes it on exit. Only `--json-file` writes elsewhere, to the path you give
it. The probe is the one exception to "read-only": it runs inside PHP by design
and deletes its own file unless you pass `keep=1`.

## Data and updates

The vulnerability data (fixed versions, fingerprints, vendor backports) is in
[data/php2shell.json](../data/php2shell.json). Each release carries a
`data_version` (currently `2026-10-21.1`), printed by `--version` and in every
report. The shell script, the Windows script and the probe each embed a copy of
the same values. `tests/run.sh` fails if the fixed versions or `data_version`
differ, and the `probe-and-rules` workflow checks the probe's copy too.

Vendor backports are added to `vendor_backports` as vendors publish fixed
packages, and released as new data versions. Re-download the latest release
before re-scanning.

## CI and releases

### What CI runs

| Workflow | When | What it runs |
|---|---|---|
| `.github/workflows/ci.yml` | every push and pull request | `shellcheck -s sh -S warning php2shell-check.sh tests/run.sh`; a JSON check of `data/php2shell.json`; `sh tests/run.sh` on Ubuntu (sh, dash, bash, busybox), macOS, and inside `debian:12`, `ubuntu:24.04`, `alpine:3.20`, `rockylinux:9` and `amazonlinux:2023`; offline `--root` scans of the official `php:8.4.26-cli`, `php:8.1-cli` and `php:7.4-cli` images (must be `VULNERABLE`) and `php:8.4.27-cli` and `php:8.5.12-cli` (must be `FIXED` by fingerprint, skipped if not yet published); a live scan that must find a running `php:8.4.26-fpm` container as `VULNERABLE` |
| `.github/workflows/windows.yml` | changes to the `.ps1`, `tests/ps1/` or the data | On Windows PowerShell and PowerShell 7: PSScriptAnalyzer (fails on errors), Pester 5 tests in `tests/ps1/`, and smoke runs (`-Json`, `-Json -SkipIoc`, text, `-Help`, a bad `-Since` that must exit 64, and a real `powershell -File` run with `-WebRoot a,b` and unknown arguments that must exit 64) |
| `.github/workflows/probe-and-rules.yml` | changes to `probe/`, `rules/` or the data | `php -l` on the probe for PHP 5.6, 7.4 and 8.1 to 8.5, plus the oldest PHP 5 image and an 8.6 RC when they can be pulled; a check that the probe's and the Nuclei template's data match `data/php2shell.json`; functional tests on PHP 8.3 and 8.5 under `php -S` (token refusal with 403, the `X-Probe-Token` header, never `FIXED`, JSON with `keep=1`, text report that deletes the file); `nuclei -validate` and banner tests built from the data; `sigma check --fail-on-issues rules/sigma` |
| `.github/workflows/release.yml` | a pushed `v*` tag | Builds, signs and publishes the release (below) |

### Releases

Pushing a `v*` tag runs `release.yml`. It:

1. Copies these files, flat, into the release: `php2shell-check.sh`,
   `php2shell-check.ps1`, `php2shell-probe.php`,
   `php2shell-version-banner.yaml`, the three `rules/sigma/*.yml` files and
   `php2shell.json`.
2. Writes `SHA256SUMS` (output of `sha256sum`) for those files.
3. Signs every file and `SHA256SUMS` with keyless cosign (cosign v2.6.1),
   producing a `<file>.sigstore.json` bundle for each, plus `<file>.sig`
   (signature) and `<file>.pem` (certificate) for older cosign versions.
4. Creates the GitHub release for the tag with these assets.

Before any of that, it refuses to publish unless the tag matches
`TOOL_VERSION` in `php2shell-check.sh` (tag `v1.0.0` for `1.0.0`) and the whole
test suite passes. A missing release file also stops it.

To verify any asset `F`:

```sh
grep " $F\$" SHA256SUMS | sha256sum -c -        # macOS: shasum -a 256 -c -
cosign verify-blob \
  --bundle "$F.sigstore.json" \
  --certificate-identity-regexp '^https://github\.com/kiran-ox/php2shell-check/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$F"
```

With an older cosign that has no `--bundle`, use
`--certificate "$F.pem" --signature "$F.sig"` instead. You can also verify
`SHA256SUMS` itself the same way, then check every file against it with
`sha256sum -c SHA256SUMS`.

## Contributing

- **False positives or false negatives:** open an issue with the `--json` output
  (remove hostnames if needed), the distribution, and the package name and version.
  If the tool reports a vulnerable build as `FIXED`, report it privately instead,
  with **Report a vulnerability** on the repository's Security tab.
- **Code changes:** keep the scripts read-only and dependency-free, and the shell
  script POSIX sh. Before opening a pull request, run what CI runs:
  - `shellcheck -s sh -S warning php2shell-check.sh tests/run.sh`
  - `sh tests/run.sh` (needs `jq`; set `TEST_SHELLS=sh,dash,bash` to pick shells)
  - for the Windows script: PSScriptAnalyzer and `Invoke-Pester ./tests/ps1`
  - for the probe: `php -l probe/php2shell-probe.php`
- If you change verdict logic, update [docs/SPEC.md](SPEC.md) first.

## License

Apache License 2.0. See [LICENSE](../LICENSE).

This tool is provided on a best-effort basis, without warranty of any kind. It
helps you prioritise. It does not replace your vendor's advisories or a proper
incident investigation.

Maintained by OX Security.
