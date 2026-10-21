# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

Each release also carries a `data_version` for `data/php2shell.json`. Data-only
updates (for example new vendor backports) get a new `data_version`.

## [1.0.0] - 2026-10-21

Initial release, data 2026-10-21.1.

### Added

- `php2shell-check.sh`: read-only POSIX sh checker for Linux, macOS, BSD and
  running containers. It reports installation verdicts from the embedded version
  string, the patch fingerprint, package changelogs and vendor data. It also
  checks running code with a restart check, SAPI exposure, and compromise triage
  from logs, processes, web roots and persistence locations. Options: `--json`,
  `--json-file`, `--since`, `--skip-ioc`, `--skip-containers`, `--deep`,
  `--webroot`, `--root` (offline images and disks), `--exec`, `--no-color`,
  `-q`/`--quiet`, `--help` and `--version`. On macOS and BSD, which have no
  `/proc`, running programs and restarts are checked with `ps` and `lsof` (or
  FreeBSD's `procstat`).
- `php2shell-check.ps1`: read-only checker for Windows (Windows PowerShell 5.1
  and PowerShell 7). It finds PHP in well-known folders, `PATH`, IIS, Apache and
  running processes, never runs PHP, and adds `install_dir` and `found_by` to
  each installation in the JSON report. Parameters: `-Json`, `-Since`,
  `-SkipIoc`, `-Deep`, `-WebRoot`, `-NoColor`, `-Version` and `-Help`.
- `probe/php2shell-probe.php`: shared-hosting probe (PHP 5.2 to 8.x). It needs
  a `PROBE_TOKEN` of at least 16 characters, passed in the `X-Probe-Token`
  header (or `token=` as a fallback), takes `format=json` and `keep=1`, never
  reports `FIXED` on its own, and deletes its own file unless `keep=1` is
  passed.
- `rules/nuclei/php2shell-version-banner.yaml`: passive Nuclei template that
  reads the PHP version from the `X-Powered-By` or `Server` header.
- Sigma rules in `rules/sigma/`: PHP-FPM worker crash or pre-script OOM, with a
  crash-burst correlation (`php2shell_php_fpm_crash_burst.yml`), PHP worker
  spawning a shell on Linux (`php2shell_linux_php_worker_spawns_shell.yml`) and
  PHP or web server spawning a shell or LOLBin on Windows
  (`php2shell_windows_php_spawns_shell.yml`).
- Text and JSON reports, and bit-flag exit codes (1 vulnerable, 2 incomplete,
  4 high-severity indicators, 64 usage error).
- `data/php2shell.json` 2026-10-21.1: fixed releases 8.5.12, 8.4.27, 8.3.36 and
  8.2.35; end-of-life, pre-release (8.6) and development (master, 8.7)
  branches; patch fingerprints; SAPI risk;
  interim mitigations.
- `docs/SPEC.md`: the detection contract shared by all checkers.
- `README.md`: a one-page "am I affected, and what do I do" guide, with the
  full reference in `docs/GUIDE.md`.
- Tests: `tests/run.sh` (POSIX sh and jq, runs under sh, dash, bash and busybox
  sh, and checks that every checker's embedded data matches
  `data/php2shell.json`) and Pester tests in `tests/ps1/`.
- CI: `ci.yml` (shellcheck, tests on Ubuntu, macOS and five distribution
  containers, offline scans of official `php` images, live container
  detection), `windows.yml` (PSScriptAnalyzer, Pester and smoke runs on both
  PowerShell editions) and `probe-and-rules.yml` (probe lint and functional
  tests, data sync, `nuclei -validate`, `sigma check`).
- Releases: `release.yml` publishes the checkers, rules and data with
  `SHA256SUMS`, and signs every asset with keyless cosign (`<file>.sig`,
  `<file>.pem`).
