# php2shell-check

Check in about a minute whether a server is affected by **PHP2Shell**: two
critical bugs in PHP that let an attacker take over a website with a single web
request ([CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
[PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5)).

| Where PHP runs | Checker |
|---|---|
| Linux, macOS, BSD, and containers running on them | `php2shell-check.sh` |
| Windows (IIS, XAMPP, WAMP, Laragon) | `php2shell-check.ps1` |
| Shared hosting where you can only upload files | `php2shell-probe.php` (see the [guide](docs/GUIDE.md#shared-hosting-probe-probephp2shell-probephp)) |

You don't need to install anything, and the checkers change nothing.

## Three separate questions

The checker answers three questions, each reported separately:

| Question | What it looks at | Where it shows in the report |
|---|---|---|
| **1. Is a vulnerable PHP installed?** | The version label built into each PHP program file, and a marker that only patched versions contain | Each PHP it found is marked `VULNERABLE`, `FIXED` or `UNKNOWN` |
| **2. Is it actually running and reachable?** | Which PHP programs are running, whether they serve websites, and whether one still runs the old code after an update | `running`, `exposure` and `RESTART REQUIRED` |
| **3. Has someone already used it?** | Signs of an attack since the bugs leaked: crashes, suspicious files, odd programs | **Findings**, marked `HIGH`, `REVIEW` or `INFO` |

It never says "safe" just because it couldn't see something. Anything it couldn't
check is listed under **Coverage gaps**.

## Am I affected?

**1. Download the checker.**

Linux, macOS or BSD:

```sh
curl -fsSLO https://github.com/kiran-ox/php2shell-check/releases/latest/download/php2shell-check.sh
```

Windows (PowerShell):

```powershell
Invoke-WebRequest -UseBasicParsing -OutFile php2shell-check.ps1 https://github.com/kiran-ox/php2shell-check/releases/latest/download/php2shell-check.ps1
```

**2. Run it on the server.**

Linux, macOS or BSD:

```sh
sudo sh php2shell-check.sh
```

Windows (in PowerShell opened with "Run as Administrator"):

```powershell
powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1
```

Running as root or Administrator lets it see every program and log. Without
that the check still runs, but it sees less.

**3. Read the line that starts with `VERDICT:`**

| VERDICT | What it means | What to do |
|---|---|---|
| `VULNERABLE` | A vulnerable PHP is installed, or the old PHP is still running after an update | [Fix it](#how-to-fix) |
| `FIXED` | Every PHP found is patched, and the patched version is what is running | Nothing here. Check your other servers too. |
| `INCOMPLETE` | Nothing vulnerable seen, but it couldn't check everything | Read "Coverage gaps" in the report. Usually: run it with `sudo`. |
| `NO_PHP_FOUND` | No PHP on this machine | Nothing. If you know PHP is there, run it again with `--deep`. |

Under the verdict, the report lists every PHP it found, what's wrong with each
one, and the exact fix.

## How to fix

**Update PHP to one of these versions, or newer:**

| Your PHP | Update to |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 or older | No fix from the PHP project. Upgrade to 8.3 or newer, or install the patched package from your Linux vendor if they offer one. |

**Then restart PHP.** Updating the files isn't enough: the old PHP keeps running
until it is restarted. For example:

```sh
sudo systemctl restart php8.3-fpm        # or apache2, httpd, lsws: whatever serves your site
```

**Then run the checker again.** It should now say `FIXED`. If it says
`RESTART REQUIRED`, something is still running the old version.

If you can't update today, the [guide](docs/GUIDE.md#if-you-cannot-patch-right-away-partial-mitigations-only)
lists stop-gap settings. They lower the risk; they don't remove it.

## Has someone already used it?

The checker also looks for signs of an attack since 20 October 2026, the day the
bugs leaked:

- PHP crashing
- suspicious files in your website folder
- programs started by PHP that shouldn't be

These appear under **Findings**:

| Label | Meaning |
|---|---|
| `HIGH` | Take it seriously: treat the server as possibly broken into. See the [guide](docs/GUIDE.md#if-you-have-high-findings) for first steps. |
| `REVIEW` | Worth a look. It may be harmless, for example your own recent deployment. |
| `INFO` | Background only. Nothing to do. |

No findings is good news, but it isn't proof: logs get rotated and attackers clean up.

## Containers and many servers

| Where | How to check it |
|---|---|
| Docker or Kubernetes host | Run the checker on the host with `sudo`. Running containers are checked too. |
| A container image | Copy its files out and scan them offline. See the [guide](docs/GUIDE.md#container-images) for the four commands. |
| Many servers at once | Use `--json` for machine-readable results. See the [guide](docs/GUIDE.md#fleets). |

On a Mac, Docker containers run inside a hidden Linux machine, so check those
with the container-image steps above.

## For scripts: exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing vulnerable, no signs of attack |
| `1` | Vulnerable PHP found |
| `2` | Couldn't check everything |
| `4` | Signs of an attack found |

Codes add up: `5` means vulnerable *and* signs of an attack.

## Is it safe to run?

- **It only reads.** It never changes, restarts or deletes anything.
- **It stays offline.** It never connects to the internet and sends nothing anywhere.
- **It never runs PHP.** It reads the version label built into PHP's own files,
  and a marker that only patched versions contain.

Two deliberate exceptions:
- The shared-hosting probe deletes its own file once it has answered.
- `--exec` lets the Linux/macOS checker run `php -i` to read settings. It is off
  unless you ask for it.

## More

- [Full guide](docs/GUIDE.md): every option, how to read each line of the
  report, fleets, CI, Windows, shared hosting and detection rules
- [How it decides](docs/SPEC.md): the exact detection rules
