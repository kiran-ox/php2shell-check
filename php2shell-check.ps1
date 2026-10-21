<#
.SYNOPSIS
    php2shell-check (Windows): read-only checker for PHP2Shell
    (CVE-2026-109618 / CVE-2026-109619).

.DESCRIPTION
    Answers three separate questions (see docs/SPEC.md):
      1. Vulnerable? Is a vulnerable PHP build present?
      2. Exposed?    Is it serving web requests (IIS FastCGI, Apache mod_php),
                     and is the running code the patched code?
      3. Compromised? Are there signs of exploitation since -Since?

    Read-only. No network access, no telemetry, no exploit code. PHP binaries
    are never executed: versions are read from the file bytes.

.PARAMETER Json
    Print a JSON report (docs/SPEC.md section 6) instead of the text report.
.PARAMETER Since
    Start of the compromise-triage window, yyyy-MM-dd. Default 2026-10-20.
.PARAMETER SkipIoc
    Only check for vulnerable PHP; skip compromise triage.
.PARAMETER Deep
    Also search every fixed drive for PHP builds (slower).
.PARAMETER WebRoot
    Extra web root folder(s) to triage. A comma-separated list is split, so
    -WebRoot C:\a,C:\b also works under powershell -File.
.PARAMETER NoColor
    Plain text output.
.PARAMETER UnboundArguments
    Not a real option: catches unknown or mistyped arguments, which are a
    usage error (exit 64).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1
.EXAMPLE
    .\php2shell-check.ps1 -Json | Out-File report.json

.NOTES
    Exit code (bit flags): 1 vulnerable, 2 incomplete, 4 high-severity
    indicators, 64 usage error.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$Json,
    [string]$Since = '2026-10-20',
    [switch]$SkipIoc,
    [switch]$Deep,
    [string[]]$WebRoot = @(),
    [switch]$NoColor,
    [switch]$Help,
    [switch]$Version,
    # An unknown or mistyped parameter (or a stray value) lands here, so it is
    # reported as a usage error (exit 64) instead of failing parameter binding
    # (exit 1 under powershell -File).
    [Parameter(ValueFromRemainingArguments = $true)]
    [object[]]$UnboundArguments
)

$script:P2S_ToolVersion = '1.0.0'

# BEGIN PHP2SHELL DATA
# Keep in sync with data/php2shell.json (tests compare them).
$script:P2S_DataVersion = '2026-10-21.1'
$script:P2S_Cves = @('CVE-2026-109618', 'CVE-2026-109619')
$script:P2S_FixedVersions = @{
    '8.5' = '8.5.12'
    '8.4' = '8.4.27'
    '8.3' = '8.3.36'
    '8.2' = '8.2.35'
}
# 8.6 (status prerelease) and master 8.7 (status development) have no fix yet:
# only their pre-release builds are VULNERABLE (docs/SPEC.md section 3, rule 7).
$script:P2S_PrereleaseBranches = @('8.6', '8.7')
$script:P2S_Fingerprints = @('Hard memory limit of ', 'memory_hard_limit_percent')
# Vendor fixed versions (none published for Windows builds). Entry format:
# @{ Origin = 'xampp'; Branch = '8.1'; FixedVersion = '8.1.34-1' }
$script:P2S_VendorBackports = @()
# END PHP2SHELL DATA

$script:P2S_Exposure = @{
    'mod_php'    = 'highest'
    'frankenphp' = 'high'
    'fpm'        = 'high'
    'litespeed'  = 'elevated'
    'cgi'        = 'elevated'
    'cli'        = 'low'
    'phpdbg'     = 'low'
}
$script:P2S_ExposureRank = @{ 'highest' = 5; 'high' = 4; 'elevated' = 3; 'low' = 1 }

# Per-request INI directives the PHP advisory names as able to emit a
# diagnostic before request initialization (CVE-2026-109619 consumer).
$script:P2S_DiagnosticDirectives = @(
    'auto_detect_line_endings', 'filter.default',
    'session.sid_length', 'session.sid_bits_per_character', 'session.use_trans_sid',
    'session.trans_sid_tags', 'session.trans_sid_hosts', 'session.referer_check',
    'session.use_only_cookies', 'report_memleaks', 'intl.error_level',
    'mbstring.http_input', 'mbstring.http_output', 'mbstring.internal_encoding',
    'iconv.input_encoding', 'iconv.output_encoding', 'iconv.internal_encoding'
)

$script:P2S_CoreDllNames = @('php8ts.dll', 'php8.dll', 'php7ts.dll', 'php7.dll', 'php5ts.dll', 'php5.dll', 'php4ts.dll')

# ---------------------------------------------------------------------------
# State (reset by Reset-P2SState so tests can call functions repeatedly)
# ---------------------------------------------------------------------------
function Reset-P2SState {
    $script:P2S_Findings = [System.Collections.Generic.List[object]]::new()
    $script:P2S_Coverage = [System.Collections.Generic.List[string]]::new()
    $script:P2S_CoverageLimited = $false
    $script:P2S_InstallDirs = @{}
    # SAPI file (php-cgi.exe, php8apache2_4.dll ...) -> the build file it was resolved to.
    $script:P2S_SapiBuilds = @{}
    $script:P2S_WebRoots = [System.Collections.Generic.List[string]]::new()
    $script:P2S_IniOverrides = [System.Collections.Generic.List[object]]::new()
    $script:P2S_ApacheConfs = [System.Collections.Generic.List[object]]::new()
    $script:P2S_ErrorLogs = [System.Collections.Generic.List[string]]::new()
    $script:P2S_Processes = @()
    $script:P2S_HttpdUnreadable = [System.Collections.Generic.List[object]]::new()
    $script:P2S_IsAdmin = $false
    $script:P2S_Opt = @{ Deep = $false; SkipIoc = $false; SinceDate = (New-Object -TypeName System.DateTime -ArgumentList 2026, 10, 20); WebRoot = @() }
}
Reset-P2SState

function Format-P2SClean {
    <# Replaces control characters (C0, DEL, C1) so printed text cannot carry terminal escape sequences. #>
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [regex]::Replace($Text, '[\x00-\x1F\x7F-\x9F]', ' ')
}

function Add-P2SCoverage {
    param([string]$Text, [switch]$Limits)
    $Text = Format-P2SClean $Text
    if (-not $script:P2S_Coverage.Contains($Text)) { $script:P2S_Coverage.Add($Text) }
    if ($Limits) { $script:P2S_CoverageLimited = $true }
}

function Add-P2SFinding {
    param(
        [ValidateSet('HIGH', 'REVIEW', 'INFO')][string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$Location = '',
        [int]$Count = 1,
        [string]$Detail = ''
    )
    $script:P2S_Findings.Add([ordered]@{
            severity = $Severity
            category = $Category
            title    = (Format-P2SClean $Title)
            location = (Format-P2SClean $Location)
            count    = $Count
            detail   = (Format-P2SClean $Detail)
        })
}

function Format-P2SShort {
    # Trim a log line or command line for display: no control characters, bounded length.
    param([string]$Text, [int]$Max = 200)
    if ($null -eq $Text) { return '' }
    $t = (Format-P2SClean $Text).Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

function Format-P2SDate {
    <# Date text in the Gregorian calendar whatever the system culture (th-TH, ar-SA ...). #>
    param([datetime]$Date, [string]$Format = 'yyyy-MM-dd')
    return $Date.ToString($Format, [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-P2SDateInt {
    <# yyyyMMdd as an int. DateTime.Year/Month/Day are always Gregorian. #>
    param([datetime]$Date)
    return ($Date.Year * 10000 + $Date.Month * 100 + $Date.Day)
}

# ---------------------------------------------------------------------------
# Redaction (docs/SPEC.md section 5): command lines and task actions have
# password, token, key and URL-credential values replaced with ***.
# ---------------------------------------------------------------------------
$script:P2S_SecretNames = 'pass(?:word|wd|phrase)?|pwd|token|secret|api[-_]?key|apikey|access[-_]?key|private[-_]?key|key|auth(?:orization)?|credentials?|signature|sig|session[-_]?id|phpsessid'
$script:P2S_SecretOptions = '-p|-pw|-a|-b|--?pass(?:word|wd|phrase)?|--?pwd|--?token|--?secret|--?api[-_]?key|--?apikey|--?auth(?:-token)?|--?access-token|--?client-secret|--?key|--cookie|/p|/rp|/pw|/pass(?:word)?'
# Quantifiers are bounded where they could overlap, so a crafted command line
# cannot make the regexes backtrack for long.
$script:P2S_RedactRules = @(
    # URL credentials: scheme://user:pass@host -> scheme://***@host
    , @('(?i)\b([a-z][a-z0-9+.\-]{0,31}://)[^\s/@"'']+@', '${1}***@')
    # Authorization schemes: Bearer <token>, Basic <base64> ...
    , @('(?i)\b(bearer|basic|digest|negotiate|ntlm)\s+[a-z0-9._~+/=][a-z0-9\-._~+/=]*', '${1} ***')
    # Cookie headers: everything up to the closing quote
    , @('(?i)\b(set-cookie|cookie)(["'']?\s*[:=]\s*)[^"''\r\n]+', '${1}${2}***')
    # name=value and name: value for secret-looking names (headers, query
    # strings, --password=x, -Password:x, DB_PASSWORD=x, PGPASSWORD=x,
    # "token":"x", {\"token\":\"x\"})
    , @(('(?i)\b((?:[a-z0-9]{1,24}[-_]){0,4}[a-z0-9]{0,24}?)(' + $script:P2S_SecretNames + ')([a-z0-9_.\-]{0,24})(\\?["'']?\s{0,4}[:=]\s{0,4})(?:\\?"[^"]*"?|''[^'']*''?|[^\s"''&;,]+)'), '${1}${2}${3}${4}***')
    # user:password after -u / --user / --proxy-user (curl)
    , @('(?i)(?<=^|[\s"''])(-u|--user|--proxy-user)(\s+|=)(?:"[^"]*:[^"]*"?|''[^'']*:[^'']*''?|[^\s"'']*:[^\s"'']*)', '${1}${2}***')
    # An option followed by its secret: -p <pw> (sshpass), -pw, -a (redis-cli),
    # --password <pw>, -Password <pw>, /p <pw>, /rp <pw> (schtasks)
    , @(('(?i)(?<=^|[\s"''])(' + $script:P2S_SecretOptions + ')\s+(?!-)(?:"[^"]*"?|''[^'']*''?|[^\s"'']+)'), '${1} ***')
    # net user <name> <password>, net use \\host\share <password>
    , @('(?i)(\bnet1?(?:\.exe)?["'']?\s+user\s+(?:"[^"]*"|[^\s"/]+)\s+)(?!/)(?:"[^"]*"?|[^\s"]+)', '${1}***')
    , @('(?i)(\bnet1?(?:\.exe)?["'']?\s+use\s+(?:[a-z]:\s+)?(?:"\\\\[^"]*"|\\\\\S+)\s+)(?!/)(?:"[^"]*"?|[^\s"]+)', '${1}***')
    # ConvertTo-SecureString '<pw>' -AsPlainText
    , @('(?i)(ConvertTo-SecureString\s+(?:-String\s+)?)(?:"[^"]*"?|''[^'']*''?|[^\s"''|;)]+)', '${1}***')
)

function ConvertTo-P2SRedactedText {
    <# Hides secrets in a command line or scheduled-task action before it is printed. #>
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    # Only the first 160 characters are ever printed; bounding the input keeps the regexes fast.
    $t = $Text
    if ($t.Length -gt 2048) { $t = $t.Substring(0, 2048) }
    foreach ($rule in $script:P2S_RedactRules) { $t = [regex]::Replace($t, $rule[0], $rule[1]) }
    # Attached -p<password>: mysql/mariadb, 7-Zip, RAR and sshpass syntax. It is
    # case-sensitive (mysql -P is the port) and limited to those tools so that
    # PowerShell parameters such as -Path stay readable.
    if ($t -match '(?i)\b(mysql[a-z]*|mariadb[a-z-]*|7z[agr]?|w?rar|unrar|sshpass)(\.exe)?\b') {
        $t = [regex]::Replace($t, '(?<=^|[\s"''])(-p)(?:"[^"]*"?|''[^'']*''?|[^\s"'']+)', '${1}***')
    }
    return $t
}

function ConvertTo-P2SAsciiJson {
    <#
      Escapes every non-ASCII character of JSON text as \uXXXX, so the report
      is valid whatever the console or file encoding (PowerShell 5.1 writes
      OEM or UTF-16 text). An unpaired surrogate becomes '?'.
    #>
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator] {
        param($m)
        $v = $m.Value
        if ($v.Length -eq 2) { return ('\u{0:x4}\u{1:x4}' -f [int]$v[0], [int]$v[1]) }
        $c = [int]$v[0]
        if ($c -ge 0xD800 -and $c -le 0xDFFF) { return '?' }
        return ('\u{0:x4}' -f $c)
    }
    return [regex]::Replace($Text, '[\uD800-\uDBFF][\uDC00-\uDFFF]|[^\x00-\x7E]', $evaluator)
}

# ---------------------------------------------------------------------------
# 32-bit PowerShell on 64-bit Windows (RMM agents often run one as SYSTEM):
# System32 is redirected to SysWOW64 and $env:ProgramFiles is Program Files (x86).
# ---------------------------------------------------------------------------
function Test-P2SWow64 {
    try { return ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) }
    catch { return $false }
}

function Get-P2SSystem32 {
    <# The 64-bit System32 folder, through Sysnative when this is a 32-bit process. #>
    $win = $env:windir
    if (-not $win) { $win = $env:SystemRoot }
    if (-not $win) { $win = 'C:\Windows' }
    if (Test-P2SWow64) {
        $native = Join-Path $win 'Sysnative'
        if (Test-Path -LiteralPath $native) { return $native }
    }
    return (Join-Path $win 'System32')
}

function Get-P2SProgramFilesDirs {
    <# Both Program Files folders; ProgramW6432 is the 64-bit one even in a 32-bit process. #>
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($v in @([Environment]::GetEnvironmentVariable('ProgramW6432'), $env:ProgramFiles, [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'))) {
        if (-not [string]::IsNullOrWhiteSpace($v) -and -not $list.Contains($v)) { $list.Add($v) }
    }
    foreach ($v in $list) { $v }
}

function Split-P2SWebRootList {
    <# -WebRoot a,b arrives as one string under powershell -File: split on commas. #>
    param([object[]]$Values)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($w in @($Values)) {
        if ($null -eq $w) { continue }
        foreach ($part in ([string]$w).Split(',')) {
            $p = $part.Trim().Trim('"').Trim("'").Trim()
            if ($p -ne '' -and -not $out.Contains($p)) { $out.Add($p) }
        }
    }
    foreach ($p in $out) { $p }
}

# ---------------------------------------------------------------------------
# Versions (docs/SPEC.md section 3)
# ---------------------------------------------------------------------------
function ConvertTo-P2SVersion {
    <#
      Parses '8.3.12', '8.6.0RC3', '8.7.0-dev', '8.1.2-1ubuntu2.20'.
      Returns $null when the text does not start with major.minor.patch.
      SuffixKind: none | prerelease | vendor
    #>
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    # ASCII digits only, bounded so [int] cannot overflow on a crafted file.
    $m = [regex]::Match($Text.Trim(), '^([0-9]{1,9})\.([0-9]{1,9})\.([0-9]{1,9})(.*)$')
    if (-not $m.Success) { return $null }
    $suffix = $m.Groups[4].Value
    $kind = 'none'
    $preRank = 0
    $preNum = 0
    if ($suffix -ne '') {
        $pm = [regex]::Match($suffix, '^-?(dev|alpha|beta|rc)([0-9]{0,9})(-dev)?$', 'IgnoreCase')
        if ($pm.Success) {
            $kind = 'prerelease'
            switch ($pm.Groups[1].Value.ToLowerInvariant()) {
                'dev' { $preRank = 1 }
                'alpha' { $preRank = 2 }
                'beta' { $preRank = 3 }
                'rc' { $preRank = 4 }
            }
            if ($pm.Groups[2].Value -ne '') { $preNum = [int]$pm.Groups[2].Value }
        }
        else {
            $kind = 'vendor'
        }
    }
    return [pscustomobject]@{
        Raw        = $Text.Trim()
        Major      = [int]$m.Groups[1].Value
        Minor      = [int]$m.Groups[2].Value
        Patch      = [int]$m.Groups[3].Value
        Suffix     = $suffix
        SuffixKind = $kind
        PreRank    = $preRank
        PreNum     = $preNum
        Branch     = ('{0}.{1}' -f [int]$m.Groups[1].Value, [int]$m.Groups[2].Value)
    }
}

function Compare-P2SVersion {
    <#
      -1 if A < B, 0 if equal, 1 if A > B. Accepts strings or parsed versions.
      Pre-release sorts before the release of the same triple; vendor suffixes
      do not change the upstream triple.
    #>
    param($A, $B)
    if ($A -is [string]) { $A = ConvertTo-P2SVersion $A }
    if ($B -is [string]) { $B = ConvertTo-P2SVersion $B }
    if ($null -eq $A -or $null -eq $B) { throw 'Compare-P2SVersion: unparseable version' }
    foreach ($part in @('Major', 'Minor', 'Patch')) {
        if ($A.$part -lt $B.$part) { return -1 }
        if ($A.$part -gt $B.$part) { return 1 }
    }
    $aPre = ($A.SuffixKind -eq 'prerelease')
    $bPre = ($B.SuffixKind -eq 'prerelease')
    if ($aPre -and -not $bPre) { return -1 }
    if ($bPre -and -not $aPre) { return 1 }
    if ($aPre -and $bPre) {
        if ($A.PreRank -lt $B.PreRank) { return -1 }
        if ($A.PreRank -gt $B.PreRank) { return 1 }
        if ($A.PreNum -lt $B.PreNum) { return -1 }
        if ($A.PreNum -gt $B.PreNum) { return 1 }
    }
    return 0
}

function Get-P2SBranchInfo {
    <#
      Status: supported | eol | prerelease | newer | unknown (no version).
      prerelease: a pre-release build (RC/alpha/beta/dev) of 8.6 or 8.7 (rule 7).
      newer: a release or vendor build of 8.6/8.7, or any newer branch (rule 8).
    #>
    param($Ver)
    if ($Ver -is [string]) { $Ver = ConvertTo-P2SVersion $Ver }
    if ($null -eq $Ver) { return [pscustomobject]@{ Branch = ''; Status = 'unknown'; Fixed = $null } }
    $branch = $Ver.Branch
    if ($script:P2S_FixedVersions.ContainsKey($branch)) {
        return [pscustomobject]@{ Branch = $branch; Status = 'supported'; Fixed = $script:P2S_FixedVersions[$branch] }
    }
    if ($Ver.Major -lt 8 -or ($Ver.Major -eq 8 -and $Ver.Minor -le 1)) {
        return [pscustomobject]@{ Branch = $branch; Status = 'eol'; Fixed = $null }
    }
    if (($script:P2S_PrereleaseBranches -contains $branch) -and $Ver.SuffixKind -eq 'prerelease') {
        return [pscustomobject]@{ Branch = $branch; Status = 'prerelease'; Fixed = $null }
    }
    return [pscustomobject]@{ Branch = $branch; Status = 'newer'; Fixed = $null }
}

function Get-P2SRemediation {
    param([string]$Status, [string]$Branch, [string]$Fixed)
    switch ($Status) {
        'supported' { return ('Upgrade to PHP {0} or later, then restart every PHP worker (IIS app pools / php-cgi, Apache).' -f $Fixed) }
        'eol' { return ('No fix from PHP for {0} (end-of-life). Upgrade to a supported branch (8.3+ recommended; 8.2 security support ends 2026-12-31) or obtain a vendor backport, then restart every PHP worker.' -f $Branch) }
        'prerelease' { return 'Pre-release build without the fix. Move to a stable release (8.5.12 or later) or a pre-release that contains the fix.' }
        'newer' { return ('PHP {0} is newer than this tool''s data and has no patch fingerprint: update php2shell-check or check the PHP release notes.' -f $Branch) }
        default { return 'Could not determine the PHP version. Check this build manually against the PHP advisory.' }
    }
}

function Get-P2SVerdict {
    <#
      docs/SPEC.md section 3, rules 1-9 (first match wins).
      -Fingerprint: $true present, $false absent, $null not inspected.
    #>
    param(
        [string]$VersionText,
        $Fingerprint = $null,
        [bool]$ChangelogMentionsCve = $false,
        [bool]$VendorDataFixed = $false,
        [bool]$IsVendorBuild = $false
    )
    $ver = ConvertTo-P2SVersion $VersionText
    $bi = Get-P2SBranchInfo $ver
    $r = [ordered]@{
        Verdict      = 'UNKNOWN'
        Evidence     = 'none'
        Reason       = ''
        Branch       = $bi.Branch
        BranchStatus = $bi.Status
        FixedVersion = $bi.Fixed
        Remediation  = ''
    }
    $vendor = $IsVendorBuild -or ($null -ne $ver -and $ver.SuffixKind -eq 'vendor')

    if ($null -eq $ver) {
        # Rule 1
        $r.Reason = 'version-unreadable'
        $r.Remediation = Get-P2SRemediation -Status 'unknown'
        return [pscustomobject]$r
    }
    if ($true -eq $Fingerprint) {
        # Rule 2
        $r.Verdict = 'FIXED'; $r.Evidence = 'fingerprint'; $r.Reason = 'patch-fingerprint-present'
        return [pscustomobject]$r
    }
    if ($bi.Status -eq 'supported' -and (Compare-P2SVersion $ver $bi.Fixed) -ge 0) {
        # Rule 3
        $r.Verdict = 'FIXED'; $r.Evidence = 'version'; $r.Reason = 'at-or-above-fixed-version'
        if ($false -eq $Fingerprint) { $r.Reason = 'at-or-above-fixed-version,fingerprint-missing' }
        return [pscustomobject]$r
    }
    if ($ChangelogMentionsCve) {
        # Rule 4
        $r.Verdict = 'FIXED'; $r.Evidence = 'changelog'; $r.Reason = 'vendor-changelog-names-cve'
        return [pscustomobject]$r
    }
    if ($VendorDataFixed) {
        # Rule 5
        $r.Verdict = 'FIXED'; $r.Evidence = 'vendor-data'; $r.Reason = 'vendor-fixed-package-version'
        return [pscustomobject]$r
    }
    $reasons = [System.Collections.Generic.List[string]]::new()
    switch ($bi.Status) {
        'eol' { $r.Verdict = 'VULNERABLE'; $reasons.Add('eol-no-upstream-fix') }          # Rule 6
        'prerelease' { $r.Verdict = 'VULNERABLE'; $reasons.Add('prerelease-unpatched') }   # Rule 7
        'newer' { $r.Verdict = 'UNKNOWN'; $reasons.Add('branch-newer-than-data') }         # Rule 8
        default { $r.Verdict = 'VULNERABLE'; $reasons.Add('below-fixed-version') }         # Rule 9
    }
    if ($vendor -and $r.Verdict -eq 'VULNERABLE') { $reasons.Add('vendor-may-backport') }
    $r.Reason = ($reasons -join ',')
    $r.Remediation = Get-P2SRemediation -Status $bi.Status -Branch $bi.Branch -Fixed $bi.Fixed
    if ($vendor -and $r.Verdict -eq 'VULNERABLE') {
        $r.Remediation += ' This is a vendor build: check the vendor advisory for a backported fix.'
    }
    return [pscustomobject]$r
}

# ---------------------------------------------------------------------------
# Reading PHP builds without executing them (docs/SPEC.md section 2)
# ---------------------------------------------------------------------------
function Get-P2SBuildInfoFromBytes {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        return [pscustomobject]@{ Version = $null; Fingerprint = $null }
    }
    # ISO-8859-1 maps every byte to one char, so offsets and ASCII text survive.
    $text = [System.Text.Encoding]::GetEncoding(28591).GetString($Bytes)
    $ver = $null
    $m = [regex]::Match($text, 'X-Powered-By: PHP/([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+~_-]*)')
    if ($m.Success) { $ver = $m.Groups[1].Value }
    $fp = $false
    foreach ($s in $script:P2S_Fingerprints) {
        if ($text.IndexOf($s, [System.StringComparison]::Ordinal) -ge 0) { $fp = $true; break }
    }
    return [pscustomobject]@{ Version = $ver; Fingerprint = $fp }
}

function Read-P2SFileBytes {
    # Shared-read open so files in use by IIS/Apache can still be read.
    param([string]$Path, [long]$MaxBytes = 268435456)
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    try {
        if ($fs.Length -gt $MaxBytes) { throw ('file larger than {0} bytes' -f $MaxBytes) }
        $buf = New-Object byte[] ([int]$fs.Length)
        $read = 0
        while ($read -lt $buf.Length) {
            $n = $fs.Read($buf, $read, $buf.Length - $read)
            if ($n -le 0) { break }
            $read += $n
        }
        return , $buf
    }
    finally { $fs.Dispose() }
}

function Get-P2SBuildInfoFromFile {
    <# VersionSource: 'bytes' (the X-Powered-By string), 'resource' (the file's version resource) or $null. #>
    param([string]$Path)
    $info = [ordered]@{
        Path             = $Path
        Version          = $null
        VersionSource    = $null
        Fingerprint      = $null
        ProductVersion   = $null
        LastWriteTimeUtc = $null
        Error            = $null
    }
    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $info.LastWriteTimeUtc = $fi.LastWriteTimeUtc
        try {
            $pv = $fi.VersionInfo.ProductVersion
            if ($pv) { $info.ProductVersion = [string]$pv }
        }
        catch { $null = $_ }
        $bytes = Read-P2SFileBytes -Path $Path
        $b = Get-P2SBuildInfoFromBytes -Bytes $bytes
        $info.Version = $b.Version
        if ($null -ne $b.Version) { $info.VersionSource = 'bytes' }
        $info.Fingerprint = $b.Fingerprint
    }
    catch {
        $info.Error = $_.Exception.Message
    }
    if ($null -eq $info.Version -and $info.ProductVersion) {
        $m = [regex]::Match($info.ProductVersion, '^\s*([0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9})')
        if ($m.Success) { $info.Version = $m.Groups[1].Value; $info.VersionSource = 'resource' }
    }
    return [pscustomobject]$info
}

function Resolve-P2SDirectory {
    # Resolves junctions/symlinks (scoop 'current', etc.) so one install is counted once.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try { $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\') } catch { return $Path }
    $parts = $full.Split('\')
    if ($parts.Length -lt 2) { return $full }
    $acc = $parts[0]
    for ($i = 1; $i -lt $parts.Length; $i++) {
        $acc = $acc + '\' + $parts[$i]
        try {
            $item = Get-Item -LiteralPath $acc -Force -ErrorAction Stop
            $lt = $null
            if ($null -ne $item.PSObject.Properties['LinkType']) { $lt = $item.LinkType }
            if ($lt -eq 'Junction' -or $lt -eq 'SymbolicLink') {
                $t = $null
                if ($null -ne $item.PSObject.Properties['Target']) { $t = @($item.Target)[0] }
                if ($t) {
                    if (-not [System.IO.Path]::IsPathRooted($t)) { $t = Join-Path (Split-Path -Path $acc -Parent) $t }
                    $acc = [System.IO.Path]::GetFullPath($t).TrimEnd('\')
                }
            }
        }
        catch { $null = $_ }
    }
    return $acc
}

# ---------------------------------------------------------------------------
# Log parsing (pure functions)
# ---------------------------------------------------------------------------
$script:P2S_Months = @{ 'jan' = 1; 'feb' = 2; 'mar' = 3; 'apr' = 4; 'may' = 5; 'jun' = 6; 'jul' = 7; 'aug' = 8; 'sep' = 9; 'oct' = 10; 'nov' = 11; 'dec' = 12 }

function Get-P2SLogDate {
    <# Returns yyyyMMdd as int, or 0 when the line has no recognised timestamp. #>
    param([string]$Line)
    if ([string]::IsNullOrEmpty($Line)) { return 0 }
    # ASCII digits only ([0-9], not \d): a line with other Unicode digits must not break [int].
    # Apache 2.4: [Wed Oct 21 10:00:00.123456 2026]
    $m = [regex]::Match($Line, '\[[A-Za-z]{3} ([A-Za-z]{3}) +([0-9]{1,2}) [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)? ([0-9]{4})\]')
    if ($m.Success) {
        $mon = $m.Groups[1].Value.ToLowerInvariant()
        if ($script:P2S_Months.ContainsKey($mon)) { return ([int]$m.Groups[3].Value * 10000 + $script:P2S_Months[$mon] * 100 + [int]$m.Groups[2].Value) }
    }
    # PHP error_log / FPM: [21-Oct-2026 10:00:00 UTC]
    $m = [regex]::Match($Line, '\[([0-9]{1,2})-([A-Za-z]{3})-([0-9]{4}) [0-9]{2}:[0-9]{2}:[0-9]{2}')
    if ($m.Success) {
        $mon = $m.Groups[2].Value.ToLowerInvariant()
        if ($script:P2S_Months.ContainsKey($mon)) { return ([int]$m.Groups[3].Value * 10000 + $script:P2S_Months[$mon] * 100 + [int]$m.Groups[1].Value) }
    }
    # ISO / nginx: 2026-10-21T10:00:00, 2026/10/21 10:00:00
    $m = [regex]::Match($Line, '(?:^|[\s\["])([0-9]{4})[-/]([0-9]{2})[-/]([0-9]{2})[T ][0-9]{2}:[0-9]{2}')
    if ($m.Success) { return ([int]$m.Groups[1].Value * 10000 + [int]$m.Groups[2].Value * 100 + [int]$m.Groups[3].Value) }
    return 0
}

function Get-P2SLogLineCategory {
    <# Classifies one log line: crash | oom-prescript | oom | prescript | timeout | hard-oom | $null #>
    param([string]$Line)
    if ([string]::IsNullOrEmpty($Line)) { return $null }
    if ($Line -match 'Hard memory limit of \d+ bytes exhausted') { return 'hard-oom' }
    if ($Line -match 'exit signal (Segmentation fault|Aborted|Bus error|Illegal instruction|Floating point exception)' -or
        $Line -match 'AH00052: child pid \d+ exit signal' -or
        $Line -match 'exited on signal (4|6|7|8|11)\b' -or
        $Line -match 'zend_mm_heap corrupted' -or
        $Line -match 'child process \d+ exited with status (3221225477|3221226356|3221225725|3221226505)' -or
        $Line -match 'FastCGI process exited unexpectedly' -or
        $Line -match '(double free or corruption|free\(\): invalid pointer|malloc\(\): corrupted|malloc_consolidate\(\): invalid)') {
        return 'crash'
    }
    if ($Line -match 'Allowed memory size of \d+ bytes exhausted' -or $Line -match 'Out of memory \(allocated') {
        if ($Line -match 'in Unknown on line 0') { return 'oom-prescript' }
        return 'oom'
    }
    if ($Line -match 'Maximum execution time of \d+ seconds? exceeded') { return 'timeout' }
    if ($Line -match '(Warning|Notice|Deprecated|Fatal error|Core Warning|Parse error|Startup)\b.*in Unknown on line 0') { return 'prescript' }
    return $null
}

function ConvertFrom-P2SIniLines {
    <# Parses php.ini lines into a hashtable (lower-case keys, last value wins). #>
    param([string[]]$Lines)
    $h = @{}
    foreach ($raw in @($Lines)) {
        if ($null -eq $raw) { continue }
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith(';') -or $line.StartsWith('[')) { continue }
        $m = [regex]::Match($line, '^([A-Za-z0-9_.\-]+)\s*=\s*(.*)$')
        if (-not $m.Success) { continue }
        $val = $m.Groups[2].Value.Trim()
        if ($val.StartsWith('"')) {
            $q = [regex]::Match($val, '^"([^"]*)"')
            if ($q.Success) { $val = $q.Groups[1].Value }
        }
        else {
            $c = $val.IndexOf(';')
            if ($c -ge 0) { $val = $val.Substring(0, $c).Trim() }
        }
        $h[$m.Groups[1].Value.ToLowerInvariant()] = $val
    }
    return $h
}

function Test-P2SIniTrue {
    param([string]$Value)
    if ($null -eq $Value) { return $false }
    return @('1', 'on', 'yes', 'true') -contains $Value.Trim().ToLowerInvariant()
}

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
function Find-P2SCoreDll {
    param([string]$Dir)
    foreach ($n in $script:P2S_CoreDllNames) {
        $p = Join-Path $Dir $n
        if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    }
    return $null
}

function Test-P2SCoreDllName {
    <# True when the file name is a PHP core DLL (php8ts.dll, php8.dll ...). #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $leaf = ''
    try { $leaf = [string][System.IO.Path]::GetFileName($Path) } catch { return $false }
    return ($script:P2S_CoreDllNames -contains $leaf.ToLowerInvariant())
}

function Resolve-P2SExistingDir {
    <# Expanded, junction-resolved folder path, or $null when it does not exist. #>
    param([string]$Dir)
    if ([string]::IsNullOrWhiteSpace($Dir)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($Dir.Trim().Trim('"'))
    try { if (-not (Test-Path -LiteralPath $expanded -PathType Container)) { return $null } }
    catch { return $null }   # malformed path from a config file
    return (Resolve-P2SDirectory $expanded)
}

function Resolve-P2SFilePath {
    <# Expanded path of an existing file, through junctions and symbolic links (WinGet links), or $null. #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    try { if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $null } }
    catch { return $null }   # malformed path from a config file
    for ($i = 0; $i -lt 8; $i++) {
        # Bounded, so a link loop cannot hang the scan.
        $item = $null
        try { $item = Get-Item -LiteralPath $p -Force -ErrorAction Stop } catch { return $null }
        $lt = $null
        if ($null -ne $item.PSObject.Properties['LinkType']) { $lt = $item.LinkType }
        if ($lt -ne 'SymbolicLink') { break }
        $t = $null
        if ($null -ne $item.PSObject.Properties['Target']) { $t = @($item.Target)[0] }
        if (-not $t) { break }
        if (-not [System.IO.Path]::IsPathRooted($t)) { $t = Join-Path (Split-Path -Path $p -Parent) $t }
        $p = [string]$t
    }
    $dir = Resolve-P2SDirectory (Split-Path -Path $p -Parent)
    if ([string]::IsNullOrEmpty($dir)) { return $p }
    return (Join-Path $dir (Split-Path -Path $p -Leaf))
}

function Add-P2SInstallEntry {
    <#
      The install record for one PHP build file: a core DLL, or a static binary
      that carries the version string itself. Keyed by that file's path.
      -Unidentified: the file is a PHP SAPI whose build could not be found; its
      version resource is not trusted, so the verdict is UNKNOWN (rule 1).
    #>
    param([string]$CoreFile, [string]$Evidence = '', $Build = $null, [switch]$Unidentified)
    $key = $CoreFile.ToLowerInvariant()
    if (-not $script:P2S_InstallDirs.ContainsKey($key)) {
        if ($null -eq $Build) { $Build = Get-P2SBuildInfoFromFile $CoreFile }
        if ($Unidentified) {
            $Build.Version = $null
            $Build.VersionSource = $null
            $Build.Fingerprint = $null
        }
        $script:P2S_InstallDirs[$key] = [ordered]@{
            Dir       = (Split-Path -Path $CoreFile -Parent)
            CoreDll   = $CoreFile
            Build     = $Build
            Sapis     = [ordered]@{}
            Evidence  = [System.Collections.Generic.List[string]]::new()
            Processes = @{}
        }
    }
    $e = $script:P2S_InstallDirs[$key]
    if ($Evidence -and -not $e.Evidence.Contains($Evidence)) { $e.Evidence.Add($Evidence) }
    return $e
}

function Add-P2SInstallSapi {
    <# Records how an installation is used (SAPI file) and which processes run it. #>
    param($Entry, [string]$Sapi, [string]$SapiPath = '', $Process = $null)
    if (-not $Sapi) { return }
    if (-not $Entry.Sapis.Contains($Sapi)) {
        if (-not $SapiPath) { $SapiPath = $Entry.CoreDll }
        $Entry.Sapis[$Sapi] = $SapiPath
    }
    if ($null -ne $Process) {
        if (-not $Entry.Processes.ContainsKey($Sapi)) { $Entry.Processes[$Sapi] = [System.Collections.Generic.List[object]]::new() }
        $already = @($Entry.Processes[$Sapi] | Where-Object { $_.ProcessId -eq $Process.ProcessId })
        if ($already.Count -eq 0) { $Entry.Processes[$Sapi].Add($Process) }
    }
}

function Get-P2SLoadedCoreDll {
    <# Path of the PHP core DLL a running process has loaded; '' if none or its modules cannot be read. #>
    param([int]$ProcessId)
    foreach ($mp in @(Get-P2SProcessModulePaths -ProcessId $ProcessId)) {
        if ($mp -and (Test-P2SCoreDllName ([string]$mp))) { return [string]$mp }
    }
    return ''
}

function Register-P2SPhpFile {
    <#
      Records the PHP build behind a PHP SAPI file (php.exe, php-cgi.exe,
      phpdbg.exe, php8apache2_4.dll ...). The build is, in order: the core DLL
      in the same folder, the core DLL the running process loaded, the core DLL
      the configuration names (Apache LoadFile), or the file itself when it
      carries the version string (a static build). Otherwise the file is still
      recorded, as UNKNOWN with a coverage note (docs/SPEC.md section 3, rule 1):
      a PHP file is never dropped silently. A configured file that does not
      exist is skipped: nothing runs from it. Emits nothing.
    #>
    param([string]$Path, [string]$Sapi = '', [string]$Evidence = '', $Process = $null, [string]$LoadedCore = '', [string]$CoreHint = '', [int]$Depth = 0)
    $file = Resolve-P2SFilePath $Path
    if ($null -eq $file) { return }
    # A scoop shim (php.exe next to php.shim) only launches the real binary: follow it.
    $shim = [System.IO.Path]::ChangeExtension($file, '.shim')
    if ($Depth -lt 3 -and (Test-Path -LiteralPath $shim -PathType Leaf)) {
        $target = $null
        try {
            foreach ($l in @(Get-Content -LiteralPath $shim -ErrorAction Stop)) {
                $m = [regex]::Match([string]$l, '^\s*path\s*=\s*"?([^"]+?)"?\s*$')
                if ($m.Success) { $target = $m.Groups[1].Value; break }
            }
        }
        catch { $target = $null }
        if ($target) {
            Register-P2SPhpFile -Path $target -Sapi $Sapi -Evidence ('{0} (via scoop shim {1})' -f $Evidence, $file) -Process $Process -Depth ($Depth + 1)
            return
        }
    }
    $fileKey = $file.ToLowerInvariant()
    $core = $null
    # Resolved before (for example through the process that runs it): reuse that,
    # so a later configuration entry for the same file does not add an UNKNOWN record.
    if ($script:P2S_SapiBuilds.ContainsKey($fileKey)) { $core = $script:P2S_SapiBuilds[$fileKey] }
    if ($null -eq $core -and (Test-P2SCoreDllName $file)) { $core = $file }
    if ($null -eq $core) { $core = Find-P2SCoreDll (Split-Path -Path $file -Parent) }
    if ($null -eq $core -and -not $LoadedCore -and $null -ne $Process) { $LoadedCore = Get-P2SLoadedCoreDll -ProcessId $Process.ProcessId }
    if ($null -eq $core -and $LoadedCore) { $core = Resolve-P2SFilePath $LoadedCore }
    if ($null -eq $core -and $CoreHint) { $core = Resolve-P2SFilePath $CoreHint }
    if ($null -ne $core) {
        $script:P2S_SapiBuilds[$fileKey] = $core
        $entry = Add-P2SInstallEntry -CoreFile $core -Evidence $Evidence
        Add-P2SInstallSapi -Entry $entry -Sapi $Sapi -SapiPath $file -Process $Process
        return
    }
    # No core DLL found: a static build carries the version string itself.
    $b = Get-P2SBuildInfoFromFile $file
    if ($b.VersionSource -eq 'bytes') {
        $script:P2S_SapiBuilds[$fileKey] = $file
        $entry = Add-P2SInstallEntry -CoreFile $file -Evidence $Evidence -Build $b
        Add-P2SInstallSapi -Entry $entry -Sapi $Sapi -SapiPath $file -Process $Process
        return
    }
    if ($b.Error) {
        Add-P2SCoverage ('Could not read {0}: {1}' -f $file, $b.Error) -Limits
    }
    else {
        $hint = ''
        if ($b.ProductVersion) { $hint = (' Its file version resource says {0}.' -f (Format-P2SShort $b.ProductVersion 40)) }
        Add-P2SCoverage ('{0} has no PHP version string, and its PHP core DLL (php8ts.dll / php8.dll) is neither in the same folder nor seen loaded by a running process: reported as UNKNOWN. Find the core DLL it loads (PATH, System32, Apache LoadFile) and check that build.{1}' -f $file, $hint)
    }
    $entry = Add-P2SInstallEntry -CoreFile $file -Evidence $Evidence -Build $b -Unidentified
    Add-P2SInstallSapi -Entry $entry -Sapi $Sapi -SapiPath $file -Process $Process
}

function Register-P2SInstallDir {
    <#
      Records a folder that may hold PHP (well-known location, PATH, deep scan):
      its core DLL, or else the php.exe / php-cgi.exe in it. A folder without
      either is not a PHP folder. Emits nothing.
    #>
    param([string]$Dir, [string]$Evidence = '')
    $real = Resolve-P2SExistingDir $Dir
    if ($null -eq $real) { return }
    $core = Find-P2SCoreDll $real
    if ($null -ne $core) {
        $null = Add-P2SInstallEntry -CoreFile $core -Evidence $Evidence
        return
    }
    # Chocolatey's shim folder holds launchers, not PHP builds (the build is in the tools folder).
    if ($real -match '(?i)\\chocolatey\\bin$') { return }
    foreach ($exe in @('php.exe', 'php-cgi.exe')) {
        $p = Join-Path $real $exe
        if (Test-Path -LiteralPath $p -PathType Leaf) {
            $s = 'cli'
            if ($exe -eq 'php-cgi.exe') { $s = 'cgi' }
            Register-P2SPhpFile -Path $p -Sapi $s -Evidence $Evidence
            return
        }
    }
}

function Get-P2SProcessList {
    $raw = $null
    try { $raw = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop) }
    catch {
        try { $raw = @(Get-WmiObject -Class Win32_Process -ErrorAction Stop) }
        catch {
            Add-P2SCoverage ('Could not enumerate processes: ' + $_.Exception.Message) -Limits
            return
        }
    }
    foreach ($p in $raw) {
        $created = $null
        try {
            $created = $p.CreationDate
            if ($created -is [string]) { $created = [System.Management.ManagementDateTimeConverter]::ToDateTime($created) }
        }
        catch { $created = $null }
        [pscustomobject]@{
            ProcessId       = [int]$p.ProcessId
            ParentProcessId = [int]$p.ParentProcessId
            Name            = [string]$p.Name
            Path            = [string]$p.ExecutablePath
            CommandLine     = [string]$p.CommandLine
            Created         = $created
        }
    }
}

function Get-P2SProcessModulePaths {
    <# Returns module file paths, or $null if the process cannot be inspected. #>
    param([int]$ProcessId)
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
        $paths = @($proc.Modules | ForEach-Object { [string]$_.FileName })
        if ($paths.Count -eq 0) { return $null }
        return $paths
    }
    catch { return $null }
}

function Invoke-P2SProcessDiscovery {
    $procs = @(Get-P2SProcessList)
    $script:P2S_Processes = $procs
    $byId = @{}
    foreach ($p in $procs) { $byId[$p.ProcessId] = $p }
    $noPath = 0
    $noModules = 0
    foreach ($p in $procs) {
        $name = $p.Name.ToLowerInvariant()
        $sapi = ''
        if ($name -eq 'php.exe' -or $name -eq 'php-win.exe') { $sapi = 'cli' }
        elseif ($name -eq 'php-cgi.exe') { $sapi = 'cgi' }
        elseif ($name -eq 'phpdbg.exe') { $sapi = 'phpdbg' }
        if ($sapi -ne '') {
            if (-not $p.Path) { $noPath++; continue }
            $ev = 'running process'
            if ($sapi -eq 'cgi' -and $byId.ContainsKey($p.ParentProcessId) -and $byId[$p.ParentProcessId].Name -ieq 'w3wp.exe') {
                $ev = 'running under IIS FastCGI (w3wp.exe)'
            }
            Register-P2SPhpFile -Path $p.Path -Sapi $sapi -Evidence $ev -Process $p
        }
        elseif ($name -eq 'httpd.exe') {
            $mods = Get-P2SProcessModulePaths -ProcessId $p.ProcessId
            if ($null -eq $mods) { $noModules++; $script:P2S_HttpdUnreadable.Add($p); continue }
            # The PHP core DLL httpd.exe loaded, wherever it lives (php8apache2_4.dll
            # copied into Apache24\modules with php8ts.dll found through PATH).
            $loadedCore = ''
            foreach ($mp in @($mods)) {
                if ($mp -and (Test-P2SCoreDllName ([string]$mp))) { $loadedCore = [string]$mp; break }
            }
            $sawModule = $false
            foreach ($mp in @($mods)) {
                if ([string]$mp -match '(?i)\\php\d*apache[^\\]*\.dll$') {
                    Register-P2SPhpFile -Path ([string]$mp) -Sapi 'mod_php' -Evidence 'loaded in a running httpd.exe' -Process $p -LoadedCore $loadedCore
                    $sawModule = $true
                }
            }
            if (-not $sawModule -and $loadedCore) {
                # PHP loaded under another module file name: the core DLL itself shows mod_php.
                Register-P2SPhpFile -Path $loadedCore -Sapi 'mod_php' -Evidence 'PHP core DLL loaded in a running httpd.exe' -Process $p
            }
        }
    }
    if ($noPath -gt 0) { Add-P2SCoverage ('{0} PHP process(es) did not expose their executable path (run as Administrator).' -f $noPath) -Limits }
    if ($noModules -gt 0) { Add-P2SCoverage ('Loaded modules of {0} httpd.exe process(es) could not be read; mod_php use was inferred from Apache configuration instead.' -f $noModules) }
}

function Get-P2SApacheRoots {
    $roots = [System.Collections.Generic.List[string]]::new()
    $patterns = @('C:\xampp\apache', 'C:\wamp64\bin\apache\*', 'C:\wamp\bin\apache\*', 'C:\laragon\bin\apache\*', 'C:\Apache*')
    foreach ($base in @(Get-P2SProgramFilesDirs)) {
        $patterns += (Join-Path $base 'Apache*')
        $patterns += (Join-Path $base 'Apache Software Foundation\*')
    }
    foreach ($pat in $patterns) {
        foreach ($d in @(Get-Item -Path $pat -ErrorAction SilentlyContinue)) {
            if ($d.PSIsContainer -and (Test-Path -LiteralPath (Join-Path $d.FullName 'conf'))) {
                if (-not $roots.Contains($d.FullName)) { $roots.Add($d.FullName) }
            }
        }
    }
    foreach ($p in @($script:P2S_Processes | Where-Object { $_.Name -ieq 'httpd.exe' -and $_.Path })) {
        $r = Split-Path -Path (Split-Path -Path $p.Path -Parent) -Parent
        if ($r -and (Test-Path -LiteralPath (Join-Path $r 'conf')) -and -not $roots.Contains($r)) { $roots.Add($r) }
    }
    return $roots
}

function Resolve-P2SApachePath {
    param([string]$PathText, [string]$ServerRoot)
    if ([string]::IsNullOrWhiteSpace($PathText) -or $PathText.Contains('${')) { return $null }
    $p = $PathText.Trim().Trim('"').Replace('/', '\')
    if (-not [System.IO.Path]::IsPathRooted($p)) { $p = Join-Path $ServerRoot $p }
    return $p
}

function Read-P2SApacheRoot {
    <# Parses an Apache install's config files in include order, sharing Define values. #>
    param([string]$Root)
    $files = [System.Collections.Generic.List[string]]::new()
    $globs = @((Join-Path $Root '*.conf'), (Join-Path $Root 'conf\httpd.conf'), (Join-Path $Root 'conf\extra\*.conf'), (Join-Path $Root 'conf\*.conf'))
    if ($Root -match '(?i)^C:\\laragon\\') { $globs += @('C:\laragon\etc\apache2\*.conf', 'C:\laragon\etc\apache2\sites-enabled\*.conf') }
    $wm = [regex]::Match($Root, '^(C:\\wamp(64)?)\\', 'IgnoreCase')
    if ($wm.Success) { $globs += (Join-Path $wm.Groups[1].Value 'alias\*.conf') }
    foreach ($g in $globs) {
        foreach ($f in @(Get-Item -Path $g -ErrorAction SilentlyContinue)) {
            if (-not $f.PSIsContainer -and -not $files.Contains($f.FullName)) { $files.Add($f.FullName) }
        }
    }
    $defines = @{}
    $serverRoot = $Root
    # LoadModule lines are registered after the whole configuration is read, so a
    # LoadFile of the PHP core DLL (anywhere in it) tells where that build lives.
    $entry = [ordered]@{
        Root            = $Root
        LoadModules     = [System.Collections.Generic.List[string]]::new()
        LoadModuleFiles = [System.Collections.Generic.List[string]]::new()
        CoreHint        = ''
    }
    foreach ($file in $files) {
        $lines = $null
        try { $lines = @(Get-Content -LiteralPath $file -ErrorAction Stop) }
        catch { Add-P2SCoverage ('Could not read Apache config ' + $file); continue }
        for ($ln = 0; $ln -lt $lines.Count; $ln++) {
            $line = ([string]$lines[$ln]).Trim()
            if ($line -eq '' -or $line.StartsWith('#')) { continue }
            foreach ($k in @($defines.Keys)) { $line = $line.Replace('${' + $k + '}', $defines[$k]) }
            $m = [regex]::Match($line, '^Define\s+(\S+)\s+"?([^"]*)"?\s*$', 'IgnoreCase')
            if ($m.Success) { $defines[$m.Groups[1].Value] = $m.Groups[2].Value; continue }
            $m = [regex]::Match($line, '^ServerRoot\s+"?([^"]+?)"?\s*$', 'IgnoreCase')
            if ($m.Success) { $sr = Resolve-P2SApachePath $m.Groups[1].Value $Root; if ($sr) { $serverRoot = $sr }; continue }
            $m = [regex]::Match($line, '^LoadModule\s+php\d*_module\s+"?([^"]+?)"?\s*$', 'IgnoreCase')
            if ($m.Success) {
                $dll = Resolve-P2SApachePath $m.Groups[1].Value $serverRoot
                if ($dll) {
                    $entry.LoadModules.Add($dll)
                    $entry.LoadModuleFiles.Add($file)
                }
                continue
            }
            $m = [regex]::Match($line, '^LoadFile\s+"?([^"]+?php\d+(ts)?\.dll)"?\s*$', 'IgnoreCase')
            if ($m.Success) {
                $dll = Resolve-P2SApachePath $m.Groups[1].Value $serverRoot
                $coreFile = $null
                if ($dll) { $coreFile = Resolve-P2SFilePath $dll }
                if ($coreFile -and (Test-P2SCoreDllName $coreFile)) {
                    if (-not $entry.CoreHint) { $entry.CoreHint = $coreFile }
                    $null = Add-P2SInstallEntry -CoreFile $coreFile -Evidence ('Apache LoadFile in ' + $file)
                }
                continue
            }
            $m = [regex]::Match($line, '^FcgidWrapper\s+"?([^"\s]+php-cgi\.exe)"?', 'IgnoreCase')
            if ($m.Success) {
                $exe = Resolve-P2SApachePath $m.Groups[1].Value $serverRoot
                if ($exe) { Register-P2SPhpFile -Path $exe -Sapi 'cgi' -Evidence ('Apache mod_fcgid wrapper in ' + $file) }
                continue
            }
            $m = [regex]::Match($line, '^DocumentRoot\s+"?([^"]+?)"?\s*$', 'IgnoreCase')
            if ($m.Success) {
                $dr = Resolve-P2SApachePath $m.Groups[1].Value $serverRoot
                if ($dr -and -not $script:P2S_WebRoots.Contains($dr)) { $script:P2S_WebRoots.Add($dr) }
                continue
            }
            $m = [regex]::Match($line, '^ErrorLog\s+"?([^"|]+?)"?\s*$', 'IgnoreCase')
            if ($m.Success) {
                $el = Resolve-P2SApachePath $m.Groups[1].Value $serverRoot
                if ($el -and -not $script:P2S_ErrorLogs.Contains($el)) { $script:P2S_ErrorLogs.Add($el) }
                continue
            }
            $m = [regex]::Match($line, '^(php_value|php_flag|php_admin_value|php_admin_flag)\s+(\S+)', 'IgnoreCase')
            if ($m.Success) {
                # Directive name and file:line only: values can be secrets.
                $script:P2S_IniOverrides.Add([pscustomobject]@{ File = $file; Line = $ln + 1; Kind = $m.Groups[1].Value.ToLowerInvariant(); Directive = $m.Groups[2].Value.ToLowerInvariant() })
            }
        }
    }
    for ($i = 0; $i -lt $entry.LoadModules.Count; $i++) {
        Register-P2SPhpFile -Path $entry.LoadModules[$i] -Sapi 'mod_php' -Evidence ('Apache LoadModule in ' + $entry.LoadModuleFiles[$i]) -CoreHint $entry.CoreHint
    }
    $script:P2S_ApacheConfs.Add($entry)
}

function Read-P2SIisConfig {
    # Through Sysnative in a 32-bit process: System32 would be redirected to SysWOW64.
    $cfg = Join-Path (Get-P2SSystem32) 'inetsrv\config\applicationHost.config'
    if (-not (Test-Path -LiteralPath $cfg)) { return }
    $x = $null
    try { [xml]$x = Get-Content -LiteralPath $cfg -Raw -ErrorAction Stop }
    catch {
        Add-P2SCoverage ('IIS is installed but applicationHost.config could not be read (' + $_.Exception.Message + '); run as Administrator.') -Limits
        return
    }
    foreach ($n in @($x.SelectNodes('//fastCgi/application'))) {
        $fp = [Environment]::ExpandEnvironmentVariables($n.GetAttribute('fullPath'))
        if ($fp -match '(?i)php-cgi\.exe$') {
            Register-P2SPhpFile -Path $fp -Sapi 'cgi' -Evidence 'IIS FastCGI application'
        }
    }
    foreach ($n in @($x.SelectNodes('//handlers/add'))) {
        $sp = $n.GetAttribute('scriptProcessor')
        if ($sp -match '(?i)php-cgi\.exe') {
            $exe = [Environment]::ExpandEnvironmentVariables($sp.Split('|')[0])
            Register-P2SPhpFile -Path $exe -Sapi 'cgi' -Evidence 'IIS handler mapping'
        }
    }
    foreach ($n in @($x.SelectNodes('//sites/site//virtualDirectory'))) {
        $pp = [Environment]::ExpandEnvironmentVariables($n.GetAttribute('physicalPath'))
        if ($pp -and -not $script:P2S_WebRoots.Contains($pp)) { $script:P2S_WebRoots.Add($pp) }
    }
}

function Get-P2SCandidateDirs {
    $dirs = [System.Collections.Generic.List[string]]::new()
    $patterns = @('C:\php*', 'C:\xampp\php', 'C:\wamp64\bin\php\*', 'C:\wamp\bin\php\*', 'C:\laragon\bin\php\*', 'C:\tools\php*')
    foreach ($base in @(Get-P2SProgramFilesDirs)) {
        $patterns += (Join-Path $base 'PHP*')
        $patterns += (Join-Path $base 'PHP\*')
    }
    $chocoTools = [Environment]::GetEnvironmentVariable('ChocolateyToolsLocation')
    if ($chocoTools) { $patterns += (Join-Path $chocoTools 'php*') }
    if ($env:ProgramData) {
        $patterns += (Join-Path $env:ProgramData 'chocolatey\lib\php*')
        $patterns += (Join-Path $env:ProgramData 'chocolatey\lib\php*\tools')
        $patterns += (Join-Path $env:ProgramData 'scoop\apps\php*\*')
    }
    if ($env:USERPROFILE) { $patterns += (Join-Path $env:USERPROFILE 'scoop\apps\php*\*') }
    foreach ($pat in $patterns) {
        foreach ($d in @(Get-Item -Path $pat -ErrorAction SilentlyContinue)) {
            if ($d.PSIsContainer -and -not $dirs.Contains($d.FullName)) { $dirs.Add($d.FullName) }
        }
    }
    foreach ($raw in @(([string]$env:Path).Split(';'))) {
        $p = $raw.Trim().Trim('"')
        if (-not $p) { continue }
        try {
            if ((Test-Path -LiteralPath (Join-Path $p 'php.exe')) -and -not $dirs.Contains($p)) { $dirs.Add($p) }
        }
        catch { $null = $_ }   # PATH entries with invalid characters
    }
    return $dirs
}

function Invoke-P2SDeepDiscovery {
    foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
        if ($drive.DriveType -ne 'Fixed' -or -not $drive.IsReady) { continue }
        $errs = $null
        $found = @(Get-ChildItem -Path $drive.RootDirectory.FullName -Recurse -File -Force -Filter 'php*.dll' -ErrorAction SilentlyContinue -ErrorVariable errs)
        foreach ($f in $found) {
            if ($script:P2S_CoreDllNames -contains $f.Name.ToLowerInvariant()) {
                Register-P2SInstallDir -Dir $f.DirectoryName -Evidence 'deep scan'
            }
        }
        if (@($errs).Count -gt 0) { Add-P2SCoverage ('Deep scan of {0} skipped {1} unreadable folder(s).' -f $drive.Name, @($errs).Count) }
    }
}

function Invoke-P2SDiscovery {
    if (Test-P2SWow64) {
        Add-P2SCoverage 'This is 32-bit PowerShell on 64-bit Windows: System32 and Program Files were read through their 64-bit paths (Sysnative, ProgramW6432), but the loaded modules of 64-bit processes cannot be read from a 32-bit process, so configuration was used instead. Run 64-bit PowerShell to check them.'
    }
    Invoke-P2SProcessDiscovery
    foreach ($root in @(Get-P2SApacheRoots)) { Read-P2SApacheRoot -Root $root }
    # httpd.exe processes whose modules were unreadable: attribute them via their own config.
    foreach ($p in $script:P2S_HttpdUnreadable) {
        if (-not $p.Path) { continue }
        $r = Split-Path -Path (Split-Path -Path $p.Path -Parent) -Parent
        foreach ($c in @($script:P2S_ApacheConfs | Where-Object { $_.Root -ieq $r })) {
            foreach ($dll in $c.LoadModules) {
                Register-P2SPhpFile -Path $dll -Sapi 'mod_php' -Evidence 'Apache LoadModule (running httpd.exe)' -Process $p -CoreHint $c.CoreHint
            }
        }
    }
    Read-P2SIisConfig
    foreach ($d in @(Get-P2SCandidateDirs)) { Register-P2SInstallDir -Dir $d -Evidence 'well-known location' }
    if ($script:P2S_Opt.Deep) { Invoke-P2SDeepDiscovery }
    else { Add-P2SCoverage 'Only well-known locations, PATH, IIS/Apache configuration and running processes were checked; use -Deep to search every fixed drive.' }
}

# ---------------------------------------------------------------------------
# Installation records, exposure and configuration context
# ---------------------------------------------------------------------------
function Get-P2SOrigin {
    param([string]$Dir)
    $d = ([string]$Dir).ToLowerInvariant()
    if ($d -like '*\xampp\*') { return 'xampp' }
    if ($d -like '*\wamp*\*') { return 'wampserver' }
    if ($d -like '*\laragon\*') { return 'laragon' }
    if ($d -like '*\scoop\*') { return 'scoop' }
    if ($d -like '*\chocolatey\*' -or $d -like 'c:\tools\php*') { return 'chocolatey' }
    if ($d -like '*\program files*\php*') { return 'installer' }
    return ''
}

function Get-P2SInstallationRecords {
    foreach ($key in @($script:P2S_InstallDirs.Keys | Sort-Object)) {
        $e = $script:P2S_InstallDirs[$key]
        $b = $e.Build
        if ($b.Error -and $null -eq $b.Version) { Add-P2SCoverage ('Could not read {0}: {1}' -f $e.CoreDll, $b.Error) -Limits }
        $v = Get-P2SVerdict -VersionText $b.Version -Fingerprint $b.Fingerprint
        $sapis = @($e.Sapis.Keys)
        if ($sapis.Count -eq 0) {
            $cliPath = Join-Path $e.Dir 'php.exe'
            if (-not (Test-Path -LiteralPath $cliPath)) { $cliPath = $e.CoreDll }
            $e.Sapis['cli'] = $cliPath
            $sapis = @('cli')
        }
        foreach ($s in $sapis) {
            $procs = @()
            if ($e.Processes.ContainsKey($s)) { $procs = @($e.Processes[$s]) }
            $restart = $false
            if ($null -ne $b.LastWriteTimeUtc) {
                foreach ($p in $procs) {
                    if ($null -ne $p.Created -and $p.Created.ToUniversalTime() -lt $b.LastWriteTimeUtc) { $restart = $true }
                }
            }
            $remediation = $v.Remediation
            if ($restart) {
                $remediation = ('{0} Running process(es) started before {1} was last changed: restart them so the patched code is loaded.' -f $remediation, (Split-Path -Path $e.CoreDll -Leaf)).Trim()
            }
            # The build the processes run (docs/SPEC.md section 6). A process that
            # started before the file changed runs the replaced image, which can no
            # longer be read: empty version, verdict UNKNOWN (and restart_required).
            $runVersion = ''
            $runVerdict = ''
            if ($procs.Count -gt 0) {
                if ($restart) { $runVerdict = 'UNKNOWN' }
                else { $runVersion = [string]$b.Version; $runVerdict = [string]$v.Verdict }
            }
            $fp = $null
            if ($true -eq $b.Fingerprint) { $fp = $true } elseif ($false -eq $b.Fingerprint) { $fp = $false }
            $exposure = 'low'
            if ($script:P2S_Exposure.ContainsKey($s)) { $exposure = $script:P2S_Exposure[$s] }
            [ordered]@{
                scope             = 'host'
                path              = [string]$e.Sapis[$s]
                sapi              = $s
                version           = [string]$b.Version
                branch            = [string]$v.Branch
                branch_status     = [string]$v.BranchStatus
                fixed_version     = [string]$v.FixedVersion
                patch_fingerprint = $fp
                package           = [ordered]@{ manager = 'none'; name = ''; version = ''; origin = (Get-P2SOrigin $e.Dir) }
                evidence          = [string]$v.Evidence
                verdict           = [string]$v.Verdict
                reason            = [string]$v.Reason
                remediation       = [string]$remediation
                running           = [ordered]@{ processes = $procs.Count; restart_required = $restart; version = $runVersion; verdict = $runVerdict }
                exposure          = $exposure
                install_dir       = [string]$e.Dir
                found_by          = ($e.Evidence -join '; ')
            }
        }
    }
}

function Add-P2SConfigFindings {
    <# Context only: never changes a verdict (docs/SPEC.md section 4). #>
    param($Entry)
    $v = Get-P2SVerdict -VersionText $Entry.Build.Version -Fingerprint $Entry.Build.Fingerprint
    $ini = Join-Path $Entry.Dir 'php.ini'
    $loc = $Entry.Dir
    $vals = @{}
    if (Test-Path -LiteralPath $ini -PathType Leaf) {
        try { $vals = ConvertFrom-P2SIniLines -Lines @(Get-Content -LiteralPath $ini -ErrorAction Stop); $loc = $ini }
        catch { Add-P2SCoverage ('Could not read ' + $ini) }
    }
    if ($vals.ContainsKey('error_log')) {
        $el = [Environment]::ExpandEnvironmentVariables([string]$vals['error_log'])
        if ($el -and $el -ne 'syslog' -and [System.IO.Path]::IsPathRooted($el) -and -not $script:P2S_ErrorLogs.Contains($el)) { $script:P2S_ErrorLogs.Add($el) }
    }
    if ($v.Verdict -eq 'UNKNOWN') { return }
    $vulnerable = ($v.Verdict -eq 'VULNERABLE')
    $upeOn = $true
    if ($vals.ContainsKey('session.upload_progress.enabled')) { $upeOn = Test-P2SIniTrue $vals['session.upload_progress.enabled'] }
    if ($upeOn -and $vulnerable) {
        Add-P2SFinding -Severity INFO -Category config -Title 'session.upload_progress.enabled is On' -Location $loc -Detail 'Default On. CVE-2026-109619 session path. Interim (partial): set session.upload_progress.enabled=0 in php.ini and restart every worker.'
    }
    elseif ($upeOn) {
        Add-P2SFinding -Severity INFO -Category config -Title 'session.upload_progress.enabled is On' -Location $loc -Detail 'Patched build. The PHP advisory suggests disabling the feature anyway if it is not used.'
    }
    if (-not $vulnerable) { return }
    if ($v.Branch -eq '8.5') {
        $febOn = $true
        if ($vals.ContainsKey('fatal_error_backtraces')) { $febOn = Test-P2SIniTrue $vals['fatal_error_backtraces'] }
        if ($febOn) {
            Add-P2SFinding -Severity INFO -Category config -Title 'fatal_error_backtraces is On (PHP 8.5 default)' -Location $loc -Detail 'Confirmed CVE-2026-109619 RCE producer. Interim (partial): fatal_error_backtraces=0 in php.ini and restart every worker.'
        }
    }
    $ml = '128M (default)'
    if ($vals.ContainsKey('memory_limit')) { $ml = [string]$vals['memory_limit'] }
    if ($ml.Trim() -eq '-1') {
        Add-P2SFinding -Severity INFO -Category config -Title 'memory_limit is -1' -Location $loc -Detail 'Removes the controllable OOM used against CVE-2026-109618, but an allocation failure can still reach the vulnerable path. Not a complete mitigation.'
    }
    else {
        Add-P2SFinding -Severity INFO -Category config -Title ('memory_limit is ' + $ml) -Location $loc -Detail 'A finite limit makes the CVE-2026-109618 OOM controllable. Interim (partial): memory_limit=-1 set administratively; restart every worker.'
    }
}

function Read-P2SHtaccessOverrides {
    <# .htaccess php_value/php_flag lines (applied per request by mod_php). #>
    foreach ($root in @($script:P2S_WebRoots)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -Filter '.htaccess' -ErrorAction SilentlyContinue)) {
            $lines = @()
            try { $lines = @(Get-Content -LiteralPath $f.FullName -ErrorAction Stop) } catch { continue }
            for ($ln = 0; $ln -lt $lines.Count; $ln++) {
                $m = [regex]::Match(([string]$lines[$ln]).Trim(), '^(php_value|php_flag|php_admin_value|php_admin_flag)\s+(\S+)', 'IgnoreCase')
                if ($m.Success) {
                    # Directive name and file:line only: values can be secrets.
                    $script:P2S_IniOverrides.Add([pscustomobject]@{ File = $f.FullName; Line = $ln + 1; Kind = $m.Groups[1].Value.ToLowerInvariant(); Directive = $m.Groups[2].Value.ToLowerInvariant() })
                }
            }
        }
    }
}

function Test-P2SDiagnosticDirective {
    param([string]$Directive)
    $d = ([string]$Directive).ToLowerInvariant()
    return (($script:P2S_DiagnosticDirectives -contains $d) -or $d.StartsWith('assert.'))
}

function Format-P2SOverride {
    <# 'file:line kind directive' (docs/SPEC.md section 5: never the value). #>
    param($Override)
    return ('{0}:{1} {2} {3}' -f $Override.File, $Override.Line, $Override.Kind, (Format-P2SShort $Override.Directive 80))
}

function Add-P2SOverrideFindings {
    $others = [System.Collections.Generic.List[object]]::new()
    foreach ($o in $script:P2S_IniOverrides) {
        if (Test-P2SDiagnosticDirective $o.Directive) {
            Add-P2SFinding -Severity REVIEW -Category config -Title ("Per-request INI override '{0}' can emit a diagnostic before request initialization" -f (Format-P2SShort $o.Directive 80)) -Location ('{0}:{1}' -f $o.File, $o.Line) -Detail ('{0} (value not shown). CVE-2026-109619 consumer path with mod_php: remove it or fix the value (hiding diagnostics does not help).' -f (Format-P2SOverride $o))
        }
        else { $others.Add($o) }
    }
    if ($others.Count -gt 0) {
        $shown = @($others | Select-Object -First 3 | ForEach-Object { Format-P2SOverride $_ }) -join '; '
        if ($others.Count -gt 3) { $shown += ('; ... ({0} more)' -f ($others.Count - 3)) }
        Add-P2SFinding -Severity INFO -Category config -Title ('{0} other per-request INI override(s) in Apache config or .htaccess' -f $others.Count) -Location $shown -Count $others.Count -Detail 'Values are not shown. Invalid values (memory_limit, date.timezone, sizes, paths rejected by open_basedir) also emit early diagnostics under mod_php; review them.'
    }
}

# ---------------------------------------------------------------------------
# Compromise triage (docs/SPEC.md section 5). Paths, counts and short log
# lines only; file contents are never printed.
# ---------------------------------------------------------------------------
$script:P2S_LogPrefilter = [regex]::new('Hard memory limit|exit signal|AH00052|exited on signal|zend_mm_heap|exited with status|FastCGI process exited|double free|free\(\)|malloc|Allowed memory size|Out of memory|Maximum execution time|in Unknown on line 0', 'Compiled')

$script:P2S_WebshellPatterns = [ordered]@{
    'eval-of-decoded-data'   = 'eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|rawurldecode|hex2bin)\s*\('
    'exec-of-request-input'  = '\b(eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*@?\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b'
    'request-input-called'   = '\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\('
    'preg-replace-e'         = 'preg_replace\s*\(\s*[''"]/[^''"]*/[a-zA-Z]*e[a-zA-Z]*[''"]'
    'decode-of-request-input' = 'base64_decode\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\b'
    'known-webshell-marker'  = 'FilesMan|b374k|WSO_VERSION|c99sh_|r57shell|IndoXploit|AnonymousFox|ALFA_DATA|alfacgiapi'
}

# PHP code in an image or icon: an opening tag followed by code (same rule as
# the shell script). ASCII whitespace only, as PHP's tokenizer requires.
$script:P2S_ImageCodePattern = '<\?(php[ \t\r\n]+|=[ \t\r\n]*)@?(eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec|include|include_once|require|require_once|file_put_contents|base64_decode|gzinflate|str_rot13|create_function|call_user_func)[ \t\r\n]*\(|<\?=[ \t\r\n]*@?\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'

function Get-P2SFileText {
    <# Latin-1 text of a file (bounded), or $null. #>
    param([string]$Path, [long]$MaxBytes = 5242880)
    try {
        $bytes = Read-P2SFileBytes -Path $Path -MaxBytes $MaxBytes
        return [System.Text.Encoding]::GetEncoding(28591).GetString($bytes)
    }
    catch { return $null }
}

function Get-P2SWebshellMatch {
    <# Returns the name of the first matching webshell pattern, or $null. #>
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    foreach ($name in @($script:P2S_WebshellPatterns.Keys)) {
        if ([regex]::IsMatch($Text, $script:P2S_WebshellPatterns[$name], 'IgnoreCase')) { return $name }
    }
    return $null
}

function Get-P2SEventText {
    <#
      An event's message plus its property values. Message is empty when the
      provider's message resources are missing (some regional Windows
      installations); the properties still name the faulting program and module.
    #>
    param($Record)
    $msg = ''
    try { $msg = [string]$Record.Message } catch { $msg = '' }
    $props = ''
    try { $props = (@($Record.Properties) | ForEach-Object { [string]$_.Value }) -join ' ' } catch { $props = '' }
    return ($msg + ' ' + $props).Trim()
}

function Test-P2SPhpEventText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    return (($Text -match '(?i)\b(php|php-cgi|php-win|phpdbg|httpd)\.exe\b') -or (($Text -match '(?i)\bw3wp\.exe\b') -and ($Text -match '(?i)php')))
}

function Get-P2SAppCrashEvents {
    param([datetime]$Start, $End = $null)
    $filter = @{ LogName = 'Application'; Id = @(1000, 1001); StartTime = $Start }
    if ($null -ne $End) { $filter['EndTime'] = $End }
    $events = @()
    try { $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop) }
    catch {
        if ([string]$_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return [pscustomobject]@{ Ok = $true; Crashes = @(); Reports = @() } }
        Add-P2SCoverage ('Could not query the Application event log: ' + $_.Exception.Message) -Limits
        return [pscustomobject]@{ Ok = $false; Crashes = @(); Reports = @() }
    }
    $crashes = [System.Collections.Generic.List[object]]::new()
    $reports = [System.Collections.Generic.List[object]]::new()
    foreach ($evt in $events) {
        $text = Get-P2SEventText -Record $evt
        if (-not (Test-P2SPhpEventText $text)) { continue }
        $item = [pscustomobject]@{ Id = [int]$evt.Id; Text = $text }
        if ($item.Id -eq 1000) { $crashes.Add($item) } else { $reports.Add($item) }
    }
    return [pscustomobject]@{ Ok = $true; Crashes = $crashes.ToArray(); Reports = $reports.ToArray() }
}

function Get-P2SOldestAppEventTime {
    <# Time of the oldest record in the Application log (a ring buffer), or $null. #>
    try {
        $oldest = @(Get-WinEvent -LogName Application -MaxEvents 1 -Oldest -ErrorAction Stop)
        if ($oldest.Count -gt 0) { return $oldest[0].TimeCreated }
    }
    catch { $null = $_ }
    return $null
}

function Invoke-P2SEventLogTriage {
    $since = $script:P2S_Opt.SinceDate
    $sinceText = Format-P2SDate $since
    $win = Get-P2SAppCrashEvents -Start $since
    if (-not $win.Ok) { return }
    $nWin = @($win.Crashes).Count
    $nRep = @($win.Reports).Count
    if ($nWin -gt 0) {
        $before = Get-P2SAppCrashEvents -Start $since.AddDays(-30) -End $since
        $nBefore = @($before.Crashes).Count
        # HIGH only when the log covers time before the window and shows no crash there.
        $covers = $false
        if ($before.Ok) {
            if ($nBefore -gt 0) { $covers = $true }
            else {
                $oldest = Get-P2SOldestAppEventTime
                if ($null -ne $oldest -and $oldest -lt $since) { $covers = $true }
            }
        }
        $sev = 'REVIEW'
        if ($nBefore -eq 0 -and $covers) { $sev = 'HIGH' }
        $context = ('{0} in the 30 days before' -f $nBefore)
        if (-not $covers) { $context = ('the Application log has nothing from before {0} to compare with' -f $sinceText) }
        $sample = Format-P2SShort ([string]@($win.Crashes)[0].Text) 200
        Add-P2SFinding -Severity $sev -Category crash -Title ('{0} PHP/web-server application crash event(s) since {1}' -f $nWin, $sinceText) -Location 'Windows Event Log: Application (ID 1000)' -Count $nWin -Detail ('{0}; {1} related WER report(s). Sample: {2}' -f $context, $nRep, $sample)
    }
    elseif ($nRep -gt 0) {
        Add-P2SFinding -Severity REVIEW -Category crash -Title ('{0} Windows Error Reporting event(s) for PHP/web-server processes since {1}' -f $nRep, $sinceText) -Location 'Windows Event Log: Application (ID 1001)' -Count $nRep -Detail 'Review the reports for faulting module php*.dll.'
    }
}

function Get-P2SLogCandidates {
    $list = [System.Collections.Generic.List[string]]::new()
    $globs = @('C:\xampp\apache\logs\error.log', 'C:\xampp\php\logs\*', 'C:\wamp64\logs\*.log', 'C:\wamp\logs\*.log', 'C:\laragon\tmp\*.log', 'C:\laragon\bin\apache\*\logs\error.log', 'C:\Apache*\logs\error.log', 'C:\php*\logs\*.log')
    foreach ($g in $globs) {
        foreach ($f in @(Get-Item -Path $g -ErrorAction SilentlyContinue)) {
            if (-not $f.PSIsContainer -and -not $list.Contains($f.FullName)) { $list.Add($f.FullName) }
        }
    }
    foreach ($p in $script:P2S_ErrorLogs) {
        if ((Test-Path -LiteralPath $p -PathType Leaf) -and -not $list.Contains($p)) { $list.Add($p) }
    }
    return $list
}

function Get-P2SLogFamilyKey {
    <#
      A log and its rotated files form one family (docs/SPEC.md section 5):
      error.log, error.log.1, error.log.2.gz, error_log-20261020 and
      error.2026-10-20.log share one key (folder + base name).
    #>
    param([string]$Path)
    $dir = ''
    $name = ''
    try {
        $dir = [string][System.IO.Path]::GetDirectoryName($Path)
        $name = [string][System.IO.Path]::GetFileName($Path)
    }
    catch { return ([string]$Path).ToLowerInvariant() }
    $n = $name.ToLowerInvariant()
    $n = [regex]::Replace($n, '\.gz$', '')
    $n = [regex]::Replace($n, '\.[0-9]+$', '')
    $n = [regex]::Replace($n, '[-_.][0-9]{8}$', '')
    $n = [regex]::Replace($n, '[-_.](?:[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{8})(?=\.[a-z]+$)', '')
    return ($dir.ToLowerInvariant() + '\' + $n)
}

function Get-P2SLogFamilies {
    <# The candidate logs, each grouped with its rotated siblings in the same folder. #>
    $families = [ordered]@{}
    foreach ($p in @(Get-P2SLogCandidates)) {
        $key = Get-P2SLogFamilyKey $p
        if (-not $families.Contains($key)) {
            $families[$key] = [pscustomobject]@{ Label = $p; Files = [System.Collections.Generic.List[string]]::new(); Seen = @{} }
        }
        $fam = $families[$key]
        if (-not $fam.Seen.ContainsKey($p)) { $fam.Seen[$p] = $true; $fam.Files.Add($p) }
    }
    $dirs = @{}
    foreach ($fam in @($families.Values)) {
        $d = Split-Path -Path $fam.Label -Parent
        if ($d) { $dirs[$d] = $true }
    }
    foreach ($d in @($dirs.Keys)) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d -File -Force -ErrorAction SilentlyContinue)) {
            $key = Get-P2SLogFamilyKey $f.FullName
            if (-not $families.Contains($key)) { continue }
            $fam = $families[$key]
            if (-not $fam.Seen.ContainsKey($f.FullName)) { $fam.Seen[$f.FullName] = $true; $fam.Files.Add($f.FullName) }
        }
    }
    foreach ($fam in @($families.Values)) { $fam }
}

function New-P2SLogCounts {
    <# Per-family counters. Covers: the family shows time before the window. #>
    $acc = [pscustomobject]@{ Covers = $false; Win = @{}; Before = @{}; Undated = @{}; Samples = @{} }
    foreach ($c in @('crash', 'oom-prescript', 'oom', 'prescript', 'timeout', 'hard-oom')) {
        $acc.Win[$c] = 0
        $acc.Before[$c] = 0
        $acc.Undated[$c] = 0
        $acc.Samples[$c] = [System.Collections.Generic.List[string]]::new()
    }
    return $acc
}

function Read-P2SLogCounts {
    <#
      Adds one log file's classified lines to the family counters. Logs are
      read in full, streamed; .gz rotations are decompressed. -Old: a file last
      written before the window, so all its lines count as before it.
      Returns $false when the file could not be read.
    #>
    param([string]$Path, [int]$SinceInt, [bool]$Old, $Acc)
    $fs = $null
    $sr = $null
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        $stream = $fs
        if ($Path -match '(?i)\.gz$') {
            try { Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop } catch { $null = $_ }
            $stream = New-Object -TypeName System.IO.Compression.GZipStream -ArgumentList $fs, ([System.IO.Compression.CompressionMode]::Decompress)
        }
        $sr = New-Object -TypeName System.IO.StreamReader -ArgumentList $stream
        $first = $true
        while ($null -ne ($line = $sr.ReadLine())) {
            if ($first -and $line.Trim() -ne '') {
                # A first line dated before the window: the family covers that time.
                $first = $false
                $fd = Get-P2SLogDate $line
                if ($fd -gt 0 -and $fd -lt $SinceInt) { $Acc.Covers = $true }
            }
            if (-not $script:P2S_LogPrefilter.IsMatch($line)) { continue }
            $cat = Get-P2SLogLineCategory $line
            if ($null -eq $cat) { continue }
            $d = Get-P2SLogDate $line
            if ($Old -or ($d -gt 0 -and $d -lt $SinceInt)) {
                $Acc.Before[$cat]++
                $Acc.Covers = $true
                continue
            }
            if ($d -eq 0) { $Acc.Undated[$cat]++ } else { $Acc.Win[$cat]++ }
            if ($Acc.Samples[$cat].Count -lt 2) { $Acc.Samples[$cat].Add((Format-P2SShort $line 200)) }
        }
        return $true
    }
    catch {
        Add-P2SCoverage ('Could not read log ' + $Path + ': ' + $_.Exception.Message)
        return $false
    }
    finally {
        if ($null -ne $sr) { $sr.Dispose() }
        elseif ($null -ne $fs) { $fs.Dispose() }
    }
}

function Invoke-P2SLogFamilyTriage {
    <# Returns $true when a log of the family was written since the window started and read. #>
    param($Family)
    $since = $script:P2S_Opt.SinceDate
    $sinceInt = ConvertTo-P2SDateInt $since
    $sinceText = Format-P2SDate $since
    $recent = [System.Collections.Generic.List[object]]::new()
    $older = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $Family.Files) {
        $fi = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        if ($null -eq $fi -or $fi.PSIsContainer) { continue }
        if ($fi.LastWriteTime -ge $since) { $recent.Add($fi) } else { $older.Add($fi) }
    }
    # Only files written since the window started can hold window events.
    if ($recent.Count -eq 0) { return $false }
    $acc = New-P2SLogCounts
    # A file of the family last written before the window: it covers that time.
    if ($older.Count -gt 0) { $acc.Covers = $true }
    $read = 0
    foreach ($fi in $recent) {
        if (Read-P2SLogCounts -Path $fi.FullName -SinceInt $sinceInt -Old $false -Acc $acc) { $read++ }
    }
    if ($read -eq 0) { return $false }
    # Crashes only in the window so far: read the newest older rotated file too,
    # so routine crashes from before the window are not reported as new.
    if ($acc.Win['crash'] -gt 0 -and $acc.Before['crash'] -eq 0 -and $older.Count -gt 0) {
        $newest = @($older | Sort-Object -Property LastWriteTime -Descending)[0]
        $null = Read-P2SLogCounts -Path $newest.FullName -SinceInt $sinceInt -Old $true -Acc $acc
    }
    $loc = $Family.Label
    if ($Family.Files.Count -gt 1) { $loc = ('{0} (+{1} rotated file(s))' -f $Family.Label, ($Family.Files.Count - 1)) }
    $sample = { param($c) ($acc.Samples[$c] -join ' || ') }
    $context = {
        param($c)
        $t = ('{0} before {1}' -f $acc.Before[$c], $sinceText)
        if ($acc.Undated[$c] -gt 0) { $t = ('{0}, {1} undated in a file changed since then' -f $t, $acc.Undated[$c]) }
        $t
    }
    $n = @{}
    foreach ($c in @($acc.Win.Keys)) { $n[$c] = $acc.Win[$c] + $acc.Undated[$c] }
    if ($n['crash'] -gt 0) {
        # HIGH only with dated crashes in the window, none before, and a family
        # that covers the time before the window (docs/SPEC.md section 5).
        $sev = 'REVIEW'
        if ($acc.Win['crash'] -gt 0 -and $acc.Before['crash'] -eq 0 -and $acc.Covers) { $sev = 'HIGH' }
        $note = ''
        if ($acc.Before['crash'] -eq 0 -and -not $acc.Covers) { $note = (' This log has nothing from before {0} to compare with.' -f $sinceText) }
        Add-P2SFinding -Severity $sev -Category crash -Title ('{0} crash / heap-corruption line(s) since {1}' -f $n['crash'], $sinceText) -Location $loc -Count $n['crash'] -Detail ('{0}.{1} Sample: {2}' -f (& $context 'crash'), $note, (& $sample 'crash'))
    }
    if ($n['oom-prescript'] -gt 0) {
        Add-P2SFinding -Severity HIGH -Category oom -Title ('{0} out-of-memory error(s) before any script ran (in Unknown on line 0) since {1}' -f $n['oom-prescript'], $sinceText) -Location $loc -Count $n['oom-prescript'] -Detail ('Matches the CVE-2026-109618 request-parsing OOM pattern; {0}. Sample: {1}' -f (& $context 'oom-prescript'), (& $sample 'oom-prescript'))
    }
    if ($n['oom'] -gt 0) {
        Add-P2SFinding -Severity REVIEW -Category oom -Title ('{0} out-of-memory error(s) since {1}' -f $n['oom'], $sinceText) -Location $loc -Count $n['oom'] -Detail ('{0}. Sample: {1}' -f (& $context 'oom'), (& $sample 'oom'))
    }
    if ($n['prescript'] -gt 0) {
        Add-P2SFinding -Severity REVIEW -Category prescript -Title ('{0} diagnostic(s) raised before scripts ran (in Unknown on line 0) since {1}' -f $n['prescript'], $sinceText) -Location $loc -Count $n['prescript'] -Detail ('{0}. Sample: {1}' -f (& $context 'prescript'), (& $sample 'prescript'))
    }
    if ($n['timeout'] -gt 0) {
        Add-P2SFinding -Severity INFO -Category timeout -Title ('{0} execution timeout(s) since {1}' -f $n['timeout'], $sinceText) -Location $loc -Count $n['timeout'] -Detail ('Timeouts are a CVE-2026-109619 producer; {0}.' -f (& $context 'timeout'))
    }
    if ($n['hard-oom'] -gt 0) {
        Add-P2SFinding -Severity INFO -Category hard-oom -Title ('{0} hard memory limit stop(s) since {1}' -f $n['hard-oom'], $sinceText) -Location $loc -Count $n['hard-oom'] -Detail 'A patched build stopped a request at the hard memory limit (possible attempt against a fixed server).'
    }
    return $true
}

function Invoke-P2SLogTriage {
    $read = 0
    foreach ($fam in @(Get-P2SLogFamilies)) {
        if (Invoke-P2SLogFamilyTriage -Family $fam) { $read++ }
    }
    if ($read -eq 0) {
        Add-P2SCoverage ('No PHP or web server log written since {0} was found. If logs are kept elsewhere (a central logging service), search them for PHP crashes and ''Allowed memory size'' errors.' -f (Format-P2SDate $script:P2S_Opt.SinceDate))
    }
}

function Invoke-P2SProcessTriage {
    $procs = @($script:P2S_Processes)
    if ($procs.Count -eq 0) { return }
    $byId = @{}
    foreach ($p in $procs) { $byId[$p.ProcessId] = $p }
    $suspicious = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'wscript.exe', 'cscript.exe', 'curl.exe', 'whoami.exe', 'net.exe', 'net1.exe', 'nltest.exe', 'wmic.exe')
    $hasModPhp = (@($script:P2S_InstallDirs.Values | Where-Object { $_.Sapis.Contains('mod_php') }).Count -gt 0)
    foreach ($p in $procs) {
        if ($suspicious -notcontains $p.Name.ToLowerInvariant()) { continue }
        if ($p.CommandLine -match '(?i)sendmail') { continue }
        $chain = [System.Collections.Generic.List[string]]::new()
        $cur = $p
        $sev = $null
        $seen = @{}
        for ($i = 0; $i -lt 4; $i++) {
            if (-not $byId.ContainsKey($cur.ParentProcessId)) { break }
            $par = $byId[$cur.ParentProcessId]
            if ($par.ProcessId -eq $cur.ProcessId -or $seen.ContainsKey($par.ProcessId)) { break }
            # A parent created after its child means the PID was reused.
            if ($null -ne $par.Created -and $null -ne $cur.Created -and $par.Created -gt $cur.Created) { break }
            $seen[$par.ProcessId] = $true
            $chain.Add(('{0}({1})' -f $par.Name, $par.ProcessId))
            $pn = $par.Name.ToLowerInvariant()
            if ($pn -eq 'php-cgi.exe') { $sev = 'HIGH' }
            elseif ($pn -eq 'httpd.exe') { if ($hasModPhp) { $sev = 'HIGH' } elseif ($null -eq $sev) { $sev = 'REVIEW' } }
            elseif (@('w3wp.exe', 'php.exe', 'php-win.exe') -contains $pn) { if ($null -eq $sev) { $sev = 'REVIEW' } }
            $cur = $par
        }
        if ($null -eq $sev) { continue }
        Add-P2SFinding -Severity $sev -Category process -Title ('{0} started by a PHP or web-server process' -f $p.Name) -Location ('pid {0} <- {1}' -f $p.ProcessId, ($chain -join ' <- ')) -Detail ('Command line (secrets redacted): ' + (Format-P2SShort (ConvertTo-P2SRedactedText $p.CommandLine) 160))
    }
}

function Get-P2SWebRootList {
    $candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($d in @('C:\inetpub\wwwroot', 'C:\xampp\htdocs', 'C:\wamp64\www', 'C:\wamp\www', 'C:\laragon\www')) { $candidates.Add($d) }
    foreach ($d in $script:P2S_WebRoots) { $candidates.Add($d) }
    foreach ($d in @($script:P2S_Opt.WebRoot)) {
        if (-not $d) { continue }
        # Folders the user named must exist; say so instead of skipping them silently.
        $x = [Environment]::ExpandEnvironmentVariables([string]$d)
        $exists = $false
        try { $exists = Test-Path -LiteralPath $x -PathType Container } catch { $exists = $false }
        if (-not $exists) { Add-P2SCoverage ('-WebRoot folder not found, so it was not checked: ' + $x); continue }
        $candidates.Add($x)
    }
    $real = [System.Collections.Generic.List[string]]::new()
    foreach ($d in $candidates) {
        $x = [Environment]::ExpandEnvironmentVariables($d)
        $exists = $false
        try { $exists = Test-Path -LiteralPath $x -PathType Container } catch { $exists = $false }
        if (-not $exists) { continue }
        $r = Resolve-P2SDirectory $x
        if ($r -and -not $real.Contains($r)) { $real.Add($r) }
    }
    # Drop roots nested inside another root: scanning the parent covers them.
    $sorted = @($real | Sort-Object -Property Length)
    $kept = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $sorted) {
        $nested = $false
        foreach ($k in $kept) { if ($r.StartsWith($k.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)) { $nested = $true; break } }
        if (-not $nested) { $kept.Add($r) }
    }
    return $kept
}

function Test-P2SSilenceFile {
    <# WordPress-style placeholder: "<?php // Silence is golden." #>
    param($File)
    if ($File.Length -ge 100) { return $false }
    $t = Get-P2SFileText -Path $File.FullName -MaxBytes 100
    if ($null -eq $t) { return $false }
    $t = $t.Trim()
    return ([regex]::IsMatch($t, '^<\?php\s*(//|#|/\*)') -and -not $t.Contains('('))
}

function Format-P2SPathList {
    param($Files, [int]$Max = 10)
    $names = @($Files | Select-Object -First $Max | ForEach-Object { $_.FullName })
    $text = $names -join '; '
    if (@($Files).Count -gt $Max) { $text += ('; ... ({0} more)' -f (@($Files).Count - $Max)) }
    return $text
}

function Get-P2SImageCodeLevel {
    <#
      'HIGH' for PHP code in an image or icon (an opening tag followed by code,
      or a webshell pattern), 'REVIEW' for a bare '<?php' tag, else $null.
      A bare '<?=' is ignored: it turns up by chance in compressed image data.
    #>
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    if ([regex]::IsMatch($Text, $script:P2S_ImageCodePattern, 'IgnoreCase')) { return 'HIGH' }
    if ($null -ne (Get-P2SWebshellMatch $Text)) { return 'HIGH' }
    if ([regex]::IsMatch($Text, '<\?php[ \t\r\n]', 'IgnoreCase')) { return 'REVIEW' }
    return $null
}

function Invoke-P2SWebRootTriage {
    $since = $script:P2S_Opt.SinceDate
    $sinceText = Format-P2SDate $since
    $phpExt = '(?i)\.(php\d?|phtml|pht|phar)$'
    $iconExt = '(?i)\.ico$'
    $imgExt = '(?i)\.(jpe?g|png|gif)$'
    $uploadRe = '(?i)\\(wp-content\\uploads|uploads?|media|images)\\|\\sites\\[^\\]+\\files\\'
    $twigRe = '(?i)\\files\\php\\twig\\'
    $roots = @(Get-P2SWebRootList)
    if ($roots.Count -eq 0) { Add-P2SCoverage 'No web root found; pass -WebRoot to triage your sites.'; return }
    foreach ($root in $roots) {
        $errs = $null
        $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue -ErrorVariable errs)
        if (@($errs).Count -gt 0) { Add-P2SCoverage ('{0} item(s) under {1} could not be read.' -f @($errs).Count, $root) -Limits }
        $changed = [System.Collections.Generic.List[object]]::new()
        $inUploads = [System.Collections.Generic.List[object]]::new()
        $codeInImages = [System.Collections.Generic.List[object]]::new()
        $tagInImages = [System.Collections.Generic.List[object]]::new()
        foreach ($f in $files) {
            $full = $f.FullName
            if ($full -match '(?i)\\(node_modules|\.git)\\') { continue }
            $recent = ($f.LastWriteTime -ge $since -or $f.CreationTime -ge $since)
            if ($f.Name -match $phpExt) {
                if ($recent) { $changed.Add($f) }
                if ($full -match $uploadRe -and $full -notmatch $twigRe -and -not (Test-P2SSilenceFile $f)) { $inUploads.Add($f) }
            }
            elseif (($f.Name -match $iconExt -and $f.Length -le 2MB) -or ($recent -and $f.Name -match $imgExt -and $f.Length -le 10MB)) {
                # PHP hidden in icons (any age) or in images changed in the window.
                $level = Get-P2SImageCodeLevel (Get-P2SFileText -Path $full -MaxBytes 10485760)
                if ($level -eq 'HIGH') { $codeInImages.Add($f) }
                elseif ($level -eq 'REVIEW') { $tagInImages.Add($f) }
            }
            elseif ($f.Name -ieq '.user.ini' -or $f.Name -ieq '.htaccess') {
                $t = Get-P2SFileText -Path $full -MaxBytes 1048576
                if ($null -eq $t) { continue }
                foreach ($m in [regex]::Matches($t, '(?im)^[ \t]*(?:php_(?:admin_)?value[ \t]+)?auto_(?:prepend|append)_file\b[^\r\n]*')) {
                    $val = $m.Value
                    if ($val -match '(?i)wordfence-waf\.php' -or $val -match '(?i)auto_(prepend|append)_file[ \t"=]*(none)?[ \t"]*$') { continue }
                    $sev = 'REVIEW'; if ($recent) { $sev = 'HIGH' }
                    Add-P2SFinding -Severity $sev -Category persistence -Title ('{0} sets auto_prepend_file/auto_append_file' -f $f.Name) -Location $full -Detail ('Code injected into every request can be a persistence mechanism. Modified {0}.' -f (Format-P2SDate $f.LastWriteTime 'yyyy-MM-dd HH:mm'))
                }
                if ($f.Name -ieq '.htaccess') {
                    $remap = [regex]::IsMatch($t, '(?im)^[ \t]*(AddType|AddHandler)[ \t]+application/x-httpd-php[^\r\n]*\.(jpe?g|png|gif|ico|txt|bmp|svg)\b')
                    $setHandlerInUploads = ($full -match $uploadRe) -and [regex]::IsMatch($t, '(?im)^[ \t]*SetHandler[ \t]+application/x-httpd-php')
                    if ($remap -or $setHandlerInUploads) {
                        Add-P2SFinding -Severity HIGH -Category persistence -Title '.htaccess makes non-PHP files executable as PHP' -Location $full -Detail ('Handler remapping is a common webshell trick. Modified {0}.' -f (Format-P2SDate $f.LastWriteTime 'yyyy-MM-dd HH:mm'))
                    }
                }
            }
        }
        if ($changed.Count -gt 0) {
            Add-P2SFinding -Severity REVIEW -Category webroot -Title ('{0} PHP file(s) created or modified since {1}' -f $changed.Count, $sinceText) -Location $root -Count $changed.Count -Detail (Format-P2SPathList $changed)
        }
        if ($inUploads.Count -gt 0) {
            Add-P2SFinding -Severity REVIEW -Category webroot -Title ('{0} PHP file(s) inside upload/media folders' -f $inUploads.Count) -Location $root -Count $inUploads.Count -Detail (Format-P2SPathList $inUploads)
        }
        if ($codeInImages.Count -gt 0) {
            Add-P2SFinding -Severity HIGH -Category webroot -Title ('{0} image/icon file(s) contain PHP code (an opening tag followed by code, or a webshell pattern)' -f $codeInImages.Count) -Location $root -Count $codeInImages.Count -Detail (Format-P2SPathList $codeInImages)
        }
        if ($tagInImages.Count -gt 0) {
            Add-P2SFinding -Severity REVIEW -Category webroot -Title ('{0} image/icon file(s) contain a PHP opening tag' -f $tagInImages.Count) -Location $root -Count $tagInImages.Count -Detail (Format-P2SPathList $tagInImages)
        }
        # Webshell patterns in the files most likely to be malicious: every
        # changed or upload-folder PHP file up to 5 MB, with no cap on the count.
        $candidates = @(@($changed) + @($inUploads) | Sort-Object -Property FullName -Unique | Where-Object { $_.Length -le 5MB })
        foreach ($f in $candidates) {
            $hit = Get-P2SWebshellMatch (Get-P2SFileText -Path $f.FullName)
            if ($null -ne $hit) {
                Add-P2SFinding -Severity HIGH -Category webshell -Title ('Webshell pattern: ' + $hit) -Location $f.FullName -Detail ('Modified {0}. Content not shown.' -f (Format-P2SDate $f.LastWriteTime 'yyyy-MM-dd HH:mm'))
            }
        }
    }
}

function Invoke-P2SScheduledTaskTriage {
    if ($null -eq (Get-Command -Name 'Get-ScheduledTask' -ErrorAction SilentlyContinue)) {
        Add-P2SCoverage 'Get-ScheduledTask is not available; scheduled tasks were not checked.'
        return
    }
    $tasks = @()
    try { $tasks = @(Get-ScheduledTask -ErrorAction Stop) }
    catch { Add-P2SCoverage ('Could not list scheduled tasks: ' + $_.Exception.Message); return }
    $since = $script:P2S_Opt.SinceDate
    foreach ($t in $tasks) {
        $taskPath = ''
        $taskName = ''
        $dateText = ''
        try { $taskPath = [string]$t.TaskPath; $taskName = [string]$t.TaskName; $dateText = [string]$t.Date } catch { continue }
        if ($taskPath -like '\Microsoft\*' -or [string]::IsNullOrWhiteSpace($dateText)) { continue }
        $d = [datetime]::MinValue
        if (-not [datetime]::TryParse($dateText, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$d)) { continue }
        if ($d -lt $since) { continue }
        $exec = ''
        try { $exec = (@($t.Actions) | ForEach-Object { ([string]$_.Execute + ' ' + [string]$_.Arguments).Trim() }) -join ' | ' } catch { $exec = '' }
        Add-P2SFinding -Severity REVIEW -Category persistence -Title ('Scheduled task registered since {0}: {1}{2}' -f (Format-P2SDate $since), $taskPath, $taskName) -Location ($taskPath + $taskName) -Detail ('Registered {0}. Action (secrets redacted): {1}' -f (Format-P2SDate $d 'yyyy-MM-dd HH:mm'), (Format-P2SShort (ConvertTo-P2SRedactedText $exec) 160))
    }
}

function Invoke-P2STriage {
    Invoke-P2SEventLogTriage
    Invoke-P2SLogTriage
    Invoke-P2SProcessTriage
    Invoke-P2SWebRootTriage
    Invoke-P2SScheduledTaskTriage
}

# ---------------------------------------------------------------------------
# Report (docs/SPEC.md sections 6 and 7)
# ---------------------------------------------------------------------------
function Get-P2SSummary {
    param($Installations, $Findings, [bool]$CoverageLimited)
    $inst = @($Installations | Where-Object { $null -ne $_ })
    $fnd = @($Findings | Where-Object { $null -ne $_ })
    $vuln = @($inst | Where-Object { $_.verdict -eq 'VULNERABLE' }).Count
    $fixed = @($inst | Where-Object { $_.verdict -eq 'FIXED' }).Count
    $unknown = @($inst | Where-Object { $_.verdict -eq 'UNKNOWN' }).Count
    $restart = @($inst | Where-Object { $true -eq $_.running.restart_required }).Count
    $high = @($fnd | Where-Object { $_.severity -eq 'HIGH' }).Count
    $review = @($fnd | Where-Object { $_.severity -eq 'REVIEW' }).Count
    $code = 0
    if ($vuln -gt 0 -or $restart -gt 0) { $code = $code -bor 1 }
    if ($unknown -gt 0 -or $CoverageLimited) { $code = $code -bor 2 }
    if ($high -gt 0) { $code = $code -bor 4 }
    $verdict = 'NO_PHP_FOUND'
    if (($code -band 1) -ne 0) { $verdict = 'VULNERABLE' }
    elseif (($code -band 2) -ne 0) { $verdict = 'INCOMPLETE' }
    elseif ($inst.Count -gt 0) { $verdict = 'FIXED' }
    return [ordered]@{
        verdict          = $verdict
        installations    = $inst.Count
        vulnerable       = $vuln
        fixed            = $fixed
        unknown          = $unknown
        restart_required = $restart
        high_findings    = $high
        review_findings  = $review
        exit_code        = $code
    }
}

function Test-P2SAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function New-P2SReport {
    param($Installations, $Summary)
    $os = [Environment]::OSVersion.VersionString
    try {
        $w = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $os = ('{0} {1}' -f [string]$w.Caption, [string]$w.Version).Trim()
    }
    catch { $null = $_ }
    $sevOrder = @{ 'HIGH' = 0; 'REVIEW' = 1; 'INFO' = 2 }
    $findings = @($script:P2S_Findings | Sort-Object -Property @{ Expression = { $sevOrder[$_.severity] } }, @{ Expression = { $_.category } })
    return [ordered]@{
        tool          = 'php2shell-check'
        tool_version  = $script:P2S_ToolVersion
        checker       = 'ps1'
        data_version  = $script:P2S_DataVersion
        scanned_at    = (Format-P2SDate -Date ((Get-Date).ToUniversalTime()) -Format "yyyy-MM-dd'T'HH:mm:ss'Z'")
        host          = [ordered]@{ hostname = [Environment]::MachineName; platform = 'windows'; os = $os; is_root = [bool]$script:P2S_IsAdmin }
        cves          = @($script:P2S_Cves)
        since         = (Format-P2SDate $script:P2S_Opt.SinceDate)
        summary       = $Summary
        installations = @($Installations)
        findings      = $findings
        coverage      = @($script:P2S_Coverage)
    }
}

function Get-P2SNextSteps {
    param($Report)
    $s = $Report.summary
    $steps = [System.Collections.Generic.List[string]]::new()
    if ($s.vulnerable -gt 0) {
        $steps.Add('Upgrade PHP: 8.5 -> 8.5.12, 8.4 -> 8.4.27, 8.3 -> 8.3.36, 8.2 -> 8.2.35 (windows.php.net builds). PHP 8.1 and older get no fix from PHP: move to a supported branch or get a vendor backport.')
    }
    if ($s.vulnerable -gt 0 -or $s.restart_required -gt 0) {
        $steps.Add('After upgrading, restart every PHP worker: IIS (iisreset, or recycle the app pools running php-cgi.exe), Apache (restart the service), and any standalone php-cgi.exe.')
    }
    if ($s.vulnerable -gt 0) {
        $steps.Add('If you cannot patch right now (partial only): session.upload_progress.enabled=0, memory_limit=-1 set administratively, and on PHP 8.5 fatal_error_backtraces=0; restart workers. Restrict access or put the site behind a WAF.')
    }
    if ($s.high_findings -gt 0) {
        $steps.Add('Treat HIGH findings as a possible compromise: isolate the server, preserve the Event Log and Apache/PHP logs, and investigate before cleaning up.')
    }
    if ($s.review_findings -gt 0) { $steps.Add('Check the REVIEW findings; normal deployments and updates can also cause them.') }
    if (($s.exit_code -band 2) -ne 0) { $steps.Add('Re-run as Administrator (add -Deep to search every fixed drive) for full coverage.') }
    $steps.Add('Re-run this check after patching.')
    return $steps
}

function Get-P2SHumanLines {
    param($Report)
    $out = [System.Collections.Generic.List[object]]::new()
    $add = { param($Text, $Color) $out.Add([pscustomobject]@{ Text = [string]$Text; Color = [string]$Color }) }
    $s = $Report.summary
    $adminText = 'no'
    if ($Report.host.is_root) { $adminText = 'yes' }
    & $add ('php2shell-check {0} (Windows) - PHP2Shell: CVE-2026-109618 / CVE-2026-109619' -f $Report.tool_version) 'Cyan'
    & $add ('Host: {0} | {1} | Administrator: {2} | data {3} | triage window since {4}' -f $Report.host.hostname, $Report.host.os, $adminText, $Report.data_version, $Report.since) ''
    & $add '' ''
    $vc = 'Yellow'
    if ($s.verdict -eq 'VULNERABLE') { $vc = 'Red' } elseif ($s.verdict -eq 'FIXED' -or $s.verdict -eq 'NO_PHP_FOUND') { $vc = 'Green' }
    & $add ('VERDICT: ' + $s.verdict) $vc
    & $add ('  {0} installation(s): {1} vulnerable, {2} fixed, {3} unknown | restart required: {4} | findings: {5} high, {6} review' -f $s.installations, $s.vulnerable, $s.fixed, $s.unknown, $s.restart_required, $s.high_findings, $s.review_findings) ''
    & $add '' ''
    & $add 'PHP installations' 'Cyan'
    if (@($Report.installations).Count -eq 0) { & $add '  No PHP installation found in the checked locations.' '' }
    foreach ($i in @($Report.installations)) {
        $c = 'Yellow'
        if ($i.verdict -eq 'VULNERABLE') { $c = 'Red' } elseif ($i.verdict -eq 'FIXED') { $c = 'Green' }
        $ver = $i.version
        if (-not $ver) { $ver = '(version unknown)' }
        & $add ('  [{0}] {1}  {2}  {3}' -f $i.verdict, $ver, $i.sapi, $i.path) $c
        & $add ('      branch {0} ({1}) | evidence: {2} | reason: {3}' -f $i.branch, $i.branch_status, $i.evidence, $i.reason) ''
        $rr = 'no'
        if ($i.running.restart_required) { $rr = 'YES' }
        $runInfo = ''
        if ($i.running.verdict) {
            $rv = $i.running.version
            if (-not $rv) { $rv = 'replaced image, version unknown' }
            $runInfo = (' ({0}, {1})' -f $rv, $i.running.verdict)
        }
        & $add ('      exposure: {0} | running: {1} process(es){2} | restart required: {3}' -f $i.exposure, $i.running.processes, $runInfo, $rr) ''
        if ($i.found_by) { & $add ('      found by: ' + $i.found_by) '' }
        if ($i.remediation) { & $add ('      fix: ' + $i.remediation) '' }
    }
    & $add '' ''
    & $add 'Findings' 'Cyan'
    if (@($Report.findings).Count -eq 0) { & $add '  No findings. (No findings does not prove the server is clean.)' '' }
    foreach ($f in @($Report.findings)) {
        $c = ''
        if ($f.severity -eq 'HIGH') { $c = 'Red' } elseif ($f.severity -eq 'REVIEW') { $c = 'Yellow' }
        & $add ('  [{0}] {1}: {2}' -f $f.severity, $f.category, $f.title) $c
        if ($f.location) { & $add ('      at: ' + $f.location) '' }
        if ($f.detail) { & $add ('      ' + $f.detail) '' }
    }
    & $add '' ''
    & $add 'Coverage' 'Cyan'
    if (@($Report.coverage).Count -eq 0) { & $add '  Full coverage of the checks this tool performs.' '' }
    foreach ($c in @($Report.coverage)) { & $add ('  - ' + $c) '' }
    & $add '' ''
    & $add 'Next steps' 'Cyan'
    $n = 1
    foreach ($step in @(Get-P2SNextSteps $Report)) { & $add ('  {0}. {1}' -f $n, $step) ''; $n++ }
    return $out
}

function Get-P2SHelpText {
    return @(
        'php2shell-check.ps1 - read-only PHP2Shell (CVE-2026-109618 / CVE-2026-109619) checker for Windows',
        '',
        'Usage: powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1 [options]',
        '',
        '  -Json            JSON report (docs/SPEC.md) instead of text',
        '  -Since DATE      start of the compromise-triage window, yyyy-MM-dd (default 2026-10-20)',
        '  -SkipIoc         only check for vulnerable PHP; skip compromise triage',
        '  -Deep            also search every fixed drive for PHP builds (slower)',
        '  -WebRoot PATH    extra web root(s) to triage (comma-separated list allowed)',
        '  -NoColor         plain text output',
        '  -Version         print version and exit',
        '  -Help            this help',
        '',
        'Exit code (bit flags): 1 vulnerable, 2 incomplete, 4 high-severity indicators, 64 usage error',
        '(also for an unknown or mistyped option).',
        'Run as Administrator for full coverage. Nothing is changed on the system.'
    )
}

function Invoke-P2SMain {
    param(
        [switch]$Json, [string]$Since = '2026-10-20', [switch]$SkipIoc, [switch]$Deep,
        [string[]]$WebRoot = @(), [switch]$Help, [switch]$Version, [object[]]$UnknownArgs = @()
    )
    # Behave the same whatever the caller's preference (tests run with 'Stop').
    $ErrorActionPreference = 'Continue'
    Reset-P2SState
    # Unknown or mistyped options (caught by the script's ValueFromRemainingArguments
    # parameter) are a usage error, like a bad -Since.
    $extra = @(@($UnknownArgs) | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($extra.Count -gt 0) {
        $shown = @($extra | ForEach-Object { Format-P2SShort ([string]$_) 60 }) -join ' '
        return [pscustomobject]@{ ExitCode = 64; Output = @(('php2shell-check: unknown argument(s): {0}. Run with -Help to see the options.' -f $shown)); Lines = $null }
    }
    if ($Help) { return [pscustomobject]@{ ExitCode = 0; Output = @(Get-P2SHelpText); Lines = $null } }
    if ($Version) { return [pscustomobject]@{ ExitCode = 0; Output = @(('php2shell-check {0} (ps1, data {1})' -f $script:P2S_ToolVersion, $script:P2S_DataVersion)); Lines = $null } }
    $sinceDate = [datetime]::MinValue
    if (-not [datetime]::TryParseExact([string]$Since, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$sinceDate)) {
        return [pscustomobject]@{ ExitCode = 64; Output = @(("php2shell-check: -Since must be yyyy-MM-dd (got '{0}')" -f (Format-P2SShort $Since 40))); Lines = $null }
    }
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        return [pscustomobject]@{ ExitCode = 64; Output = @('php2shell-check.ps1 is for Windows. On Linux and macOS use php2shell-check.sh.'); Lines = $null }
    }
    # -WebRoot a,b arrives as the single string 'a,b' under powershell -File.
    $script:P2S_Opt = @{ Deep = [bool]$Deep; SkipIoc = [bool]$SkipIoc; SinceDate = $sinceDate; WebRoot = @(Split-P2SWebRootList $WebRoot) }
    $script:P2S_IsAdmin = Test-P2SAdmin
    if (-not $script:P2S_IsAdmin) {
        Add-P2SCoverage 'Not running as Administrator: IIS configuration, other users'' process paths, some logs and web roots may be unreadable.' -Limits
    }

    Invoke-P2SDiscovery
    if (@($script:P2S_InstallDirs.Values | Where-Object { $_.Sapis.Contains('mod_php') }).Count -gt 0) { Read-P2SHtaccessOverrides }
    $installations = @(Get-P2SInstallationRecords)
    foreach ($e in @($script:P2S_InstallDirs.Values)) { Add-P2SConfigFindings -Entry $e }
    Add-P2SOverrideFindings
    if ($SkipIoc) { Add-P2SCoverage 'Compromise triage skipped (-SkipIoc).' }
    else { Invoke-P2STriage }

    $summary = Get-P2SSummary -Installations $installations -Findings $script:P2S_Findings -CoverageLimited $script:P2S_CoverageLimited
    $report = New-P2SReport -Installations $installations -Summary $summary
    if ($Json) {
        # Non-ASCII escaped as \uXXXX: valid JSON whatever the output encoding (PowerShell 5.1).
        return [pscustomobject]@{ ExitCode = [int]$summary.exit_code; Output = @(ConvertTo-P2SAsciiJson (ConvertTo-Json -InputObject $report -Depth 10)); Lines = $null }
    }
    return [pscustomobject]@{ ExitCode = [int]$summary.exit_code; Output = $null; Lines = @(Get-P2SHumanLines $report) }
}

# Entry point: runs only when executed, not when dot-sourced (tests).
if ($MyInvocation.InvocationName -ne '.') {
    $p2sResult = Invoke-P2SMain -Json:$Json -Since $Since -SkipIoc:$SkipIoc -Deep:$Deep -WebRoot $WebRoot -Help:$Help -Version:$Version -UnknownArgs $UnboundArguments
    if ($null -ne $p2sResult.Lines) {
        $p2sColor = -not $NoColor
        try { if ([Console]::IsOutputRedirected) { $p2sColor = $false } } catch { $p2sColor = $false }
        foreach ($p2sLine in $p2sResult.Lines) {
            if ($p2sColor) {
                if ($p2sLine.Color) { Write-Host $p2sLine.Text -ForegroundColor $p2sLine.Color } else { Write-Host $p2sLine.Text }
            }
            else { Write-Output $p2sLine.Text }
        }
    }
    else {
        foreach ($p2sOut in @($p2sResult.Output)) { Write-Output $p2sOut }
    }
    exit $p2sResult.ExitCode
}
