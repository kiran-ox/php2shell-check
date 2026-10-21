<?php
/*
 * php2shell-check web probe 1.0.0
 *
 * Checks the PHP build that serves this website for PHP2Shell
 * (CVE-2026-109618 / CVE-2026-109619). For hosting accounts without shell
 * access. On a server you control, run php2shell-check.sh instead: it also
 * covers other PHP versions, running processes, restarts and logs.
 *
 * How to use
 *   1. Set PROBE_TOKEN below to a random string of at least 16 letters and
 *      digits.
 *   2. Upload this file to your web root under a random name, for example
 *      p2s-7f3k9q2m.php.
 *   3. Send the token in the X-Probe-Token request header:
 *        curl -H 'X-Probe-Token: YOUR_TOKEN' https://your-site.example/p2s-7f3k9q2m.php
 *      Add ?format=json to the URL for machine-readable output.
 *      Without the header, ?token=YOUR_TOKEN in the URL also works, but a
 *      token in a URL ends up in access logs and browser history, and a chat
 *      app that previews a pasted link would run the probe and delete it.
 *   4. The file deletes itself before it prints the result. Add keep=1 to the
 *      query string to keep it, then delete it yourself when you are done.
 *      A missing or wrong token gets 403 Forbidden and nothing else.
 *
 * What it does
 *   Reads PHP_VERSION, the server API and a few INI values of the request that
 *   runs it. It changes nothing, sends nothing anywhere and never calls
 *   phpinfo(). Its only side effect is deleting its own file.
 *
 * Syntax is kept compatible with PHP 5.2 through 8.x so it can report on
 * end-of-life versions too.
 *
 * Verdict logic: docs/SPEC.md. Data: data/php2shell.json. License: Apache-2.0.
 */

define('PROBE_TOKEN', 'CHANGE-ME-TO-A-LONG-RANDOM-STRING');

define('P2S_TOKEN_PLACEHOLDER', 'CHANGE-ME-TO-A-LONG-RANDOM-STRING');
define('P2S_TOOL_VERSION', '1.0.0');

// BEGIN PHP2SHELL DATA (copy of data/php2shell.json; tests check they match)
function p2s_data()
{
    return array(
        'data_version' => '2026-10-21.1',
        'cves' => array('CVE-2026-109618', 'CVE-2026-109619'),
        'fixed' => array(
            '8.5' => '8.5.12',
            '8.4' => '8.4.27',
            '8.3' => '8.3.36',
            '8.2' => '8.2.35',
        ),
        'prerelease' => array('8.6', '8.7'),
        'oldest_supported' => '8.2',
        'security_support_ends' => array('8.2' => '2026-12-31'),
        'fingerprint_ini' => 'memory_hard_limit_percent',
    );
}
// END PHP2SHELL DATA

function p2s_exposure($sapi)
{
    $map = array(
        'mod_php' => 'highest',
        'frankenphp' => 'high',
        'fpm' => 'high',
        'litespeed' => 'elevated',
        'cgi' => 'elevated',
        'cli' => 'low',
        'phpdbg' => 'low',
    );
    return isset($map[$sapi]) ? $map[$sapi] : 'unknown';
}

function p2s_sapi($raw)
{
    $r = strtolower((string) $raw);
    if ($r === 'apache2handler' || $r === 'apache2filter' || $r === 'apache') {
        return 'mod_php';
    }
    if ($r === 'fpm-fcgi') {
        return 'fpm';
    }
    if ($r === 'cgi-fcgi' || $r === 'cgi') {
        return 'cgi';
    }
    return $r;
}

// Directives the advisory names as emitting diagnostics before request
// initialization when they are set per request (CVE-2026-109619 consumer).
function p2s_flagged_directive($name)
{
    $exact = array(
        'auto_detect_line_endings',
        'filter.default',
        'session.sid_length',
        'session.sid_bits_per_character',
        'session.use_trans_sid',
        'session.trans_sid_tags',
        'session.trans_sid_hosts',
        'session.referer_check',
        'session.use_only_cookies',
        'report_memleaks',
        'intl.error_level',
        'mbstring.http_input',
        'mbstring.http_output',
        'mbstring.internal_encoding',
        'iconv.input_encoding',
        'iconv.output_encoding',
        'iconv.internal_encoding',
    );
    if (in_array($name, $exact, true)) {
        return true;
    }
    return strpos($name, 'assert.') === 0;
}

// Returns array(major, minor, patch, kind, suffix) where kind is '' for a
// release, 'pre' for alpha/beta/RC/dev and 'vendor' for any other suffix
// (such as -1ubuntu2.20). Returns false when the string is not x.y.z...
function p2s_parse_version($v)
{
    if (!is_string($v)) {
        return false;
    }
    $len = strlen($v);
    $i = 0;
    $nums = array();
    for ($n = 0; $n < 3; $n++) {
        $start = $i;
        while ($i < $len && ord($v[$i]) >= 48 && ord($v[$i]) <= 57) {
            $i++;
        }
        if ($i === $start || $i - $start > 6) {
            return false;
        }
        $nums[] = (int) substr($v, $start, $i - $start);
        if ($n < 2) {
            if ($i >= $len || $v[$i] !== '.') {
                return false;
            }
            $i++;
        }
    }
    $suffix = $i < $len ? (string) substr($v, $i) : '';
    $kind = '';
    if ($suffix !== '') {
        $s = strtolower($suffix);
        if ($s[0] === '-') {
            $s = (string) substr($s, 1);
        }
        $kind = 'vendor';
        $pre = array('alpha', 'beta', 'rc', 'dev');
        foreach ($pre as $p) {
            if (strpos($s, $p) === 0) {
                $kind = 'pre';
            }
        }
    }
    return array($nums[0], $nums[1], $nums[2], $kind, $suffix);
}

// True when the parsed version is at or above the release $fixed ("x.y.z").
// A pre-release of x.y.z sorts before x.y.z.
function p2s_at_least($p, $fixed)
{
    $f = p2s_parse_version($fixed);
    if ($p === false || $f === false) {
        return false;
    }
    for ($i = 0; $i < 3; $i++) {
        if ($p[$i] > $f[$i]) {
            return true;
        }
        if ($p[$i] < $f[$i]) {
            return false;
        }
    }
    return $p[3] !== 'pre';
}

function p2s_branch_status($p, $data)
{
    $branch = $p[0] . '.' . $p[1];
    if (isset($data['fixed'][$branch])) {
        return 'supported';
    }
    if (in_array($branch, $data['prerelease'], true)) {
        // 8.6 pre-releases and master (8.7.0-dev) do not have the fix yet. A
        // release or vendor build of these branches is newer than the data.
        return ($p[3] === 'pre') ? 'prerelease' : 'newer';
    }
    $oldest = p2s_parse_version($data['oldest_supported'] . '.0');
    if ($p[0] < $oldest[0] || ($p[0] === $oldest[0] && $p[1] < $oldest[1])) {
        return 'eol';
    }
    return 'newer';
}

// Installation verdict, docs/SPEC.md section 3. Rules 4 and 5 (package
// changelog, vendor fixed versions) need server access and are not checked.
function p2s_assess($version, $fingerprint, $data)
{
    $r = array(
        'branch' => '',
        'branch_status' => 'unknown',
        'fixed_version' => '',
        'evidence' => 'none',
        'verdict' => 'UNKNOWN',
        'reason' => '',
        'remediation' => '',
    );
    $p = p2s_parse_version($version);
    if ($p === false) {
        $r['reason'] = 'version-unreadable';
        $r['remediation'] = 'The PHP version could not be read. Ask your hosting provider which PHP version serves this site.';
        return $r;
    }
    $branch = $p[0] . '.' . $p[1];
    $status = p2s_branch_status($p, $data);
    $r['branch'] = $branch;
    $r['branch_status'] = $status;
    if ($status === 'supported') {
        $r['fixed_version'] = $data['fixed'][$branch];
    }
    $sunset = '';
    if (isset($data['security_support_ends'][$branch])) {
        $sunset = ' PHP ' . $branch . ' security support ends ' . $data['security_support_ends'][$branch] . '; plan a move to 8.3 or newer.';
    }
    $vendor_note = '';
    if ($p[3] === 'vendor') {
        $vendor_note = ' This looks like a vendor build (suffix ' . p2s_clean($p[4], 40) . '). Vendors backport fixes without changing the version number, so ask your hosting provider whether this build includes the fix for CVE-2026-109618 and CVE-2026-109619.';
    }

    if ($fingerprint === true) {
        $r['verdict'] = 'FIXED';
        $r['evidence'] = 'fingerprint';
        $r['reason'] = 'patch-fingerprint-present';
        $r['remediation'] = 'No upgrade needed for these CVEs. Make sure every PHP worker was restarted after the update.' . $sunset;
        return $r;
    }
    if ($status === 'supported' && p2s_at_least($p, $r['fixed_version'])) {
        $r['verdict'] = 'FIXED';
        $r['evidence'] = 'version';
        if ($fingerprint === false) {
            $r['reason'] = 'at-or-above-fixed-version,fingerprint-missing';
            $r['remediation'] = 'No upgrade needed for these CVEs. The patch fingerprint was not found, which is unusual for an official build; ask your host to confirm the build includes the fix.' . $sunset;
        } else {
            $r['reason'] = 'at-or-above-fixed-version,fingerprint-unavailable';
            $r['remediation'] = 'No upgrade needed for these CVEs. Make sure every PHP worker was restarted after the update.' . $sunset;
        }
        return $r;
    }
    if ($status === 'newer') {
        $r['reason'] = 'branch-newer-than-data';
        $r['remediation'] = 'PHP ' . p2s_clean($version, 64) . ' is newer than the data in this probe (' . $data['data_version'] . ') and the patch fingerprint '
            . (($fingerprint === false) ? 'was not found' : 'could not be checked')
            . '. Get the latest probe, or check https://www.php.net/ to see whether this version includes the fix.';
        return $r;
    }

    $r['verdict'] = 'VULNERABLE';
    if ($status === 'eol') {
        $r['reason'] = 'eol-no-upstream-fix';
        $r['remediation'] = 'PHP ' . $branch . ' is end-of-life and gets no fix from the PHP project. Switch this site to a supported branch (8.3 or newer recommended; 8.2 security support ends 2026-12-31) in your hosting control panel, or ask your host for a vendor backport.';
    } elseif ($status === 'prerelease') {
        $r['reason'] = 'prerelease-unpatched';
        $r['remediation'] = 'Pre-release builds are not for production. Move this site to a stable, fixed release (for example 8.5.12 or later).';
        return $r;
    } else {
        $r['reason'] = 'below-fixed-version';
        $r['remediation'] = 'Upgrade to PHP ' . $r['fixed_version'] . ' or later (or switch this site to a fixed PHP version in your hosting control panel), then restart every PHP worker.' . $sunset;
    }
    if ($vendor_note !== '') {
        $r['reason'] .= ',vendor-may-backport';
        $r['remediation'] .= $vendor_note;
    }
    return $r;
}

// Returns the INI value as a string, false when the directive does not
// exist, or null when ini_get() is unavailable (disabled). PHP before 8
// returns NULL from disabled functions; PHP 8 removes them.
function p2s_ini($name)
{
    if (!function_exists('ini_get')) {
        return null;
    }
    $v = @ini_get($name);
    if ($v === false) {
        return false;
    }
    if (!is_string($v)) {
        return null;
    }
    return $v;
}

function p2s_bool($v)
{
    if (!is_string($v)) {
        return null;
    }
    $s = strtolower(trim($v));
    if ($s === '1' || $s === 'on' || $s === 'yes' || $s === 'true') {
        return true;
    }
    if ($s === '' || $s === '0' || $s === 'off' || $s === 'no' || $s === 'false' || $s === 'none') {
        return false;
    }
    if (is_numeric($s)) {
        return ((int) $s) !== 0;
    }
    return null;
}

// Names of flagged directives whose value for this request differs from
// php.ini (values are never reported, docs/SPEC.md section 5). Returns null
// when ini_get_all() is unavailable.
function p2s_overrides()
{
    if (!function_exists('ini_get_all')) {
        return null;
    }
    $all = @ini_get_all();
    if (!is_array($all)) {
        return null;
    }
    $out = array();
    foreach ($all as $name => $info) {
        if (!is_string($name) || !is_array($info) || !p2s_flagged_directive($name)) {
            continue;
        }
        $global = isset($info['global_value']) ? (string) $info['global_value'] : '';
        $local = isset($info['local_value']) ? (string) $info['local_value'] : '';
        if ($global !== $local) {
            $out[] = p2s_clean($name, 64);
        }
    }
    return $out;
}

// Printable ASCII only, truncated, so values can't break the output.
function p2s_clean($s, $max)
{
    $s = (string) $s;
    $out = '';
    $len = strlen($s);
    for ($i = 0; $i < $len && $i < $max; $i++) {
        $o = ord($s[$i]);
        $out .= ($o >= 32 && $o <= 126) ? $s[$i] : '?';
    }
    if ($len > $max) {
        $out .= '...';
    }
    return $out;
}

function p2s_clean_host($h)
{
    $h = (string) $h;
    $out = '';
    $len = strlen($h);
    for ($i = 0; $i < $len && $i < 253; $i++) {
        $c = $h[$i];
        $o = ord($c);
        if (($o >= 48 && $o <= 57) || ($o >= 65 && $o <= 90) || ($o >= 97 && $o <= 122)
            || $c === '.' || $c === '-' || $c === ':' || $c === '[' || $c === ']') {
            $out .= $c;
        }
    }
    return $out;
}

function p2s_finding($severity, $category, $title, $detail)
{
    return array(
        'severity' => $severity,
        'category' => $category,
        'title' => $title,
        'location' => 'this request',
        'count' => 1,
        'detail' => $detail,
    );
}

// Configuration context, docs/SPEC.md section 4. Never changes the verdict.
// Returns array(findings, coverage notes).
function p2s_config_findings($assess, $ini_ok)
{
    $f = array();
    $notes = array();
    if (!$ini_ok) {
        $notes[] = 'ini_get() is unavailable (probably disabled), so the patch fingerprint and INI settings could not be read.';
        return array($f, $notes);
    }
    $sev = ($assess['verdict'] === 'VULNERABLE') ? 'REVIEW' : 'INFO';

    $v = p2s_ini('session.upload_progress.enabled');
    if ($v === false) {
        $f[] = p2s_finding('INFO', 'config', 'Session upload progress is not available in this build',
            'The session extension is not loaded or this PHP version predates session.upload_progress (5.4).');
    } elseif (p2s_bool($v) === false) {
        $f[] = p2s_finding('INFO', 'config', 'session.upload_progress.enabled is Off',
            'This blocks the confirmed CVE-2026-109619 session path only. Updating PHP is the only complete fix.');
    } else {
        $f[] = p2s_finding($sev, 'config', 'session.upload_progress.enabled is On (CVE-2026-109619 session path)',
            'Interim only: set session.upload_progress.enabled=0 in php.ini, an FPM pool or server configuration (not ini_set() or .user.ini), then restart every PHP worker. This blocks the confirmed session path but not other variants.');
    }

    $v = p2s_ini('fatal_error_backtraces');
    if (is_string($v)) {
        if (p2s_bool($v) === false) {
            $f[] = p2s_finding('INFO', 'config', 'fatal_error_backtraces is Off',
                'This blocks the confirmed fatal-backtrace path of CVE-2026-109619 only.');
        } else {
            $f[] = p2s_finding($sev, 'config', 'fatal_error_backtraces is On (PHP 8.5 default; confirmed CVE-2026-109619 RCE producer)',
                'Interim only: set fatal_error_backtraces=0 administratively (php.ini, FPM pool or server configuration) and restart every PHP worker. This blocks the confirmed fatal-backtrace path only.');
        }
    }

    $v = p2s_ini('memory_limit');
    if (is_string($v)) {
        if (trim($v) === '-1') {
            $f[] = p2s_finding('INFO', 'config', 'memory_limit is -1 (no PHP memory limit)',
                'This removes the controllable memory-limit failure behind CVE-2026-109618, but an underlying allocation failure can still reach the bug. Not a complete mitigation.');
        } else {
            $f[] = p2s_finding($sev, 'config', 'memory_limit is ' . p2s_clean($v, 32) . ' (a finite limit makes the CVE-2026-109618 out-of-memory path controllable)',
                'Interim only: set memory_limit=-1 administratively (php_admin_value in the FPM pool or Apache configuration), check that no pool, directory or application setting restores a finite limit, and restart every worker. Do not use RLIMIT_AS or RLIMIT_DATA instead.');
        }
    }

    $names = array('post_max_size', 'upload_max_filesize', 'max_file_uploads', 'max_input_vars',
        'max_input_nesting_level', 'max_multipart_body_parts', 'file_uploads', 'enable_post_data_reading');
    $parts = array();
    foreach ($names as $n) {
        $x = p2s_ini($n);
        if (is_string($x)) {
            $parts[] = $n . '=' . p2s_clean($x, 32);
        }
    }
    if (count($parts) > 0) {
        $f[] = p2s_finding('INFO', 'config', 'Request body limits: ' . implode(', ', $parts),
            'The advisory suggests post_max_size=8M without uploads (32M with uploads), upload_max_filesize below post_max_size, a lower max_input_nesting_level, and frontend limits on body size, fields, parts, headers and nesting that also cover requests without a usable Content-Length.');
    }

    $ov = p2s_overrides();
    if ($ov === null) {
        $notes[] = 'ini_get_all() is unavailable, so per-request INI overrides could not be checked.';
    } else {
        if (count($ov) > 0) {
            $f[] = p2s_finding($sev, 'config', 'Per-request INI overrides of directives that can emit diagnostics before request initialization (CVE-2026-109619)',
                'Overridden for this request: ' . implode(', ', $ov) . '. Overrides come from .htaccess or php_value (mod_php), fastcgi_param PHP_VALUE/PHP_ADMIN_VALUE (FPM) or .user.ini; the first two apply before request initialization. Remove invalid or deprecated per-request settings. Hiding diagnostics with error_reporting, display_errors or @ does not help.');
        }
        $notes[] = 'Per-request INI overrides with invalid values are rejected by PHP and leave no trace that can be seen from inside PHP, yet they can still trigger CVE-2026-109619. Check .htaccess, php_value/php_admin_value and fastcgi_param PHP_VALUE/PHP_ADMIN_VALUE settings on the server, or ask your hosting provider.';
    }

    return array($f, $notes);
}

function p2s_build_report()
{
    $data = p2s_data();
    $ini_ok = is_string(p2s_ini('display_errors'));
    $fingerprint = null;
    if ($ini_ok) {
        $fingerprint = is_string(p2s_ini($data['fingerprint_ini']));
    }
    $raw_sapi = PHP_SAPI;
    $sapi = p2s_sapi($raw_sapi);
    $assess = p2s_assess(PHP_VERSION, $fingerprint, $data);
    $cfg = p2s_config_findings($assess, $ini_ok);
    $findings = $cfg[0];

    $is_root = false;
    if (function_exists('posix_geteuid')) {
        $uid = @posix_geteuid();
        if ($uid === 0) {
            $is_root = true;
            $findings[] = p2s_finding('REVIEW', 'config', 'PHP runs as root',
                'Remote code execution through these bugs would give an attacker full control of the server. Run PHP workers as an unprivileged user.');
        }
    }

    $coverage = array(
        'A web probe sees only the PHP build, server API and configuration that served this request (this site and this worker pool). Other PHP versions, pools, sites and command-line binaries on the server are not visible.',
        'Not checked from the web: running processes and restart state, package changelogs and vendor backports, logs and signs of compromise. Run php2shell-check.sh on the server, or ask your hosting provider.',
        'The verdict reflects the worker that answered this request. Other workers can run older code until every PHP worker has been restarted.',
        'Because of these limits the summary is never FIXED and exit bit 2 (incomplete) is always set, even when this PHP build is fixed.',
    );
    foreach ($cfg[1] as $n) {
        $coverage[] = $n;
    }

    $installation = array(
        'scope' => 'web',
        'path' => '',
        'sapi' => $sapi,
        'sapi_raw' => p2s_clean($raw_sapi, 32),
        'version' => p2s_clean(PHP_VERSION, 64),
        'branch' => $assess['branch'],
        'branch_status' => $assess['branch_status'],
        'fixed_version' => $assess['fixed_version'],
        'patch_fingerprint' => $fingerprint,
        'package' => array('manager' => 'none', 'name' => '', 'version' => '', 'origin' => 'unknown (web probe)'),
        'evidence' => $assess['evidence'],
        'verdict' => $assess['verdict'],
        'reason' => $assess['reason'],
        'remediation' => $assess['remediation'],
        // The worker that answered runs this very build.
        'running' => array(
            'processes' => 1,
            'restart_required' => false,
            'version' => p2s_clean(PHP_VERSION, 64),
            'verdict' => $assess['verdict'],
        ),
        'exposure' => p2s_exposure($sapi),
    );

    return array(
        'tool' => 'php2shell-check',
        'tool_version' => P2S_TOOL_VERSION,
        'checker' => 'probe',
        'data_version' => $data['data_version'],
        'scanned_at' => (string) @gmdate('Y-m-d\TH:i:s\Z'),
        'host' => array(
            'hostname' => p2s_clean_host(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : ''),
            'platform' => 'web',
            'os' => p2s_clean(PHP_OS, 32),
            'is_root' => $is_root,
        ),
        'cves' => $data['cves'],
        // No compromise-triage window: the probe reads no logs or files.
        'since' => null,
        'summary' => array(),
        'installations' => array($installation),
        'findings' => $findings,
        'coverage' => $coverage,
        'probe' => array('file' => basename(__FILE__), 'self_delete' => 'pending', 'ini_available' => $ini_ok),
    );
}

// summary block and exit-code bits, docs/SPEC.md sections 6 and 7. A web
// probe cannot see other PHP versions, processes, restarts or logs, so its
// coverage is always limited: exit bit 2 is always set and the summary is
// INCOMPLETE unless the PHP that answered is VULNERABLE. It is never FIXED,
// even when this installation's own verdict is.
function p2s_summary($report)
{
    $inst = $report['installations'][0];
    $vuln = ($inst['verdict'] === 'VULNERABLE') ? 1 : 0;
    $fixed = ($inst['verdict'] === 'FIXED') ? 1 : 0;
    $unknown = ($inst['verdict'] === 'UNKNOWN') ? 1 : 0;
    $limited = 1;
    $high = 0;
    $review = 0;
    foreach ($report['findings'] as $f) {
        if ($f['severity'] === 'HIGH') {
            $high++;
        } elseif ($f['severity'] === 'REVIEW') {
            $review++;
        }
    }
    $exit = 0;
    if ($vuln) {
        $exit |= 1;
    }
    if ($unknown || $limited) {
        $exit |= 2;
    }
    if ($high > 0) {
        $exit |= 4;
    }
    $verdict = $vuln ? 'VULNERABLE' : 'INCOMPLETE';
    return array(
        'verdict' => $verdict,
        'installations' => 1,
        'vulnerable' => $vuln,
        'fixed' => $fixed,
        'unknown' => $unknown,
        'restart_required' => 0,
        'high_findings' => $high,
        'review_findings' => $review,
        'exit_code' => $exit,
    );
}

// Minimal JSON encoder: no dependency on ext/json, ASCII-only output.
function p2s_json_string($s)
{
    $s = (string) $s;
    $out = '"';
    $len = strlen($s);
    for ($i = 0; $i < $len; $i++) {
        $c = $s[$i];
        $o = ord($c);
        if ($c === '"') {
            $out .= '\\"';
        } elseif ($c === '\\') {
            $out .= '\\\\';
        } elseif ($o === 10) {
            $out .= '\\n';
        } elseif ($o === 13) {
            $out .= '\\r';
        } elseif ($o === 9) {
            $out .= '\\t';
        } elseif ($o < 32 || $o > 126) {
            $out .= sprintf('\\u%04x', $o);
        } else {
            $out .= $c;
        }
    }
    return $out . '"';
}

function p2s_json($v, $indent)
{
    if ($v === null) {
        return 'null';
    }
    if ($v === true) {
        return 'true';
    }
    if ($v === false) {
        return 'false';
    }
    if (is_int($v)) {
        return (string) $v;
    }
    if (!is_array($v)) {
        return p2s_json_string($v);
    }
    $is_list = true;
    $expect = 0;
    foreach ($v as $k => $unused) {
        if ($k !== $expect) {
            $is_list = false;
            break;
        }
        $expect++;
    }
    if (count($v) === 0) {
        return $is_list ? '[]' : '{}';
    }
    $next = $indent . '  ';
    $items = array();
    if ($is_list) {
        foreach ($v as $item) {
            $items[] = $next . p2s_json($item, $next);
        }
        return "[\n" . implode(",\n", $items) . "\n" . $indent . ']';
    }
    foreach ($v as $k => $item) {
        $items[] = $next . p2s_json_string((string) $k) . ': ' . p2s_json($item, $next);
    }
    return "{\n" . implode(",\n", $items) . "\n" . $indent . '}';
}

function p2s_text($r)
{
    $i = $r['installations'][0];
    $fp = 'unavailable';
    if ($i['patch_fingerprint'] === true) {
        $fp = 'present';
    } elseif ($i['patch_fingerprint'] === false) {
        $fp = 'absent';
    }
    $branch = 'unknown';
    if ($i['branch'] !== '') {
        $branch = $i['branch'] . ' (' . $i['branch_status'] . ')';
        if ($i['fixed_version'] !== '') {
            $branch .= ', fixed in ' . $i['fixed_version'];
        }
    }
    $lines = array();
    $lines[] = 'php2shell-check web probe ' . $r['tool_version'] . ' (data ' . $r['data_version'] . ')';
    $lines[] = 'PHP2Shell: ' . implode(' / ', $r['cves']);
    $lines[] = '';
    $lines[] = 'Verdict: ' . $i['verdict'] . '   (summary ' . $r['summary']['verdict'] . ', exit code ' . $r['summary']['exit_code'] . ')';
    if ($r['summary']['verdict'] === 'INCOMPLETE') {
        $lines[] = '  The summary is INCOMPLETE because a web probe cannot see the rest of the server (see Scope and limits).';
    }
    $lines[] = '  PHP version       : ' . $i['version'];
    $lines[] = '  Server API        : ' . $i['sapi'] . ' (' . $i['sapi_raw'] . '), exposure ' . $i['exposure'];
    $lines[] = '  Branch            : ' . $branch;
    $lines[] = '  Patch fingerprint : ' . $fp . ' (memory_hard_limit_percent INI entry)';
    $lines[] = '  Evidence          : ' . $i['evidence'];
    $lines[] = '  Reason            : ' . $i['reason'];
    $lines[] = '  What to do        : ' . $i['remediation'];
    $lines[] = '';
    $lines[] = 'Findings (configuration context; they do not change the verdict, and interim settings are partial):';
    if (count($r['findings']) === 0) {
        $lines[] = '  (none)';
    }
    foreach ($r['findings'] as $f) {
        $lines[] = '  [' . $f['severity'] . '] ' . $f['title'];
        $lines[] = '      ' . $f['detail'];
    }
    $lines[] = '';
    $lines[] = 'Scope and limits:';
    foreach ($r['coverage'] as $c) {
        $lines[] = '  - ' . $c;
    }
    $lines[] = '';
    $lines[] = 'Self-delete: ' . $r['probe']['self_delete'] . ' (' . $r['probe']['file'] . ')';
    return implode("\n", $lines) . "\n";
}

function p2s_headers($type, $status)
{
    if (!function_exists('header') || !function_exists('headers_sent') || headers_sent()) {
        return;
    }
    if ($status === 403) {
        @header('HTTP/1.1 403 Forbidden', true, 403);
    }
    @header('Content-Type: ' . $type . '; charset=utf-8');
    @header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    @header('Pragma: no-cache');
    @header('Expires: 0');
    @header('X-Robots-Tag: noindex, nofollow');
    @header('X-Content-Type-Options: nosniff');
    @header('Referrer-Policy: no-referrer');
}

// The token from the X-Probe-Token request header, or else from ?token=.
// The header keeps the token out of access logs and browser history, and
// out of the link previews that chat apps fetch (a fetched link with the
// token would run the probe and delete it). When the header is sent, the
// query string is not looked at.
function p2s_given_token()
{
    if (isset($_SERVER['HTTP_X_PROBE_TOKEN']) && is_string($_SERVER['HTTP_X_PROBE_TOKEN'])) {
        $h = trim($_SERVER['HTTP_X_PROBE_TOKEN'], " \t");
        if ($h !== '') {
            return $h;
        }
    }
    if (isset($_GET['token']) && is_string($_GET['token'])) {
        return $_GET['token'];
    }
    return null;
}

// Constant-time comparison (hash_equals needs PHP 5.6).
function p2s_equals($known, $given)
{
    if (!is_string($known) || !is_string($given) || $known === '') {
        return false;
    }
    $klen = strlen($known);
    $glen = strlen($given);
    $diff = $klen ^ $glen;
    for ($i = 0; $i < $glen; $i++) {
        $diff |= ord($known[$i % $klen]) ^ ord($given[$i]);
    }
    return $diff === 0;
}

function p2s_main()
{
    // Swallow stray warnings (display_errors may be On on shared hosting)
    // so they can't corrupt the report.
    $level = function_exists('ob_get_level') ? ob_get_level() : 0;
    if (function_exists('ob_start')) {
        @ob_start();
    }

    $given = p2s_given_token();
    $token = PROBE_TOKEN;
    $authorized = is_string($token) && $token !== P2S_TOKEN_PLACEHOLDER
        && strlen($token) >= 16 && p2s_equals($token, $given);

    if (!$authorized) {
        p2s_discard($level);
        p2s_headers('text/plain', 403);
        echo "Forbidden\n";
        return;
    }

    $json = isset($_GET['format']) && $_GET['format'] === 'json';
    $keep = isset($_GET['keep']) && $_GET['keep'] === '1';

    $report = p2s_build_report();

    if ($keep) {
        $report['probe']['self_delete'] = 'skipped (keep=1)';
    } elseif (function_exists('unlink') && @unlink(__FILE__) === true) {
        $report['probe']['self_delete'] = 'deleted';
    } elseif (p2s_gone(__FILE__)) {
        // An overlapping request deleted it first.
        $report['probe']['self_delete'] = 'deleted';
    } else {
        $report['probe']['self_delete'] = 'failed';
        $report['findings'][] = p2s_finding('REVIEW', 'probe', 'The probe could not delete itself',
            'Delete ' . basename(__FILE__) . ' from the web root now.');
    }
    $report['summary'] = p2s_summary($report);

    p2s_discard($level);
    if ($json) {
        p2s_headers('application/json', 200);
        echo p2s_json($report, '') . "\n";
    } else {
        p2s_headers('text/plain', 200);
        echo p2s_text($report);
    }
}

// True when the file is no longer there. Trusted only while its directory is
// still visible, so that open_basedir or a disabled function can't make a
// failed delete look done.
function p2s_gone($file)
{
    if (!function_exists('file_exists') || !function_exists('is_dir') || !function_exists('dirname')) {
        return false;
    }
    if (function_exists('clearstatcache')) {
        @clearstatcache();
    }
    return @is_dir(dirname($file)) === true && @file_exists($file) === false;
}

function p2s_discard($level)
{
    if (!function_exists('ob_get_level') || !function_exists('ob_end_clean')) {
        return;
    }
    while (ob_get_level() > $level) {
        if (!@ob_end_clean()) {
            break;
        }
    }
}

p2s_main();
