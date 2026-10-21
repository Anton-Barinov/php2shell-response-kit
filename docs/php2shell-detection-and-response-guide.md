# php2shell: detection and response guide

2026-10-21 · ORBITRON

CVE-2026-109618 and CVE-2026-109619 (php2shell, CVSS v4.0 9.2) are a state-corruption bug that occurs when PHP runs out of memory while parsing a request — before any application code runs. Fixed in **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**. Until you patch, detection and response teams should watch the log signatures below. Key principle: **each of these signatures is an *attempt* indicator; on its own it proves neither that a host is unpatched nor that exploitation succeeded** — evaluate it together with request context, process telemetry and the effective package version.

## Scope and verification limits

Every finding here was produced in an isolated lab, from PHP's **own official source** (unpatched and patched builds) and PHP's **own published regression tests**. No request was sent to any production system and no exploit chain was built.

- **Confirmed:** patched versions 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (php.net). Single fix commit: *"Avoid state corruption via bailout"* (GHSA-w8hw-w9fx-j79w / CVE-2026-109618, GHSA-6wmf-4rv5-p3rp / CVE-2026-109619).
- **Proven in the lab:** the **precondition** of the bug — out-of-memory while parsing a request, the per-SAPI consequences, and the upload-progress handler running before RINIT. These behaviours were shown to be fixed by the patch via the regression tests.
- **NOT proven in the lab:** the full memory-corruption → RCE chain (heap grooming, pointer hijack) was deliberately not built. The RCE impact is reported by third parties; we verified only the condition the bug needs to occur.
- **Unverified claims:** statements such as "affected since PHP 5.4" and "RCE proven on WordPress/Drupal etc." are outside this work's scope. php.net released fixes only for 8.2–8.5; 8.1 and earlier are EOL with no upstream fix, but exactly which older versions are affected has not been independently confirmed here.
- **mod_php is the highest-risk setup** (php.net): a persistent worker can carry the corrupted state into the next request on the same process (CVE-2026-109619). PHP-FPM is also affected by CVE-2026-109618.

## How the bug works

PHP parses the request body (POST, multipart, uploads) **before any application code runs**. The chain:

1. **Entry:** the attacker sends a body whose parsing costs far more memory than its size — hundreds of thousands of headers in one part, huge field names, or a body that does not match `Content-Length` (in the unpatched version `post_max_size` could be bypassed on some paths, GHSA-2cv3).
2. **Corruption (CVE-2026-109618):** when `memory_limit` is hit, unpatched PHP does a `zend_bailout()` — a **`longjmp` out of the middle of running C code**. Half-built structures stay referenced in memory; the cleanup that follows walks over that invalid data as if it were valid.
3. **Stale state (CVE-2026-109619):** if the start-up failure happens before RINIT, extension RSHUTDOWNs are skipped (`modules_activated=0`); globals such as session state are neither set up nor torn down, and keep pointing at freed memory.

The patch closes this: OOM no longer jumps, it is queued as a "delayed OOM" (`EG(delayed_oom)`) and raised at a safe point; the parsers gain `ZEND_HAS_OOM()` checks; the upload-progress deserialize runs in **incomplete-classes-only** mode (no class resolution, no user code); and `php_request_shutdown()` resets all global state.

**For detection the most important point is the SAPI difference** — the same OOM leaves a different trace depending on the worker type:

| SAPI | On OOM during start-up | Observed trace in the lab | Carried to next request |
| --- | --- | --- | --- |
| **PHP-FPM** | Worker ends itself (`FPM_EXIT_SOFTWARE`) | FPM master log: `child <PID> exited with code 70` + `PHP message: ... in Unknown on line 0` | No (worker dies) |
| **mod_php (Apache)** | Request returns 500, process keeps living | Apache error_log: `Allowed memory size ... in Unknown on line 0` | **Yes** — corrupted state can carry into the next request on the same process |
| **CGI (process per request)** | Process dies | `in Unknown on line 0` | No |

Verified in the lab with a single-worker mod_php: the **same PID served the request before and after** the OOM. On FPM the worker closed with `code 70` on every failed start-up — this is **not** a SIGSEGV crash and is treated as a separate signature below.

## Lab verification

Unpatched and patched builds were compiled with debug + AddressSanitizer; PHP's new regression tests were run on both.

**Proof matrix** (PHP's own tests; 8.3.35 unpatched, 8.3.36 patched):

| Test | Unpatched | Patched | What it shows |
| --- | --- | --- | --- |
| Official regression tests (total) | 5 of 27 fail | 27/27 pass | Scope of the fix |
| Multipart `post_max_size` bypass (GHSA-2cv3) | FAIL — whole body ends up in `$_POST` | PASS — warning + data dropped | Controlled-OOM entry primitive |
| 600,000 repeated part headers (GHSA-f883 007) | FAIL — unbounded accumulation → OOM | PASS — only 2 headers kept | Memory-exhaustion vector |
| Upload-progress, missing script (`rfc1867_no_user_code`) | FAIL — classes resolve, `$_SESSION` left behind | PASS — no code runs, no trace | Pre-RINIT code execution |
| Invalid SID + upload-progress (`rfc1867_sid_invalid`) | FAIL — write attempted after read failed | PASS — nothing written | Source of the A4 signature (below) |

**Mitigation matrix** — which interim setting actually stops the OOM (unpatched 8.3.35 php-cgi, with PHP's own test body):

| Setting | Result |
| --- | --- |
| Default (memory_limit=128M) | OOM — `in Unknown on line 0` |
| `post_max_size=8M` alone | OOM (does not stop it) |
| `session.upload_progress.enabled=0` alone | OOM (does not stop it) |
| `session.use_strict_mode=1` alone | OOM (does not stop it) |
| `memory_limit=-1` | Completes (~218M peak) |
| Patched 8.3.36, default | Completes (~2M peak) |

The only setting that stops it on its own is **`memory_limit=-1`** — but that introduces a **DoS risk** (a few-MB request can cost hundreds of MB), so it must be paired with a cgroup/container memory limit. Note: these figures are from debug + ASan builds; release builds account memory differently, but Ubuntu's normal 8.3.6 mod_php also exhausted 128M on the same test body.

## Where the logs live

The paths below are common examples; they vary by distro, install method, container and vhost config. **Confirm the real path from the running service's configuration.**

| Install / source | Records to collect | For what |
| --- | --- | --- |
| Rocky / RHEL / Alma — Apache | `/var/log/httpd/error_log`, `/var/log/httpd/access_log`; vhost logs | PHP/Apache errors + related requests |
| Ubuntu / Debian — Apache | `/var/log/apache2/error.log`, `access.log`; vhost logs | Same; `ErrorLog`/`CustomLog` decide |
| nginx | `/var/log/nginx/error.log`, `access.log` | FastCGI/upstream errors, 5xx, request context |
| Rocky/RHEL — PHP-FPM | `/var/log/php-fpm/error.log` + pool PHP error file (e.g. `www-error.log`) | FPM process events + PHP fatal/warning |
| Ubuntu/Debian — PHP-FPM | `/var/log/php8.4-fpm.log` (name varies by version) + pool error file | Worker exits + PHP errors |
| systemd | `journalctl -u php\*-fpm\* -u httpd -u apache2 -u nginx` | Service errors, restarts, journal output |
| Container / Kubernetes | Container stdout/stderr + separate in-container log files | PHP/FPM/web logs with pod/container/node info |
| WAF / reverse proxy | Security events, rule matches, body-inspection errors | Multipart anomalies, blocking |
| Endpoint | EDR events; auditd `/var/log/audit/audit.log` if configured | Process/file/network activity from PHP/web workers |

**Important distinction:** FPM's own `error_log` and PHP's `error_log` manage **different** records. Collecting only one misses the other. Collecting the nginx access log is not the same as collecting the PHP error log.

**Finding the real path:**

- **Apache:** `ErrorLog` / `CustomLog` in the active server and vhost config.
- **nginx:** `error_log` / `access_log` in the active `http`/`server`/`location` blocks.
- **FPM:** `error_log` in `php-fpm.conf`; `php_admin_value[error_log]`, `php_admin_flag[log_errors]`, `access.log` in pool files.
- **PHP:** the php.ini loaded by the SAPI that serves the request. Do **not** assume `php --ini` on the CLI matches the web SAPI.

**Prerequisite:** `log_errors=On` and `error_log` defined. On FPM, `catch_workers_output=yes` is recommended so worker stdout/stderr reaches the main log. Fatals are logged even with `display_errors=Off`.

## Trigger signatures with log examples

The raw log lines below were produced by firing the real vector against an unpatched 8.3.x FPM and mod_php lab. Each signature is an **attempt** indicator.

### A1 — Main trigger: OOM while parsing the request (CVE-2026-109618)

FPM (stderr forwarded to the main log):
```
WARNING: [pool www] child 849 said into stderr: "NOTICE: PHP message: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted ... in Unknown on line 0"
```
mod_php (Apache error_log):
```
[php:error] [pid 587] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
```
Regex:
```
Allowed memory size of [0-9]+ bytes exhausted .* in Unknown on line 0
```
**Why it matters:** `in Unknown on line 0` means the error belongs to **request parse/startup**, not an application script. A normal application OOM logs `.../foo.php on line 42`. A series from the same IP with growing part count/size = calibration behaviour.

### A2 — Upload-progress vector is engaged (CVE-2026-109619 path)
```
PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters ... in Unknown on line 0
```
The `PHP Request Startup:` prefix shows the warning came from the upload-progress handler before RINIT, not from inside a script. Normal `session_start()` warnings do not carry this prefix. **Caution:** this line appears on patched versions too (it is a trace of the attempt, not version-specific). If your app does not use upload progress, it is HIGH on its own.

### A3 — Session read failure (same chain as A2)
```
PHP Warning:  PHP Request Startup: Failed to read session data: files (path: /var/lib/php/sessions) in Unknown on line 0
```
Also not patched/unpatched discriminating; shows the vector is being tried.

### A4 — Stale-state write attempt (interpret carefully)
```
PHP Warning:  PHP Request Startup: Failed to write session data (files) ... in Unknown on line 0
```
This line is **not** produced on patched versions (confirmed via the test diff): unpatched PHP attempts the write even after the read failed. **But a critical limitation:** this line only appears when the **write also fails** (invalid SID or an unwritable `save_path`). On a real server with a writable `save_path` and a **valid** attacker-chosen SID, the unpatched version writes the stale state **silently and successfully — the A4 line never appears.** So A4 is **one-directional**: (a) unreliable for attack detection — it never appears in the real flow (valid SID + writable save_path); (b) as a version indicator it is meaningful in one direction only — its **presence** means a vulnerable version + a broken write path, its **absence proves nothing**; (c) it is not for inventory/patch verification. Use the package version/changelog for inventory and patch verification.

### A5 — Content-Length / limit bypass attempts
```
POST Content-Length of [0-9]+ bytes exceeds the limit of [0-9]+ bytes
Actual POST length does not match Content-Length, and exceeds [0-9]+ bytes
```
Large POSTs with a lying Content-Length — the entry primitive of the controlled-OOM trigger (GHSA-2cv3). If the WAF can compare "bytes received ≠ Content-Length," it is caught there too.

### A6 — WAF / body inspection (a rule, not a log)

In the multipart body, if the app does not legitimately use them, look for:

- a `name="PHP_SESSION_UPLOAD_PROGRESS"` form field
- a `name="PHPSESSID"` SID supplied in the body
- megabytes of repeated `Content-Disposition` / `Content-Type` headers; hundreds of thousands of headers in one part; `Content-Length: 0` with a large body

## Compromise indicators

This group is seen if exploitation **has progressed**. One important distinction:

- **FPM `exited with code 70`** — the normal trace of an OOM during start-up; the worker exits cleanly. Seen on every failed start-up in the lab. This is **not** a crash (SIGSEGV) but it is the most common observable of the OOM trigger on FPM. Correlate with A1.
- **SIGSEGV / SIGABRT** — expected only when an actual memory-corruption trigger fires (requires grooming). Seeing it is a more serious signal than A1.

| Where | What to look for |
| --- | --- |
| FPM master log | `child [0-9]+ exited with code 70` (OOM-startup) · `exited on signal 11 (SIGSEGV)` · `exited on signal 6 (SIGABRT)` · short-interval worker respawn clusters |
| Apache error log | `seg fault or similar nasty error detected in the child` · `child pid [0-9]+ exit signal Segmentation fault \(11\)` |
| nginx error log | `upstream prematurely closed connection` · `recv\(\) failed` + 502 bursts in the access log |
| Apache + FPM | `AH01071: Got error 'PHP message: ...'` (PHP message carried into the Apache log) |
| Access log (correlation) | multipart POST from the same IP → immediately 500/502/503 → the same IP continues |
| Session directory | `sess_` files the app would never create; `upload_progress_` keys inside them |
| HTTP responses | abnormally long / odd-character `Set-Cookie: PHPSESSID=...` — a possible trace of the memory-disclosure vector |

**Note:** a successful **silent** exploitation (pure memory disclosure) may produce no logs at all. So the B group and response-size anomalies should be watched together. The `Set-Cookie` and response-size traces rely on reported vectors; since we did not produce memory disclosure in our lab, treat them as *reported* (unverified) signals.

## Traffic and access-log footprint

The attack can look "normal" on the surface; scanning status codes alone is not enough. The patterns here were measured in the ORBITRON lab; the access-log hole and the code-70 behaviour were re-confirmed for this guide.

- **Behaviour, not status:** a code-executing multipart POST still returns `status=200`; a large multipart POST to a non-existent endpoint (`404`) is also anomalous. What to look for in the access log is not whether the URI exists but the **large / many-part multipart POST** behaviour.
- **⭐ Access-log hole (confirmed):** a request that dies *during request start-up* (while parsing) is **never written to the FPM access log**, yet it leaves a trace in the error log. In the lab the normal request was logged; the OOM-triggering request was not, and the worker closed with `exited with code 70`. **Correlation rule:** if an `Allowed memory size ... in Unknown on line 0` (or `exited with code 70`) line in the error log has no matching access-log entry for the same time/pool, that request died at start-up = a php2shell-style trigger attempt (even on a patched version).
- **Calibration pattern:** exploitation probes with gradually growing bodies to break the limit at the desired point. A **monotonically growing `bytes_in` series** to the same URI (≥4-5 requests) with **super-linear `dur`** (upload-progress re-encodes the session on every part, so ~O(n²)) = calibration plus a CPU/DoS side effect. MEDIUM on its own; CRITICAL together with the error-log signatures.
- **Traffic volume (estimate):** in the lab with a low `memory_limit` the trigger fires with a few hundred KB of body; at a production 128M limit this grows roughly by tens of times (~9-18 MB range). But amplification levers such as long field/file names keep the body small while exhausting large amounts of memory, so a volume threshold cannot be a rule on its own — use it with the pattern.
- **Disk artifacts:** even when the app never calls `session_start()`, an upload-progress attack causes `sess_*` writes / mtime churn in the session directory; on an endpoint that uses no sessions this is a strong anomaly. Also unexpected new files owned by the php-fpm/www-data user (see post-exploitation). Note: the engine being able to **write a file** with the worker identity before RINIT was shown in the lab only with `opcache.preload` plus a gadget class seeded into the session (server-side collaboration); an external attacker cannot set that up alone. So treat worker-uid-owned new files as a post-exploitation hunting signal, not as general proof of RCE.

## Post-exploitation hunting

If code execution happened, you see unexpected process, file and network activity as the PHP worker user (www-data / apache / php-fpm).

- **auditd (process):** watch `execve` by the web worker user's `euid`:
```
auditctl -a always,exit -F arch=b64 -S execve -F euid=48 -k php2shell_rce
```
`/bin/sh`, `/bin/bash`, `curl`, `wget`, `base64`, `perl`, `python` launches (euid = apache is usually 48, www-data 33).
- **Filesystem:** new files in `/tmp`, `/dev/shm`, upload directories and the web root — especially new `.php` (webshell) and oddly named script files.
- **Persistence:** crontab entries, SSH `authorized_keys`, systemd user units owned by the web worker user.
- **Network:** unexpected outbound connections from the PHP worker (reverse shell, C2, data exfiltration).

Compare this activity against change records and the application's normal behaviour; apps that legitimately use `exec()` (image/PDF tools, backups, deploy hooks) produce false positives.

## Correlation and alerting

The PHP error line **may not contain** a source IP; correlate the IP from the HTTP access/WAF record. Do not derive an exact match from a close timestamp alone; behind a proxy, take the real client IP from the trusted proxy chain. Where possible correlate on request ID and worker PID (adding pool name + child PID to the FPM access log helps).

| Alert | Condition | Confidence / action |
| --- | --- | --- |
| CRITICAL | same source IP && A1 ≥ 3 times && < 10 min | Calibration / active attempt → start IR |
| CRITICAL | multipart POST (A6) → then 5xx / worker respawn → IP continues | Possibly partial success → IR |
| HIGH | A2 or A3 (alone, if the app does not use upload progress) | Upload-progress vector triggered |
| HIGH | C group (execve/webshell from the worker) not the app's known behaviour | Post-exploitation → IR |
| MEDIUM | A1 + FPM `code 70` (same pool/time) | OOM trigger took down an FPM worker |
| MEDIUM | B-group crash signals, if no known app crash cause | Possible memory corruption |
| CRITICAL | `Allowed memory size ... in Unknown on line 0` **present** in the error log && **no** matching access-log entry for the same time | Request died at start-up = trigger attempt (access-log hole) |
| MEDIUM | ≥4 monotonically growing `bytes_in` to the same URI && super-linear `dur` | Calibration — CRITICAL together with the error-log signatures |

**Example correlation chain:** unusual multipart request → A1/A2 in the same server/pool and time window → worker exit (code 70) or 5xx → repeated similar requests. Add an unexpected command/file/connection from the worker and suspicion strengthens.

**Duplicate-event caution:** the same error can arrive from both the FPM and the Apache log; do not count two sources as one event and falsely trip the "3 attempts" threshold.

## Ready queries and ORBITRON rules

Greps for quick triage:
```
# A1: main trigger (FPM + Apache error log)
grep -E "Allowed memory size of [0-9]+ bytes exhausted .*in Unknown on line 0" \
  /var/log/*fpm*.log /var/log/httpd/*error* /var/log/apache2/*error*

# A2-A4: request-startup session signatures
grep -F "PHP Request Startup:" /var/log/*fpm*.log /var/log/httpd/*error*

# FPM worker: OOM-startup (code 70) and a real crash (signal)
grep -E "exited with code 70|exited on signal (11|6)" /var/log/*fpm*.log

# Apache + FPM wrapper
journalctl -u httpd --since today | grep "AH01071" | grep -E "Allowed memory|Request Startup"

# Behaviour in the access log: multipart POST + 5xx
awk '$6=="\"POST" && $9~/^50[0-9]$/' /var/log/nginx/access.log
```

Mapping to the ORBITRON php2shell-response-kit (public repo):

| Signal | Rule |
| --- | --- |
| A1 (OOM, in Unknown on line 0) | Sigma `php2shell_php_oom_during_request_parsing` · Wazuh 109627 |
| OOM + then a worker crash (2 min) | Wazuh 109628 |
| Repeated OOM (5/5 min) | Wazuh 109629 |
| FPM worker exited with code 70 (OOM-startup) | Sigma `php2shell_php_fpm_worker_exit_code70` · Wazuh 109630 |
| Code 70 within 2 min of an OOM-during-parsing | Wazuh 109631 |
| Worker crash (SIGSEGV/SIGABRT) | Sigma `php2shell_php_worker_crash` · Wazuh 109625/109626 |
| A6 multipart header flood / body error | ModSecurity 9109622 / 9109623 |
| Upload-progress field | ModSecurity 9109618/19/21 |
| C group (webserver → shell/webshell) | Sigma spawns_shell / file_written_to_webroot · Wazuh 109610–109621 · YARA |

All SIEM/EDR queries are generated with pySigma and are untested on live platforms; the scripts, YARA and ModSecurity rules were lab-tested. Baseline 1–2 hours before alerting.

**Correlation limitation:** the repository rules Wazuh 109628 and 109631 tie the OOM and the later event by a **time window, not by worker PID**. Do not report their matches as "OOM confirmed on this exact worker" — exact process attribution needs PID/pool correlation you add on your platform. The priority recommendations in this guide do not change the existing rule levels.

## Interim mitigations, patch verification and sources

**Priority:** apply your distribution's package that fixes both CVEs (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or a vendor backport), restart the relevant services and **long-lived workers**. Verify the running processes use the patched version. Do patch verification via the package record, the vendor advisory and the running process — log signatures such as A4 are not reliable for this.

The interim mitigations' **effect on monitoring** (no alert does not mean safe):

| Mitigation | Effect on detection |
| --- | --- |
| `session.upload_progress.enabled=Off` | A2/A3/A4 disappear (vector closes); A1/A5/B remain |
| `memory_limit=-1` (+ cgroup) | A1 not produced; the underlying allocation failure can still be hit at the cgroup limit — keep watching the B group |
| Lower `post_max_size` (8M/32M) | A5 fires more often (you gain visibility) |
| Web-server allow-list (only existing, used `.php`) | the non-existent-script vector closes; A1 drops |
| `fatal_error_backtraces=Off` (8.5 only) | closes one UAF surface |

**Visibility gaps:** `log_errors` must be on and the error level must include the relevant messages; `display_errors=Off` does not turn logging off. Standard access logs do not contain the multipart body — seeing the `PHP_SESSION_UPLOAD_PROGRESS` field needs WAF/body inspection. Interim mitigations can stop some logs from being produced; take a before/after baseline.

**Sources:**

- PHP security releases 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (21 Oct 2026): [php.net/archive/2026](https://www.php.net/archive/2026.php)
- Fix commit "Avoid state corruption via bailout" (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp): [github.com/php/php-src](https://github.com/php/php-src/commit/3c832b523ee13b1a010177d2ff84aea18be0015e)
- ORBITRON php2shell-response-kit (inventory scripts + rules): [github.com/orbitron-ai/php2shell-response-kit](https://github.com/orbitron-ai/php2shell-response-kit)

The lab verification was done by ORBITRON on 21 Oct 2026 in an isolated environment, using unpatched/patched builds compiled from PHP's official source and PHP's official regression tests. No exploit chain was built and nothing was triggered on production systems.
