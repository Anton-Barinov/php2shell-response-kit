# Changelog

## v1.0.0 — 2026-10-21 10:30 TRT (07:30 UTC) — pre-disclosure
* Initial release before the official PHP advisory (scheduled 14:00 UTC).
* Linux and Windows read-only inventory scripts (PHP runtimes, SAPIs, effective `session.upload_progress.*`, overrides, package/backport status).
* Sigma sources + generated Splunk, QRadar, CrowdStrike Falcon (LogScale), SentinelOne (DV/PQ) queries — untested on live platforms.
* Wazuh rules (auditd, FIM, Sysmon, crash logs), YARA hunting rules, ModSecurity rules (lab-tested).
* Workaround status: `session.upload_progress.enabled=0` = partial mitigation only (per Flatt Security update).

## v1.3.6 — 2026-10-21
* docs (EN + TR): sharpened the A4 signature to its agreed one-directional framing — unreliable for attack
  detection (invisible in the real valid-SID / writable-save_path flow), meaningful as a version indicator
  only in one direction (presence => vulnerable + broken write path; absence proves nothing), and not for
  inventory/patch verification (use the package changelog).

## v1.3.5 — 2026-10-21
* docs (EN + TR): added a "traffic and access-log footprint" section — the access-log hole (a request that
  dies at request start-up leaves an error-log line but no access-log entry; lab-re-confirmed with
  `exited with code 70` and no access line), the calibration pattern (growing bytes_in + super-linear dur
  from the O(n^2) upload-progress re-encode), traffic-volume estimates and disk artifacts. Added two
  correlation rules (access-log hole, calibration). The pre-RINIT file-write is noted as preload-dependent
  (not externally reachable), so worker-uid files are framed as a post-exploitation signal, not proof of RCE.

## v1.3.4 — 2026-10-21
* Added a detailed detection & response field guide (EN + TR) under `docs/`, linked from the README:
  root cause, SAPI differences, lab verification matrix, trigger signatures with real log examples,
  compromise indicators (incl. FPM code 70), correlation logic and the rule mapping.

## v1.3.3 — 2026-10-21
* **New rule (lab finding):** on PHP-FPM an out-of-memory during request start-up does not crash the worker
  with a signal — the worker exits cleanly with **code 70** (FPM_EXIT_SOFTWARE). This is the most common
  observable of the php2shell trigger on FPM and the signal-based crash rule (109625) does not catch it.
  Added Sigma `php2shell_php_fpm_worker_exit_code70` (+ Splunk, QRadar payload, CrowdStrike), Wazuh 109630
  (code 70) and 109631 (code 70 within 2 min of an out-of-memory during parsing = OOM trigger confirmed).

## v1.3.2 — 2026-10-21
* README (EN/TR): **correction** — the pre-disclosure lab note "a non-existent `.php` path does not trigger it"
  applies to mod_php / built-in server only. Lab test: unpatched PHP-FPM parses the request body (upload
  progress, out-of-memory) even for a missing script, so `/random.php` reaches PHP behind Apache
  `SetHandler proxy:fcgi` or nginx `fastcgi_pass` without `try_files`. Added the web-server allow-list
  mitigation (existing + intended entry points only, body limits, GET/HEAD-only where possible).

## v1.3.1 — 2026-10-21
* **Fix (Linux):** on RHEL/Rocky with Remi packages the script reported "Apache httpd loads mod_php" when
  `15-php.conf` contained the `LoadModule` line inside `<IfModule mpm_prefork_module>` while httpd ran
  `mpm_event` + PHP-FPM. Detection now uses `httpd -M`. Found on a Rocky Linux 9 production host.

## v1.3.0 — 2026-10-21 (after the PHP security release)
* PHP released **8.5.12, 8.4.27, 8.3.36, 8.2.35**. Root cause from the official fix ("Avoid state corruption
  via bailout", GHSA-w8hw-w9fx-j79w / CVE-2026-109618, GHSA-6wmf-4rv5-p3rp / CVE-2026-109619): out-of-memory
  abort while parsing the request leaves corrupted / stale state for the next request on the worker.
* **Scripts (Linux v1.3.0, Windows v1.3.0):** fixed versions built in (`PHP2SHELL_FIXED_UPSTREAM` still
  overrides); new `Interim:` line / `interim_mitigations` JSON per runtime and per container for the four
  advisory settings (`memory_limit=-1`, `post_max_size`, `session.upload_progress.enabled=0`,
  `fatal_error_backtraces=0` on 8.5); `memory_limit`, `post_max_size`, `fatal_error_backtraces` added to the
  reported settings and to the override search (pool / web server / per-directory); `--container-exec`
  also reports `memory_limit`; summary text follows the advisory.
* **New rules:** Sigma `php2shell_php_oom_during_request_parsing` (+ Splunk, QRadar payload, CrowdStrike);
  Wazuh 109627 (out-of-memory during request parsing), 109628 (followed by a worker crash within 2 min),
  109629 (burst); ModSecurity 9109622 (multipart part-header flood, log only), 9109623 (request-body error,
  log only).
* **Fix (generated CrowdStrike queries):** keyword searches were rendered as `/"text"/i`, which requires
  literal quotes in the event; now `/text/i`. Affects `php2shell_php_worker_crash.logscale`.
* README (EN/TR): status, confirmed facts, workaround table per the advisory (with the `memory_limit=-1`
  DoS caveat), detection table, plan, and lab notes from the patch analysis (official regression tests only).

## v1.2.3 — 2026-10-21 14:55 TRT
* **Fix (Linux):** for Apache + mod_php containers (e.g. official `php:*-apache` images) package and
  fix status were taken from the Apache executable (`apache2-bin`), not from PHP. The script now reads the
  loaded `libphp*.so` from `/proc/<pid>/maps` (verified by inode) and uses it for package ownership and
  version; the report shows it as `PHP : mod_php module ...`. Found during validation on a Docker host.
* Containers with `PHP_VERSION` in their environment (official images) are always treated as source builds.

## v1.2.2 — 2026-10-21 14:00 TRT
* **Fix (Linux):** on hosts without any PHP container the container section aborted with
  `NS_PIDS: unbound variable` (`set -u` with an empty associative array). Arrays are now initialised and
  empty-array loops are guarded (also for bash < 4.4). Found on a Rocky Linux 10.2 production host.

## v1.2.1 — 2026-10-21 14:00 TRT
* **Fix (Linux, regression in v1.2.0):** v1.2.0 treated every process in another mount namespace as a
  container. systemd services with `PrivateTmp=`/`ProtectSystem=` (php-fpm and httpd on RHEL/Rocky and Debian)
  have their own mount namespace, so the host's php-fpm was reported as an unidentified "container" and the
  host `php-fpm` runtime showed `not running`. Containers are now detected by a different root file system
  (`/proc/<pid>/root` device:inode), not by mount namespace. Found on a Rocky Linux 10.2 production host.
* Container binary path is normalised to the path inside the container (verified by inode against
  `/proc/<pid>/exe`); the version string is read from `/proc/<pid>/exe`.

## v1.2.0 — 2026-10-21 13:20 TRT
* **Fix (Linux):** processes running in a container were matched to host binaries with the same path
  (`/proc/<pid>/exe` shows the path inside the container). This could put container workers into the host
  `Running:` result (wrong `STALE`/`LOADED`) and add container binaries to host discovery. The script now
  separates processes by mount namespace.
* **New (Linux):** containers / Kubernetes pods on the host are inspected by default, read-only via
  `/proc/<pid>/root` — works for Docker, Podman, containerd and CRI-O, nothing is executed inside them.
  Per container: PHP version (env, `php_version.h`, dpkg owner of the binary, apk, binary string), package and
  changelog status, official-image (`/usr/local`) vs distro layout, `session.upload_progress.enabled` parsed
  from ini/pool files, and the `Running:` state against the container's own config files. Pod / container
  names via `crictl`, `docker` or `podman inspect` when available; Apache containers are recognised when
  `libphp` is loaded.
* Options: `--no-containers` skips the inspection; `--container-exec` (alias of the old `--containers`)
  additionally runs `php -r` through `docker|podman exec`.
* Limits: only containers running on this host/node; images and stopped containers are not covered (use an
  image scanner such as Trivy/Grype after the advisory); values are parsed from files, not `php -i`.

## v1.1.0 — 2026-10-21 12:15 TRT
* Scripts: new `Running:` check per runtime. Settings were read from the ini files on disk only, so an `Off`
  result did not prove that running workers had been reloaded. Both scripts now compare the start time of the
  running processes with the last config change and with the PHP binary:
  `LOADED`, `STALE` (reload/recycle needed), `RESTART REQUIRED` (binary replaced by an update, service not
  restarted), `UNVERIFIED` (Linux: master only, e.g. `pm=ondemand`), `not running`.
* Linux: FPM pool files and `php-fpm.conf` are part of the config comparison; processes running a deleted
  (replaced) binary are flagged and the runtime is treated as not patched.
* Windows: reports IIS FastCGI `monitorChangesTo`; without it IIS does not restart php-cgi on php.ini edits.
* JSON: `runtime_state` per runtime and top-level `stale_runtime`.

## v1.0.1 — 2026-10-21
* README: added the ORBITRON investigation playbook (screenshot) as section 11.

## Planned — after 14:00 UTC
* Add official affected/fixed versions; set default `FIXED_UPSTREAM` in the scripts.
* Replace/extend behavioural rules with trigger-specific signatures once the patch diff is public.
* Update distribution status (RHSA/RLSA/ALSA, DSA, USN) as advisories appear.
