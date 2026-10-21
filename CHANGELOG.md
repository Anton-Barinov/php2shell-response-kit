# Changelog

## v1.0.0 — 2026-10-21 10:30 TRT (07:30 UTC) — pre-disclosure
* Initial release before the official PHP advisory (scheduled 14:00 UTC).
* Linux and Windows read-only inventory scripts (PHP runtimes, SAPIs, effective `session.upload_progress.*`, overrides, package/backport status).
* Sigma sources + generated Splunk, QRadar, CrowdStrike Falcon (LogScale), SentinelOne (DV/PQ) queries — untested on live platforms.
* Wazuh rules (auditd, FIM, Sysmon, crash logs), YARA hunting rules, ModSecurity rules (lab-tested).
* Workaround status: `session.upload_progress.enabled=0` = partial mitigation only (per Flatt Security update).

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
