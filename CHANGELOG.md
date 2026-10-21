# Changelog

## v1.0.0 — 2026-10-21 10:30 TRT (07:30 UTC) — pre-disclosure
* Initial release before the official PHP advisory (scheduled 14:00 UTC).
* Linux and Windows read-only inventory scripts (PHP runtimes, SAPIs, effective `session.upload_progress.*`, overrides, package/backport status).
* Sigma sources + generated Splunk, QRadar, CrowdStrike Falcon (LogScale), SentinelOne (DV/PQ) queries — untested on live platforms.
* Wazuh rules (auditd, FIM, Sysmon, crash logs), YARA hunting rules, ModSecurity rules (lab-tested).
* Workaround status: `session.upload_progress.enabled=0` = partial mitigation only (per Flatt Security update).

## v1.0.1 — 2026-10-21
* README: added the ORBITRON investigation playbook (screenshot) as section 11.

## Planned — after 14:00 UTC
* Add official affected/fixed versions; set default `FIXED_UPSTREAM` in the scripts.
* Replace/extend behavioural rules with trigger-specific signatures once the patch diff is public.
* Update distribution status (RHSA/RLSA/ALSA, DSA, USN) as advisories appear.
