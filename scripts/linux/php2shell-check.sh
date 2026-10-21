#!/usr/bin/env bash
# =============================================================================
#  ORBITRON php2shell exposure checker (Linux)        v1.2.0  (2026-10-21)
#  CVE-2026-109618 / CVE-2026-109619  ("php2shell")
#
#  READ-ONLY. This script does not change configuration, does not install
#  anything, does not open network connections and does not test for the
#  vulnerability. It inventories PHP runtimes and reports:
#    - PHP binaries / SAPIs (CLI, FPM, CGI, LiteSpeed, mod_php)
#    - effective session.upload_progress.* and related settings per SAPI
#    - per-pool / per-directory / web-server level overrides of those settings
#    - owning package, repository origin and whether the package changelog
#      already mentions the CVE IDs (distribution backport detection)
#    - running PHP / web server processes, and whether the RUNNING workers
#      actually use the current configuration and binary (a settings change
#      or a package update only takes effect after a reload/restart)
#    - PHP running inside containers / Kubernetes pods on this host (Docker,
#      Podman, containerd, CRI-O): found via the process table, inspected
#      READ-ONLY through /proc/<pid>/root - nothing is executed inside them
#    - optionally (--container-exec) exact values via 'docker|podman exec php'
#
#  Usage:  sudo ./php2shell-check.sh [--json] [-o report.json] [--webroot DIR]...
#                                    [--no-containers] [--container-exec]
#  Exit codes: 0 = no PHP found, 1 = PHP found and every runtime confirmed
#              patched, 2 = PHP found and at least one runtime NOT confirmed
#              patched, 3 = usage error.
#
#  License: MIT. Provided as-is, without warranty. Review before running.
# =============================================================================

set -u
LC_ALL=C; export LC_ALL

SCRIPT_VERSION="1.2.0"
CVES="CVE-2026-109618 CVE-2026-109619"

# Fixed upstream versions. EMPTY until the official PHP advisory is published
# (scheduled 2026-10-21 14:00 UTC). Fill in, e.g. "8.2.35 8.3.36 8.4.27 8.5.12",
# ONLY from https://www.php.net/ - rumoured numbers must not be used here.
FIXED_UPSTREAM="${PHP2SHELL_FIXED_UPSTREAM:-}"

# Branches that receive upstream security fixes (php.net/supported-versions).
SUPPORTED_BRANCHES="8.2 8.3 8.4 8.5"

JSON_ONLY=0
OUT_FILE=""
SCAN_CONTAINERS=1
CONTAINER_EXEC=0
WEBROOTS=()

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON_ONLY=1 ;;
    -o|--output) shift; OUT_FILE="${1:-}"; [ -n "$OUT_FILE" ] || { usage; exit 3; } ;;
    --webroot) shift; [ -n "${1:-}" ] || { usage; exit 3; }; WEBROOTS+=("$1") ;;
    --no-containers) SCAN_CONTAINERS=0 ;;
    --container-exec|--containers) CONTAINER_EXEC=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 3 ;;
  esac
  shift
done

if [ ${#WEBROOTS[@]} -eq 0 ]; then
  WEBROOTS=(/var/www /srv /usr/share/nginx /home /opt/bitnami)
fi

have() { command -v "$1" >/dev/null 2>&1; }
TIMEOUT=""; have timeout && TIMEOUT="timeout 15"

say() { [ "$JSON_ONLY" -eq 1 ] || printf '%s\n' "$*"; }
hr()  { say "------------------------------------------------------------------------------"; }

json_str() {
  # JSON string escape (backslash, quote, control characters)
  [ -n "$1" ] || { printf '""'; return; }
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r/\\r/g' \
    | awk 'BEGIN{ORS=""} NR>1{print "\\n"} {print}' | sed 's/^/"/; s/$/"/'
}

ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# --------------------------------------------------------------------------
# Host facts
# --------------------------------------------------------------------------
HOSTNAME_S="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)"
OS_NAME="unknown"; OS_ID=""; OS_LIKE=""
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  OS_NAME="$(. /etc/os-release; echo "${PRETTY_NAME:-$NAME}")"
  OS_ID="$(. /etc/os-release; echo "${ID:-}")"
  OS_LIKE="$(. /etc/os-release; echo "${ID_LIKE:-}")"
fi
PKG_FAMILY="other"
case " $OS_ID $OS_LIKE " in
  *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*|*" amzn "*|*" cloudlinux "*) PKG_FAMILY="rpm" ;;
  *" debian "*|*" ubuntu "*) PKG_FAMILY="deb" ;;
  *" alpine "*) PKG_FAMILY="apk" ;;
  *" suse "*|*" sles "*|*" opensuse "*) PKG_FAMILY="rpm" ;;
esac
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Mount namespace of this script. Processes in another mount namespace run in a
# container: their /proc/<pid>/exe path refers to the CONTAINER file system and
# must not be matched against binaries of this host.
SELF_MNT="$(readlink /proc/self/ns/mnt 2>/dev/null)"
same_mnt() { local m; m="$(readlink "/proc/$1/ns/mnt" 2>/dev/null)"; [ -z "$m" ] || [ -z "$SELF_MNT" ] || [ "$m" = "$SELF_MNT" ]; }
[ "$(id -u)" -eq 0 ] || say "WARNING: not running as root - some configs/changelogs may be unreadable."

# --------------------------------------------------------------------------
# 1. Discover PHP binaries
# --------------------------------------------------------------------------
CANDIDATES=()
for p in /usr/bin/php* /usr/sbin/php-fpm* /usr/bin/php-cgi* /usr/local/bin/php* /usr/local/sbin/php-fpm* \
         /opt/remi/php*/root/usr/bin/php* /opt/remi/php*/root/usr/sbin/php-fpm* \
         /opt/rh/rh-php*/root/usr/bin/php* /opt/rh/rh-php*/root/usr/sbin/php-fpm* \
         /opt/cpanel/ea-php*/root/usr/bin/php* /opt/cpanel/ea-php*/root/usr/sbin/php-fpm* \
         /opt/plesk/php/*/bin/php* /opt/plesk/php/*/sbin/php-fpm* \
         /opt/alt/php*/usr/bin/php* /opt/alt/php*/usr/sbin/php-fpm* \
         /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/lsphp*/bin/php \
         /opt/bitnami/php/bin/php* /opt/bitnami/php/sbin/php-fpm* \
         /www/server/php/*/bin/php* /www/server/php/*/sbin/php-fpm*; do
  [ -f "$p" ] && [ -x "$p" ] || continue
  b="$(basename "$p")"
  case "$b" in
    php|php[0-9]*|php-fpm|php-fpm[0-9]*|php-cgi|php-cgi[0-9]*|lsphp|lsphp[0-9]*) ;;
    *) continue ;;
  esac
  case "$b" in *config*|*ize*|*dbg*) continue ;; esac
  CANDIDATES+=("$p")
done
for c in php php-fpm php-cgi lsphp; do
  have "$c" && CANDIDATES+=("$(command -v "$c")")
done
# binaries of running processes (catches custom builds in odd paths)
if [ -d /proc ]; then
  for exe in /proc/[0-9]*/exe; do
    same_mnt "$(basename "$(dirname "$exe")")" || continue   # container process: handled in section 6
    t="$(readlink "$exe" 2>/dev/null)" || continue
    case "$(basename "$t")" in php|php[0-9]*|php-fpm*|php-cgi*|lsphp*) CANDIDATES+=("$t") ;; esac
  done
fi

BINARIES=()
SEEN=" "
for c in "${CANDIDATES[@]+"${CANDIDATES[@]}"}"; do
  r="$(readlink -f "$c" 2>/dev/null || echo "$c")"
  r="${r% (deleted)}"
  [ -x "$r" ] || continue
  case "$SEEN" in *" $r "*) continue ;; esac
  SEEN="$SEEN$r "
  BINARIES+=("$r")
done

# --------------------------------------------------------------------------
# helpers to read effective settings
# --------------------------------------------------------------------------
KEYS="session.upload_progress.enabled session.upload_progress.cleanup session.upload_progress.name session.upload_progress.prefix session.use_strict_mode session.save_handler session.save_path file_uploads cgi.fix_pathinfo"

# normalise phpinfo (text or HTML) to "key => local => master" lines
phpinfo_norm() {
  sed -e 's#</td><td[^>]*>#  => #g' -e 's/<[^>]*>//g' -e 's/&nbsp;/ /g' -e 's/&quot;/"/g' \
      -e 's/[[:space:]]\{1,\}=>/ =>/g' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}
info_get() { # $1=normalised info, $2=key -> local value
  printf '%s\n' "$1" | awk -F' => ' -v k="$2" '$1==k {print $2; exit}'
}

pkg_info() { # $1=path -> "pkg|version|origin|changelog_status"
  local f="$1" pkg="" ver="" origin="" cl="unknown"
  if have rpm && rpm -qf "$f" >/dev/null 2>&1; then
    pkg="$(rpm -qf --qf '%{NAME}' "$f" 2>/dev/null)"
    ver="$(rpm -qf --qf '%{VERSION}-%{RELEASE}' "$f" 2>/dev/null)"
    origin="$(rpm -qf --qf '%{VENDOR}' "$f" 2>/dev/null)"
    case "$ver" in *remi*) origin="Remi ($origin)";; esac
    if rpm -q --changelog "$pkg" 2>/dev/null | grep -qE 'CVE-2026-10961[89]'; then cl="mentions-cve"; else cl="not-mentioned"; fi
  elif have dpkg-query && dpkg -S "$f" >/dev/null 2>&1; then
    pkg="$(dpkg -S "$f" 2>/dev/null | head -n1 | cut -d: -f1)"
    ver="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)"
    origin="$(dpkg-query -W -f='${Maintainer}' "$pkg" 2>/dev/null)"
    case "$ver" in *sury*) origin="deb.sury.org ($origin)";; esac
    local src; src="$(dpkg-query -W -f='${source:Package}' "$pkg" 2>/dev/null)"
    local logf=""
    for d in "/usr/share/doc/$pkg" "/usr/share/doc/${src}-common" "/usr/share/doc/$src"; do
      [ -r "$d/changelog.Debian.gz" ] && { logf="$d/changelog.Debian.gz"; break; }
    done
    if [ -n "$logf" ]; then
      if zcat "$logf" 2>/dev/null | grep -qE 'CVE-2026-10961[89]'; then cl="mentions-cve"; else cl="not-mentioned"; fi
    else
      cl="changelog-unavailable"
    fi
  elif have apk && apk info --who-owns "$f" >/dev/null 2>&1; then
    pkg="$(apk info --who-owns "$f" 2>/dev/null | awk '{print $NF}')"
    ver="$pkg"; origin="alpine"; cl="check-secdb"
  else
    pkg="unpackaged"; cl="n/a"
  fi
  printf '%s|%s|%s|%s' "$pkg" "$ver" "$origin" "$cl"
}

branch_of() { printf '%s' "$1" | sed -n 's/^\([0-9]\{1,\}\.[0-9]\{1,\}\).*/\1/p'; }

fix_status() { # $1=upstream version $2=changelog status $3=package origin $4=package name
  local v="$1" cl="$2" origin="$3" pkg="$4"
  if [ "$cl" = "mentions-cve" ]; then echo "patched (package changelog lists CVE)"; return; fi
  # Distribution packages keep the old upstream version number and backport
  # fixes, so an upstream version comparison would be wrong for them.
  local distro=0
  case "$pkg" in unpackaged|"") distro=0 ;; *)
    case "$origin" in
      *sury*|*Remi*|*remi*) distro=0 ;;
      *) distro=1 ;;
    esac ;;
  esac
  if [ "$distro" -eq 1 ]; then
    echo "NOT CONFIRMED - distro package; changelog does not list the CVEs yet (check vendor advisory)"
    return
  fi
  if [ -z "$FIXED_UPSTREAM" ]; then echo "pending - official advisory not yet published"; return; fi
  local br; br="$(branch_of "$v")"
  for fv in $FIXED_UPSTREAM; do
    if [ "$(branch_of "$fv")" = "$br" ]; then
      if ver_ge "$v" "$fv"; then echo "patched (upstream >= $fv)"; else echo "NOT PATCHED (upstream < $fv)"; fi
      return
    fi
  done
  echo "NOT PATCHED - no upstream fix for branch $br (upgrade, or use a vendor/ESM backport)"
}

# --------------------------------------------------------------------------
# Runtime state: do the RUNNING processes use the current config and binary?
# The settings above are read from the ini files on disk. Running FPM/CGI
# workers and Apache children keep the values (and the binary) they were
# started with until a reload/restart.
# --------------------------------------------------------------------------
NOW_EPOCH="$(date +%s)"
declare -A P_PPID P_START P_EXE P_HOST
if have ps; then
  while read -r pid ppid et; do
    [ -n "$pid" ] || continue
    P_PPID[$pid]="$ppid"; P_START[$pid]=$((NOW_EPOCH - et))
    P_EXE[$pid]="$(readlink "/proc/$pid/exe" 2>/dev/null)"
    if same_mnt "$pid"; then P_HOST[$pid]=1; else P_HOST[$pid]=0; fi
  done < <(ps -eo pid=,ppid=,etimes= 2>/dev/null)
fi
ANY_STALE=0
STATE_TEXT=""; STATE_JSON=""

fmt_epoch() { date -d "@$1" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$1"; }

newest_mtime() { # files... -> "epoch|file" of the newest existing file
  local best=0 bf="" f m
  for f in "$@"; do
    [ -f "$f" ] || continue
    m="$(stat -c %Y "$f" 2>/dev/null)" || continue
    if [ "${m:-0}" -gt "$best" ]; then best="$m"; bf="$f"; fi
  done
  printf '%s|%s' "$best" "$bf"
}

runtime_state() { # $1=match mode (bin|apache|none) $2=binary $3=php.ini $4=scan dir(s) $5=label
  local mode="$1" bin="$2" ini="$3" scandir="$4" label="$5"
  STATE_TEXT=""; STATE_JSON=""
  if [ "$mode" = "none" ]; then
    STATE_TEXT="n/a (CLI reads its configuration at every start)"
    STATE_JSON="{\"status\":\"n/a\"}"; return
  fi
  # configuration files that the running SAPI loaded at start-up
  local files=() d f
  case "$ini" in ""|"(none)") ;; *) files+=("$ini") ;; esac
  for d in ${scandir//:/ }; do
    case "$d" in ""|"(none)") ;; *) for f in "$d"/*.ini; do files+=("$f"); done ;; esac
  done
  if [ -n "$ini" ] && [ "$mode" = "bin" ]; then
    case "$label" in php-fpm*)
      d="$(dirname "$ini")"
      for f in "$d/php-fpm.conf" /etc/php-fpm.conf "$d"/pool.d/*.conf "$d"/php-fpm.d/*.conf /etc/php-fpm.d/*.conf; do files+=("$f"); done ;;
    esac
  fi
  local nm cfg_epoch cfg_file
  nm="$(newest_mtime "${files[@]+"${files[@]}"}")"; cfg_epoch="${nm%%|*}"; cfg_file="${nm#*|}"

  # matching processes (host mount namespace only)
  local pid exe base fam=()
  for pid in "${!P_EXE[@]}"; do
    exe="${P_EXE[$pid]}"; [ -n "$exe" ] || continue
    [ "${P_HOST[$pid]:-1}" = "1" ] || continue
    base="$(basename "${exe% (deleted)}")"
    case "$mode" in
      bin)    [ "${exe% (deleted)}" = "$bin" ] || continue ;;
      apache) case "$base" in httpd|apache2) ;; *) continue ;; esac ;;
    esac
    fam+=("$pid")
  done
  eval_family "$cfg_epoch" "$cfg_file" "${fam[@]+"${fam[@]}"}"
}

eval_family() { # $1=config epoch $2=config file $3..=pids -> STATE_TEXT / STATE_JSON
  local cfg_epoch="$1" cfg_file="$2"; shift 2
  local fam=("$@") deleted=0 p
  STATE_TEXT=""; STATE_JSON=""
  if [ ${#fam[@]} -eq 0 ]; then
    STATE_TEXT="not running"
    STATE_JSON="{\"status\":\"not-running\"}"; return
  fi
  for p in "${fam[@]}"; do case "${P_EXE[$p]}" in *" (deleted)") deleted=$((deleted+1)) ;; esac; done
  # masters = processes whose parent is not of the same family; workers = the rest
  local workers=0 stale=0 oldest=0 masters=0 mstale=0 fampids=" ${fam[*]} "
  for p in "${fam[@]}"; do
    if [[ "$fampids" == *" ${P_PPID[$p]} "* ]]; then
      workers=$((workers+1))
      if [ "$oldest" -eq 0 ] || [ "${P_START[$p]}" -lt "$oldest" ]; then oldest="${P_START[$p]}"; fi
      [ "$cfg_epoch" -gt 0 ] && [ "${P_START[$p]}" -lt "$cfg_epoch" ] && stale=$((stale+1))
    else
      masters=$((masters+1))
      [ "$cfg_epoch" -gt 0 ] && [ "${P_START[$p]}" -lt "$cfg_epoch" ] && mstale=$((mstale+1))
    fi
  done
  local status
  local cfgdesc
  cfgdesc="last config change $(fmt_epoch "$cfg_epoch") (${cfg_file:-unknown})"
  if [ "$deleted" -gt 0 ]; then
    status="restart-required"; ANY_STALE=1; ANY_UNPATCHED=1
    STATE_TEXT="RESTART REQUIRED: $deleted process(es) still run a binary that was replaced on disk (package updated, service not restarted)"
  elif [ "$workers" -eq 0 ] && [ "$mstale" -eq 0 ]; then
    status="loaded"
    STATE_TEXT="LOADED: process(es) started after the $cfgdesc"
  elif [ "$workers" -eq 0 ]; then
    status="unverified"
    STATE_TEXT="UNVERIFIED: no worker processes (e.g. pm=ondemand) and the master predates the $cfgdesc; a reload may keep the master's start time (systemd) - check the service log for a reload, or restart"
  elif [ "$stale" -gt 0 ]; then
    status="stale"; ANY_STALE=1
    STATE_TEXT="STALE: $stale of $workers worker(s) started before the $cfgdesc - reload/restart the service"
  else
    status="loaded"
    STATE_TEXT="LOADED: all $workers worker(s) started after the $cfgdesc"
  fi
  STATE_JSON="{\"status\":$(json_str "$status"),\"processes\":${#fam[@]},\"workers\":$workers,\"stale_workers\":$stale,\"deleted_binary_processes\":$deleted,\"config_mtime\":$(json_str "$(fmt_epoch "$cfg_epoch")"),\"config_file\":$(json_str "$cfg_file"),\"oldest_worker_start\":$(json_str "$( [ "$oldest" -gt 0 ] && fmt_epoch "$oldest")")}"
}

# --------------------------------------------------------------------------
# 2. Inspect each runtime
# --------------------------------------------------------------------------
RUNTIME_JSON=()
ANY_UNPATCHED=0
NPHP=0

report_runtime() { # $1=label $2=binary $3=normalised phpinfo $4=note $5=SAPI display override $6=process match mode
  local label="$1" bin="$2" info="$3" note="${4:-}" api_override="${5:-}" pmode="${6:-bin}"
  local ver api ini scandir
  ver="$(info_get "$info" "PHP Version")"
  [ -n "$ver" ] || ver="$("$bin" -v 2>/dev/null | head -n1 | awk '{print $2}')"
  api="$(info_get "$info" "Server API")"
  [ -n "$api_override" ] && api="$api_override"
  ini="$(info_get "$info" "Loaded Configuration File")"
  scandir="$(info_get "$info" "Scan this dir for additional .ini files")"
  local br branch_state
  br="$(branch_of "$ver")"
  case " $SUPPORTED_BRANCHES " in *" $br "*) branch_state="upstream-supported" ;; *) branch_state="upstream-EOL" ;; esac
  local pi pkg pver porigin pcl
  pi="$(pkg_info "$bin")"
  pkg="${pi%%|*}"; pi="${pi#*|}"; pver="${pi%%|*}"; pi="${pi#*|}"; porigin="${pi%%|*}"; pcl="${pi#*|}"
  local fs; fs="$(fix_status "$ver" "$pcl" "$porigin" "$pkg")"
  case "$fs" in patched*) ;; *) ANY_UNPATCHED=1 ;; esac
  NPHP=$((NPHP+1))

  hr
  say "Runtime  : $label"
  say "Binary   : $bin"
  say "Version  : ${ver:-unknown}   (branch ${br:-?}: $branch_state)"
  say "SAPI     : ${api:-unknown}${note:+   [$note]}"
  say "php.ini  : ${ini:-none}   scan dir: ${scandir:-none}"
  say "Package  : $pkg ${pver}  ${porigin:+[$porigin]}"
  say "Changelog: $pcl    Fix status: $fs"
  local kv=""
  for k in $KEYS; do
    local v; v="$(info_get "$info" "$k")"
    say "$(printf '   %-34s %s' "$k" "${v:-<not set>}")"
    kv="$kv$(json_str "$k"):$(json_str "${v:-}"),"
  done
  local upe; upe="$(info_get "$info" "session.upload_progress.enabled")"
  case "$upe" in
    On|1)
      case "$label" in
        php-fpm*) say "   -> ON in php.ini - pools may override it (see 'Overrides' below). Patch is still required." ;;
        *)        say "   -> session.upload_progress.enabled is ON (partial mitigation NOT applied; patch is still required)" ;;
      esac ;;
  esac
  [ "$branch_state" = "upstream-EOL" ] && say "   -> Branch $br gets no upstream fix. Only a distro backport/ESM, a paid backport or an upgrade closes it."
  runtime_state "$pmode" "$bin" "$ini" "$scandir" "$label"
  say "Running  : $STATE_TEXT"

  RUNTIME_JSON+=("{\"label\":$(json_str "$label"),\"binary\":$(json_str "$bin"),\"version\":$(json_str "$ver"),\"branch\":$(json_str "$br"),\"branch_state\":$(json_str "$branch_state"),\"server_api\":$(json_str "$api"),\"note\":$(json_str "$note"),\"php_ini\":$(json_str "$ini"),\"scan_dir\":$(json_str "$scandir"),\"package\":$(json_str "$pkg"),\"package_version\":$(json_str "$pver"),\"package_origin\":$(json_str "$porigin"),\"changelog_cve\":$(json_str "$pcl"),\"fix_status\":$(json_str "$fs"),\"runtime_state\":${STATE_JSON:-null},\"settings\":{${kv%,}}}")
}

say "ORBITRON php2shell exposure checker v$SCRIPT_VERSION  |  $CVES"
say "Host: $HOSTNAME_S  |  OS: $OS_NAME  |  $NOW"
[ -n "$FIXED_UPSTREAM" ] || say "NOTE: fixed versions not configured yet (official advisory pending). Fix status relies on package changelogs only."

for bin in "${BINARIES[@]+"${BINARIES[@]}"}"; do
  raw="$($TIMEOUT "$bin" -i 2>/dev/null)"
  if [ -z "$raw" ]; then
    say "WARNING: could not run '$bin -i' - skipping detailed check"
    continue
  fi
  info="$(printf '%s\n' "$raw" | phpinfo_norm)"
  name="$(basename "$bin")"
  case "$name" in
    php-fpm*) report_runtime "php-fpm" "$bin" "$info" "master ini only - see pool overrides below" ;;
    php-cgi*) report_runtime "php-cgi" "$bin" "$info" ;;
    lsphp*)   report_runtime "lsphp" "$bin" "$info" ;;
    *)        report_runtime "php-cli" "$bin" "$info" "CLI values may differ from the web SAPI" "" "none" ;;
  esac
done

# --------------------------------------------------------------------------
# 3. mod_php (Apache module) - evaluate the Apache-specific ini set
# --------------------------------------------------------------------------
MODPHP_NOTES=()
for ap in /etc/php/*/apache2/php.ini; do
  [ -r "$ap" ] || continue
  vdir="$(dirname "$(dirname "$ap")")"; v="$(basename "$vdir")"
  enabled="no"; ls /etc/apache2/mods-enabled/php"$v".load >/dev/null 2>&1 && enabled="yes"
  cli=""; for cb in "/usr/bin/php$v" /usr/bin/php; do [ -x "$cb" ] && { cli="$cb"; break; }; done
  if [ -n "$cli" ]; then
    raw="$(PHP_INI_SCAN_DIR="$vdir/apache2/conf.d" $TIMEOUT "$cli" -c "$ap" -i 2>/dev/null)"
    info="$(printf '%s\n' "$raw" | phpinfo_norm)"
    report_runtime "mod_php $v (Apache module enabled: $enabled)" "$cli" "$info" "evaluated with $ap via CLI binary; Apache php_flag/php_admin_* overrides listed below" "apache2handler (mod_php)" "apache"
  else
    MODPHP_NOTES+=("mod_php ini $ap found but no matching CLI binary to evaluate it")
  fi
done
if ls /etc/httpd/conf.modules.d/*php*.conf >/dev/null 2>&1 && grep -qsE 'LoadModule +php[0-9_]*_module' /etc/httpd/conf.modules.d/*php*.conf; then
  MODPHP_NOTES+=("Apache httpd loads mod_php (RHEL family): it uses /etc/php.ini + /etc/php.d, i.e. the same values as the php-cli runtime above")
fi
for n in "${MODPHP_NOTES[@]+"${MODPHP_NOTES[@]}"}"; do hr; say "mod_php  : $n"; done

# --------------------------------------------------------------------------
# 4. Overrides (FPM pools, web server config, per-directory files)
# --------------------------------------------------------------------------
OVR_JSON=()
add_override() { # $1=type $2=file:line:text
  OVR_JSON+=("{\"type\":$(json_str "$1"),\"match\":$(json_str "$2")}")
  say "   [$1] $2"
}
hr
say "Overrides of session.upload_progress.* (pool / web server / per-directory):"
OV_COUNT=0
for d in /etc/php/*/fpm/pool.d /etc/php-fpm.d /etc/opt/remi/php*/php-fpm.d /opt/remi/php*/root/etc/php-fpm.d \
         /opt/cpanel/ea-php*/root/etc/php-fpm.d /opt/plesk/php/*/etc/php-fpm.d /usr/local/etc/php-fpm.d \
         /etc/php*/php-fpm.d /opt/alt/php*/etc/php-fpm.d /www/server/php/*/etc/php-fpm.d; do
  [ -d "$d" ] || continue
  while IFS= read -r m; do [ -n "$m" ] && { add_override "fpm-pool" "$m"; OV_COUNT=$((OV_COUNT+1)); }; done \
    < <(grep -rHnE '^[^;#]*session\.upload_progress' "$d" 2>/dev/null)
done
for d in /etc/apache2 /etc/httpd /etc/nginx /usr/local/apache/conf /usr/local/lsws/conf /etc/openlitespeed; do
  [ -d "$d" ] || continue
  while IFS= read -r m; do [ -n "$m" ] && { add_override "webserver" "$m"; OV_COUNT=$((OV_COUNT+1)); }; done \
    < <(grep -rHnE '^[^#]*session\.upload_progress' "$d" 2>/dev/null)
done
for w in "${WEBROOTS[@]}"; do
  [ -d "$w" ] || continue
  while IFS= read -r f; do
    while IFS= read -r m; do [ -n "$m" ] && { add_override "per-dir" "$m"; OV_COUNT=$((OV_COUNT+1)); }; done \
      < <(grep -HnE '^[^;#]*session\.upload_progress' "$f" 2>/dev/null)
  done < <(find "$w" -maxdepth 8 \( -name .user.ini -o -name .htaccess \) -type f 2>/dev/null)
done
[ "$OV_COUNT" -eq 0 ] && say "   none found (defaults/ini values above apply)"
say "   Note: .user.ini applies to FPM/CGI only; .htaccess php_flag/php_value to mod_php only;"
say "         nginx 'fastcgi_param PHP_VALUE' / PHP_ADMIN_VALUE and FPM php_admin_* override php.ini."

# --------------------------------------------------------------------------
# 5. Running processes
# --------------------------------------------------------------------------
hr
say "Running PHP / web server processes (master + worker counts, host and containers):"
PROC_JSON=()
if have ps; then
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    say "   $line"
    PROC_JSON+=("$(json_str "$line")")
  done < <(ps -eo comm=,user= 2>/dev/null | awk '$1 ~ /^(php|php-fpm|php-cgi|lsphp|httpd|apache2|nginx|litespeed|lshttpd|openlitespeed)/ {c[$1" (user "$2")"]++} END {for (k in c) print c[k]"x "k}' | sort)
fi
[ ${#PROC_JSON[@]} -eq 0 ] && say "   none"

# --------------------------------------------------------------------------
# 6. Containers / Kubernetes pods (READ-ONLY via /proc/<pid>/root)
#    Works for Docker, Podman, containerd and CRI-O because it starts from the
#    host process table. Nothing is executed inside the container: version and
#    settings are read from files (env, headers, package DB, binary strings,
#    ini/pool files). Values are therefore "parsed", not "effective"; use
#    --container-exec for php -i based values via docker/podman exec.
# --------------------------------------------------------------------------
CONT_JSON=()

is_php_proc() { # $1=pid -> 0 if PHP-related (php, php-fpm, php-cgi, lsphp or Apache with libphp loaded)
  local exe="${P_EXE[$1]% (deleted)}" b
  b="$(basename "$exe")"
  case "$b" in
    php|php[0-9]*|php-fpm|php-fpm[0-9]*|php-cgi|php-cgi[0-9]*|lsphp|lsphp[0-9]*|frankenphp) return 0 ;;
    httpd|apache2) grep -qs 'libphp' "/proc/$1/maps" && return 0 ;;
  esac
  return 1
}

container_id_of() { # $1=pid -> 64-hex container id from cgroup (Docker, containerd, CRI-O, Podman)
  grep -oE '[0-9a-f]{64}' "/proc/$1/cgroup" 2>/dev/null | tail -n1
}

container_name_of() { # $1=container id -> "runtime:name image" or pod/namespace (best effort, read-only API calls)
  local id="$1" out=""
  [ -n "$id" ] || return 0
  if have crictl; then
    out="$($TIMEOUT crictl inspect "$id" 2>/dev/null)"
    if [ -n "$out" ]; then
      local pod ns cname img
      pod="$(printf '%s' "$out" | grep -m1 -oE '"io.kubernetes.pod.name": *"[^"]*"' | sed 's/.*: *"//; s/"$//')"
      ns="$(printf '%s' "$out" | grep -m1 -oE '"io.kubernetes.pod.namespace": *"[^"]*"' | sed 's/.*: *"//; s/"$//')"
      cname="$(printf '%s' "$out" | grep -m1 -oE '"io.kubernetes.container.name": *"[^"]*"' | sed 's/.*: *"//; s/"$//')"
      img="$(printf '%s' "$out" | grep -m1 -oE '"image": *"[^"]*"' | sed 's/.*: *"//; s/"$//')"
      [ -n "$pod" ] && { printf 'k8s pod %s/%s container %s image %s' "${ns:-?}" "$pod" "${cname:-?}" "${img:-?}"; return 0; }
    fi
  fi
  for rt in docker podman; do
    have "$rt" || continue
    out="$($TIMEOUT "$rt" inspect --format '{{.Name}} image {{.Config.Image}}' "$id" 2>/dev/null)"
    [ -n "$out" ] && { printf '%s %s' "$rt" "${out#/}"; return 0; }
  done
  return 0
}

ini_bool() { # normalise an ini boolean
  local v; v="$(printf '%s' "$1" | tr -d '"'"'"' ;' | tr '[:upper:]' '[:lower:]')"
  case "$v" in 1|on|true|yes) echo "On" ;; 0|off|false|no|none|"") echo "Off" ;; *) echo "$1" ;; esac
}

if [ "$SCAN_CONTAINERS" -eq 1 ]; then
  hr
  say "Containers / pods on this host (read-only inspection via /proc/<pid>/root; nothing executed inside):"
  declare -A NS_PIDS
  for pid in "${!P_EXE[@]}"; do
    [ "${P_HOST[$pid]:-1}" = "0" ] || continue
    is_php_proc "$pid" || continue
    ns="$(readlink "/proc/$pid/ns/mnt" 2>/dev/null)" || continue
    NS_PIDS[$ns]="${NS_PIDS[$ns]:-} $pid"
  done
  [ ${#NS_PIDS[@]} -eq 0 ] && say "   no PHP processes found in containers"
  for ns in "${!NS_PIDS[@]}"; do
    # shellcheck disable=SC2206
    pids=(${NS_PIDS[$ns]})
    rep="$(printf '%s\n' "${pids[@]}" | sort -n | head -n1)"
    root="/proc/$rep/root"
    if [ ! -r "$root/" ]; then say "   [pid $rep] container root not readable (run as root)"; continue; fi
    cid="$(container_id_of "$rep")"; cname="$(container_name_of "$cid")"
    exe_in="${P_EXE[$rep]% (deleted)}"
    env_blob=""
    for q in "${pids[@]}"; do   # php-fpm overwrites its own environ (process title) - try all processes
      e="$(tr '\0' '\n' < "/proc/$q/environ" 2>/dev/null)"
      case "$e" in *PHP_VERSION=*|*PHP_INI_DIR=*) env_blob="$e"; break ;; esac
    done

    # --- version (env -> headers -> package DB -> binary strings)
    ver=""; vsrc=""
    ver="$(printf '%s\n' "$env_blob" | sed -n 's/^PHP_VERSION=//p' | head -n1)"; [ -n "$ver" ] && vsrc="env PHP_VERSION"
    if [ -z "$ver" ]; then
      for h in "$root"/usr/local/include/php/main/php_version.h "$root"/usr/include/php*/php/main/php_version.h "$root"/usr/include/php/main/php_version.h; do
        [ -r "$h" ] || continue
        ver="$(sed -n 's/^#define PHP_VERSION "\(.*\)"/\1/p' "$h" | head -n1)"; [ -n "$ver" ] && { vsrc="php_version.h"; break; }
      done
    fi
    pkg="unpackaged"; pver=""; porigin=""; pcl="n/a"
    owner=""
    if [ -d "$root/var/lib/dpkg/info" ]; then
      owner="$(grep -lxF "$exe_in" "$root"/var/lib/dpkg/info/*.list 2>/dev/null | head -n1)"
      owner="$(basename "${owner%.list}" 2>/dev/null)"; owner="${owner%%:*}"
    fi
    if [ -n "$owner" ] && [ -r "$root/var/lib/dpkg/status" ]; then
      line="$(awk -v RS= -v P="$owner" '$0 ~ ("^Package: " P "\n") {v=$0; sub(/.*\nVersion: /,"",v); sub(/\n.*/,"",v); m=$0; if (m ~ /\nMaintainer: /) {sub(/.*\nMaintainer: /,"",m); sub(/\n.*/,"",m)} else m=""; print v"|"m; exit}' "$root/var/lib/dpkg/status" 2>/dev/null)"
      pkg="$owner"; pver="${line%%|*}"; porigin="${line#*|}"
      case "$pver" in *sury*) porigin="deb.sury.org ($porigin)";; esac
      src="${pkg%-*}"; pcl="changelog-unavailable"
      for d in "$root/usr/share/doc/$pkg" "$root/usr/share/doc/$src-common" "$root/usr/share/doc/$src"; do
        if [ -r "$d/changelog.Debian.gz" ]; then
          if zcat "$d/changelog.Debian.gz" 2>/dev/null | grep -qE 'CVE-2026-10961[89]'; then pcl="mentions-cve"; else pcl="not-mentioned"; fi
          break
        fi
      done
      [ -z "$ver" ] && { ver="$(printf '%s' "$pver" | sed -n 's/^\([0-9]*:\)\{0,1\}\([0-9]\+\.[0-9]\+\.[0-9]\+\).*/\2/p')"; vsrc="dpkg"; }
    elif [ -r "$root/lib/apk/db/installed" ] && [ "${exe_in#/usr/local/}" = "$exe_in" ]; then
      line="$(awk -v RS= '/\nP:php[0-9]+(-fpm|-cgi|-common)?\n/ {p=$0; sub(/.*\nP:/,"",p); sub(/\n.*/,"",p); v=$0; sub(/.*\nV:/,"",v); sub(/\n.*/,"",v); print p"|"v; exit}' "$root/lib/apk/db/installed" 2>/dev/null)"
      if [ -n "$line" ]; then
        pkg="${line%%|*}"; pver="${line#*|}"; porigin="alpine"; pcl="check-secdb"
        [ -z "$ver" ] && { ver="${pver%%-r*}"; vsrc="apk"; }
      fi
    elif [ -d "$root/var/lib/rpm" ] && [ "${exe_in#/usr/local/}" = "$exe_in" ] && [ -z "$owner" ]; then
      pkg="rpm-package"; porigin="rpm-based image"; pcl="unknown (rpm DB not read without executing rpm)"
    fi
    if [ -z "$ver" ] && [ -r "$root$exe_in" ]; then
      ver="$(grep -a -m1 -oE 'X-Powered-By: PHP/[0-9]+\.[0-9]+\.[0-9]+' "$root$exe_in" 2>/dev/null | head -n1 | sed 's/.*PHP\///')"
      [ -n "$ver" ] && vsrc="binary string"
    fi
    if [ -z "$ver" ]; then
      for lp in "$root"/usr/lib/apache2/modules/libphp*.so "$root"/usr/lib64/httpd/modules/libphp*.so "$root"/usr/local/lib/libphp*.so; do
        [ -r "$lp" ] || continue
        ver="$(grep -a -m1 -oE 'X-Powered-By: PHP/[0-9]+\.[0-9]+\.[0-9]+' "$lp" 2>/dev/null | head -n1 | sed 's/.*PHP\///')"
        [ -n "$ver" ] && { vsrc="libphp string"; break; }
      done
    fi
    br="$(branch_of "$ver")"
    case " $SUPPORTED_BRANCHES " in *" $br "*) bstate="upstream-supported" ;; *) bstate="upstream-EOL" ;; esac
    [ -n "$ver" ] || bstate="unknown"
    fs="$(fix_status "$ver" "$pcl" "$porigin" "$pkg")"
    case "$fs" in patched*) ;; *) ANY_UNPATCHED=1 ;; esac

    # --- session.upload_progress.enabled parsed from ini + pool files (last one wins; default On)
    ini_dir="$(printf '%s\n' "$env_blob" | sed -n 's/^PHP_INI_DIR=//p' | head -n1)"
    kind="cli"; case "$(basename "$exe_in")" in php-fpm*) kind="fpm" ;; php-cgi*) kind="cgi" ;; httpd|apache2) kind="apache2" ;; esac
    files=(); layout="distro"
    case "$exe_in" in /usr/local/*) layout="source-build" ;; esac
    [ -n "$ini_dir" ] && layout="source-build"
    if [ "$layout" = "source-build" ]; then   # official php images and other /usr/local builds
      ini_dir="${ini_dir:-/usr/local/etc/php}"
      files+=("$root$ini_dir/php.ini" "$root$ini_dir"/conf.d/*.ini)
    else
      files+=("$root/etc/php.ini" "$root"/etc/php.d/*.ini)
      for d in "$root"/etc/php/*/"$kind"; do files+=("$d/php.ini" "$d"/conf.d/*.ini); done
      for d in "$root"/etc/php[78]*; do [ -d "$d" ] && files+=("$d/php.ini" "$d"/conf.d/*.ini); done
    fi
    scan_env="$(printf '%s\n' "$env_blob" | sed -n 's/^PHP_INI_SCAN_DIR=//p' | head -n1)"
    for d in ${scan_env//:/ }; do files+=("$root$d"/*.ini); done
    pools=()
    if [ "$kind" = "fpm" ]; then
      if [ "$layout" = "source-build" ]; then
        pools+=("$root"/usr/local/etc/php-fpm.d/*.conf)
      else
        pools+=("$root"/etc/php/*/fpm/pool.d/*.conf "$root"/etc/php-fpm.d/*.conf "$root"/etc/php[78]*/php-fpm.d/*.conf)
      fi
    fi
    upe="On"; upsrc="PHP default"; seen=" "; cfgfiles=()
    for f in "${files[@]}" "${pools[@]+"${pools[@]}"}"; do
      [ -f "$f" ] || continue
      case "$seen" in *" $f "*) continue ;; esac; seen="$seen$f "
      cfgfiles+=("$f")
      v="$(grep -E '^[[:space:]]*(session\.upload_progress\.enabled[[:space:]]*=|php(_admin)?_(value|flag)\[session\.upload_progress\.enabled\][[:space:]]*=)' "$f" 2>/dev/null | tail -n1 | sed 's/^[^=]*=[[:space:]]*//')"
      [ -n "$v" ] && { upe="$(ini_bool "$v")"; upsrc="${f#"$root"}"; }
    done

    # --- running state of this container's PHP processes
    nm="$(newest_mtime "${cfgfiles[@]+"${cfgfiles[@]}"}")"
    eval_family "${nm%%|*}" "${nm#*|}" "${pids[@]}"
    STATE_TEXT="${STATE_TEXT//$root/}"
    [ "${STATE_TEXT%%:*}" = "STALE" ] && ANY_STALE=1

    NPHP=$((NPHP+1))
    if [ -n "$cname" ]; then label_c="$cname${cid:+ (id ${cid:0:12})}"
    elif [ -n "$cid" ]; then label_c="id ${cid:0:12}"
    else label_c="unidentified (mount namespace ${ns#mnt:})"; fi
    say "   Container: $label_c"
    say "      Process  : $(basename "$exe_in") x${#pids[@]} (host pid $rep, path in container $exe_in, layout $layout)"
    say "      Version  : ${ver:-unknown}${vsrc:+ (from $vsrc)}   branch ${br:-?}: $bstate"
    say "      Package  : $pkg ${pver} ${porigin:+[$porigin]}"
    say "      Fix      : $fs"
    say "      upload_progress.enabled: $upe (set in: $upsrc; parsed from files, not executed)"
    say "      Running  : $STATE_TEXT"
    CONT_JSON+=("{\"container_id\":$(json_str "$cid"),\"name\":$(json_str "$cname"),\"host_pid\":$rep,\"processes\":${#pids[@]},\"binary\":$(json_str "$exe_in"),\"version\":$(json_str "$ver"),\"version_source\":$(json_str "$vsrc"),\"branch_state\":$(json_str "$bstate"),\"package\":$(json_str "$pkg"),\"package_version\":$(json_str "$pver"),\"package_origin\":$(json_str "$porigin"),\"changelog_cve\":$(json_str "$pcl"),\"fix_status\":$(json_str "$fs"),\"upload_progress_enabled\":$(json_str "$upe"),\"upload_progress_source\":$(json_str "$upsrc"),\"runtime_state\":${STATE_JSON//$root/}}")
  done
fi

# Optional: exact values via docker/podman exec (executes php inside the container)
if [ "$CONTAINER_EXEC" -eq 1 ]; then
  hr
  say "Container exec check (php -r inside each running Docker/Podman container; CLI values):"
  for rt in docker podman; do
    have "$rt" || continue
    while IFS='|' read -r cid2 cimg; do
      [ -n "$cid2" ] || continue
      r="$($TIMEOUT "$rt" exec "$cid2" sh -c 'command -v php >/dev/null 2>&1 && php -r "echo PHP_VERSION,\"|\",ini_get(\"session.upload_progress.enabled\");"' 2>/dev/null)"
      [ -n "$r" ] || continue
      say "   [$rt] $cid2 $cimg -> PHP ${r%%|*}, session.upload_progress.enabled=${r#*|}"
      CONT_JSON+=("{\"exec_runtime\":$(json_str "$rt"),\"container_id\":$(json_str "$cid2"),\"image\":$(json_str "$cimg"),\"version\":$(json_str "${r%%|*}"),\"upload_progress_enabled_cli\":$(json_str "${r#*|}")}")
    done < <("$rt" ps --format '{{.ID}}|{{.Image}}' 2>/dev/null)
  done
fi

# --------------------------------------------------------------------------
# 7. Summary + JSON
# --------------------------------------------------------------------------
hr
if [ "$NPHP" -eq 0 ]; then
  RESULT="no-php-found"; RC=0
  say "RESULT: no PHP runtime found on this host."
elif [ "$ANY_UNPATCHED" -eq 1 ]; then
  RESULT="php-found-not-confirmed-patched"; RC=2
  say "RESULT: PHP found - at least one runtime is NOT confirmed patched against $CVES."
  [ "$ANY_STALE" -eq 1 ] && say "        ATTENTION: running processes do not use the current config/binary - see 'Running' lines; reload/restart first."
  say "        Patch as soon as the fix is available for your package source; until then:"
  say "        session.upload_progress.enabled=0 (partial mitigation only), restrict exposure,"
  say "        enable the detection rules from the ORBITRON php2shell repository."
else
  RESULT="php-found-all-confirmed-patched"; RC=1
  say "RESULT: PHP found - all runtimes confirmed patched (by changelog/upstream version)."
  [ "$ANY_STALE" -eq 1 ] && say "        ATTENTION: some running processes use an older config - see 'Running' lines."
fi

join() { local IFS=,; printf '%s' "$*"; }
JSON="{\"tool\":\"orbitron-php2shell-check\",\"tool_version\":$(json_str "$SCRIPT_VERSION"),\"cves\":[\"CVE-2026-109618\",\"CVE-2026-109619\"],\"timestamp\":$(json_str "$NOW"),\"host\":$(json_str "$HOSTNAME_S"),\"os\":$(json_str "$OS_NAME"),\"package_family\":$(json_str "$PKG_FAMILY"),\"fixed_upstream_configured\":$(json_str "$FIXED_UPSTREAM"),\"result\":$(json_str "$RESULT"),\"stale_runtime\":$([ "$ANY_STALE" -eq 1 ] && echo true || echo false),\"runtimes\":[$(join "${RUNTIME_JSON[@]+"${RUNTIME_JSON[@]}"}")],\"overrides\":[$(join "${OVR_JSON[@]+"${OVR_JSON[@]}"}")],\"processes\":[$(join "${PROC_JSON[@]+"${PROC_JSON[@]}"}")],\"containers\":[$(join "${CONT_JSON[@]+"${CONT_JSON[@]}"}")]}"

[ "$JSON_ONLY" -eq 1 ] && printf '%s\n' "$JSON"
if [ -n "$OUT_FILE" ]; then
  printf '%s\n' "$JSON" > "$OUT_FILE" && say "JSON report written to $OUT_FILE"
fi
exit "$RC"
