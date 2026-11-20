# shellcheck shell=bash
# One scan at a time on the MacBook, plus a memory brake (MS-4030). Sourced by scan.sh and
# scans/containers/rescan.sh (TOOLS=bin); every opengrep, trivy and syft run on the Mac goes through it.
# 19.11.2026: two agent runs started scan.sh at the same time, each opengrep took about 850 MB,
# the Mac (16 GB) swapped 1 GB more within 10 minutes, load 280, the Multica server stopped answering.
#
#   scan_guard <name>   returns 0 with the lock held (released when the script exits),
#                       75 when the memory brake or the lock wait gave up (alarm sent, lock not held)
#
# Lock: mkdir of SCAN_LOCK_DIR (default ~/.local/state/cyber-security/scan.lock) with the holder's
# pid, start time and name inside. A second scan waits until the holder is done; a holder whose
# pid is gone (or reused by another process) is stale and its lock is taken over.
# Memory brake, checked with the lock held: free memory below SCAN_MEM_MIN_FREE_PCT (20, as
# memory_pressure reports it) -> wait up to SCAN_MEM_WAIT seconds (900), then give up and report to
# the alarm intake (alarm-digest.py melden cyber-security scan-gebremst). Without a readable value
# the brake does not hold the scan. Swap is only logged, never a reason to wait: macOS keeps swap
# files allocated until reboot, so after days of uptime the used swap stays above any fixed limit
# while memory is free (MS-4099, 20.11.2026: 12 days up, swap 4.9-5.2 GB at 33-38 % free, every
# rescan braked). Disk room for swap is guarded by mac-disk.sh.
# Outside macOS (GitHub Actions, sec-hub with its own /run/sec-scan.lock) a no-op, unless
# SCAN_LOCK_FORCE=1 (tests). SCAN_LOCK=0 switches both off.
# Env: SCAN_LOCK_WAIT (s, 10800), SCAN_LOCK_POLL (s, 10), SCAN_MEM_POLL (s, 30),
#      SCAN_LOCK_LOG (default scan-lock.log next to the lock), SCAN_ALARM (command replacing
#      alarm-digest.py, gets: melden cyber-security scan-gebremst <text>; tests).
# Every event is one line `scan-lock: event=<name> ...` on stderr and in SCAN_LOCK_LOG.

_scan_lock_dir='' _scan_lock_logfile=/dev/null
_scan_lock_log() {
  local line
  line="$(date '+%Y-%m-%dT%H:%M:%S%z') scan-lock: $* pid=$$"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$_scan_lock_logfile" 2>/dev/null || true
}
_scan_lock_start() { LC_ALL=C ps -o lstart= -p "$1" 2>/dev/null | sed 's/  */ /g; s/^ //; s/ $//'; }
_scan_lock_alarm() {
  if [ -n "${SCAN_ALARM:-}" ]; then
    "$SCAN_ALARM" melden cyber-security scan-gebremst "$1" >/dev/null 2>&1 || true
  else
    python3 "$HOME/.claude/scripts/alarm-digest.py" melden cyber-security scan-gebremst "$1" >/dev/null 2>&1 || true
  fi
}
# 0 = lock dir present and its holder alive (or just being written); 1 = stale or gone
_scan_lock_held() {
  local pid start age
  [ -d "$_scan_lock_dir" ] || return 1
  pid="$(cat "$_scan_lock_dir/pid" 2>/dev/null || true)"
  if [ -z "$pid" ]; then  # between mkdir and the pid file; stale only when that takes over 60 s
    age=$(( $(date +%s) - $(stat -f %m "$_scan_lock_dir" 2>/dev/null || stat -c %Y "$_scan_lock_dir" 2>/dev/null || date +%s) ))
    [ "$age" -lt 60 ]; return
  fi
  kill -0 "$pid" 2>/dev/null || return 1
  start="$(cat "$_scan_lock_dir/start" 2>/dev/null || true)"
  [ -z "$start" ] || [ "$start" = "$(_scan_lock_start "$pid")" ]
}
_scan_lock_holder() { tr '\n' ' ' < "$_scan_lock_dir/info" 2>/dev/null || echo unknown; }

scan_lock_release() {
  [ -n "$_scan_lock_dir" ] || return 0
  [ "$(cat "$_scan_lock_dir/pid" 2>/dev/null)" = "$$" ] && rm -rf "$_scan_lock_dir" \
    && _scan_lock_log "event=lock_released"
  _scan_lock_dir=
  return 0
}

_scan_mem_free_pct() { memory_pressure 2>/dev/null | LC_ALL=C awk -F': *' '/free percentage/ {sub(/%.*/, "", $2); print int($2); exit}'; }
_scan_swap_used_mb() {
  sysctl -n vm.swapusage 2>/dev/null | LC_ALL=C awk '{for (i = 1; i < NF; i++) if ($i == "used") {
    v = $(i + 2); u = substr(v, length(v)); n = v + 0; if (u == "G") n *= 1024; print int(n); exit}}'
}
# prints the reason when memory is tight, nothing when the scan may start
_scan_mem_tight() {
  local free swap
  free="$(_scan_mem_free_pct)"; swap="$(_scan_swap_used_mb)"
  if [ -n "$free" ] && [ "$free" -lt "${SCAN_MEM_MIN_FREE_PCT:-20}" ]; then
    echo "free=${free}% (min ${SCAN_MEM_MIN_FREE_PCT:-20}%) swap=${swap:-?}MB"
  fi
}

scan_guard() {
  local name="${1:-scan}" t0 waited=0 reason holder
  [ "${SCAN_LOCK:-1}" != 0 ] || return 0
  [ "$(uname -s)" = Darwin ] || [ "${SCAN_LOCK_FORCE:-0}" = 1 ] || return 0
  _scan_lock_dir="${SCAN_LOCK_DIR:-$HOME/.local/state/cyber-security/scan.lock}"
  _scan_lock_logfile="${SCAN_LOCK_LOG:-$(dirname "$_scan_lock_dir")/scan-lock.log}"
  mkdir -p "$(dirname "$_scan_lock_dir")"
  # keep the log short: the last 2000 lines
  if [ "$(wc -l < "$_scan_lock_logfile" 2>/dev/null || echo 0)" -gt 4000 ]; then
    tail -n 2000 "$_scan_lock_logfile" > "$_scan_lock_logfile.tmp" && mv "$_scan_lock_logfile.tmp" "$_scan_lock_logfile"
  fi
  t0=$(date +%s)
  until mkdir "$_scan_lock_dir" 2>/dev/null; do
    if ! _scan_lock_held; then
      # rename first: of several waiters only one takes the stale lock away
      if mv "$_scan_lock_dir" "$_scan_lock_dir.stale.$$" 2>/dev/null; then
        _scan_lock_log "event=lock_stale name=\"$name\" holder=\"$(tr '\n' ' ' < "$_scan_lock_dir.stale.$$/info" 2>/dev/null)\""
        rm -rf "$_scan_lock_dir.stale.$$"
      fi
      continue
    fi
    if [ "$waited" = 0 ]; then
      waited=1; holder="$(_scan_lock_holder)"
      _scan_lock_log "event=lock_wait name=\"$name\" holder=\"${holder% }\""
    fi
    if [ $(( $(date +%s) - t0 )) -ge "${SCAN_LOCK_WAIT:-10800}" ]; then
      reason="Scan \"$name\" nicht gestartet: Sperre seit $(( ($(date +%s) - t0) / 60 )) min belegt von ${holder% }"
      _scan_lock_log "event=lock_timeout name=\"$name\""
      _scan_lock_alarm "$reason"; echo "$reason" >&2
      _scan_lock_dir=; return 75
    fi
    sleep "${SCAN_LOCK_POLL:-10}"
  done
  printf '%s\n' "$$" > "$_scan_lock_dir/pid"
  _scan_lock_start "$$" > "$_scan_lock_dir/start"
  printf 'name=%s pid=%s since=%s cwd=%s\n' "$name" "$$" "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$PWD" > "$_scan_lock_dir/info"
  trap scan_lock_release EXIT
  _scan_lock_log "event=lock_acquired name=\"$name\" waited_s=$(( $(date +%s) - t0 ))"

  t0=$(date +%s); waited=0
  while reason="$(_scan_mem_tight)"; [ -n "$reason" ]; do
    if [ "$waited" = 0 ]; then waited=1; _scan_lock_log "event=mem_wait name=\"$name\" $reason"; fi
    if [ $(( $(date +%s) - t0 )) -ge "${SCAN_MEM_WAIT:-900}" ]; then
      _scan_lock_log "event=mem_brake name=\"$name\" $reason"
      reason="Scan \"$name\" abgebrochen, Speicher knapp nach $(( ($(date +%s) - t0) / 60 )) min Warten: $reason"
      _scan_lock_alarm "$reason"; echo "$reason" >&2
      scan_lock_release; return 75
    fi
    sleep "${SCAN_MEM_POLL:-30}"
  done
  [ "$waited" = 0 ] || _scan_lock_log "event=mem_ok name=\"$name\" waited_s=$(( $(date +%s) - t0 ))"
  return 0
}
