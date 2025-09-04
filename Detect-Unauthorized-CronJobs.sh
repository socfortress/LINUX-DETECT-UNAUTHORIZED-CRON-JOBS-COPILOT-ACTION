#!/bin/sh
set -eu

ScriptName="Detect-Unauthorized-CronJobs"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart="$(date +%s)"
US="$(printf '\037')"  

WriteLog(){ m="$1"; l="${2:-INFO}"; ts="$(date '+%Y-%m-%d %H:%M:%S')"; line="[$ts][$l] $m"; printf '%s\n' "$line" >&2; printf '%s\n' "$line" >> "$LogPath"; }
RotateLog(){ [ -f "$LogPath" ]||return 0; kb=$(du -k "$LogPath" | awk '{print $1}'); [ "$kb" -le "$LogMaxKB" ]&&return 0; i=$((LogKeep-1)); while [ $i -ge 0 ]; do [ -f "$LogPath.$i" ]&&mv -f "$LogPath.$i" "$LogPath.$((i+1))"; i=$((i-1)); done; mv -f "$LogPath" "$LogPath.1"; }
iso_now(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
escape_json(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

BeginNDJSON(){ TMP_AR="$(mktemp)"; TMP_SEEN="$(mktemp)"; }
Normalize(){ printf '%s' "$1" | tr '\t' ' ' | sed -E 's/  +/ /g; s/^ +//; s/ +$//'; }
ExtractExecPath(){ awk '{for(i=1;i<=NF;i++){ if($i ~ /^\// && $i !~ /^\*\/[0-9]/){print $i; exit} }}'; }
Key(){ printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$(Normalize "$4")"; }
SeenOrAdd(){ k="$1"; if grep -Fxq -- "$k" "$TMP_SEEN" 2>/dev/null; then return 0; else printf '%s\n' "$k" >> "$TMP_SEEN"; return 1; fi; }

AddRecord(){
  ts="$(iso_now)"
  source="$1"; path="$2"; user="$3"; sched="$4"; cmd="$5"; exe="$6"; reason="$7"
  k="$(Key "$source" "$path" "$exe" "$cmd")"
  if ! SeenOrAdd "$k"; then
    printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"source":"%s","path":"%s","user":"%s","schedule":"%s","command":"%s","exec_path":"%s","reason":"%s"}\n' \
      "$ts" "$HostName" "$ScriptName" \
      "$(escape_json "$source")" "$(escape_json "$path")" "$(escape_json "$user")" \
      "$(escape_json "$(Normalize "$sched")")" "$(escape_json "$(Normalize "$cmd")")" \
      "$(escape_json "$exe")" "$(escape_json "$reason")" >> "$TMP_AR"
  fi
}
AddInfo(){ ts="$(iso_now)"; printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"info","message":"%s"}\n' "$ts" "$HostName" "$ScriptName" "$(escape_json "$1")" >> "$TMP_AR"; }
AddError(){ ts="$(iso_now)"; printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"error","message":"%s"}\n' "$ts" "$HostName" "$ScriptName" "$(escape_json "$1")" >> "$TMP_AR"; }

CommitNDJSON(){
  [ -s "$TMP_AR" ] || AddInfo "no_results"
  AR_DIR="$(dirname "$ARLog")"
  [ -d "$AR_DIR" ] || WriteLog "Directory missing: $AR_DIR (will attempt write anyway)" WARN
  if mv -f "$TMP_AR" "$ARLog"; then
    WriteLog "Wrote NDJSON to $ARLog" INFO
  else
    WriteLog "Primary write FAILED to $ARLog" WARN
    if mv -f "$TMP_AR" "$ARLog.new"; then
      WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
    else
      keep="/tmp/active-responses.$$.ndjson"
      cp -f "$TMP_AR" "$keep" 2>/dev/null || true
      WriteLog "Failed to write both $ARLog and $ARLog.new; saved $keep" ERROR
      rm -f "$TMP_AR" 2>/dev/null || true
      exit 1
    fi
  fi
  for p in "$ARLog" "$ARLog.new"; do
    if [ -f "$p" ]; then
      sz=$(wc -c < "$p" 2>/dev/null || echo 0)
      ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
      head1=$(head -n1 "$p" 2>/dev/null || true)
      WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
    fi
  done
  rm -f "$TMP_SEEN" 2>/dev/null || true
}

ParseCronLine(){
  raw="$1"; file="$2"
  L="$(Normalize "$raw")"
  parsed="$(awk -v line="$L" -v file="$file" -v US="$US" '
    function trim(s){sub(/^[ \t\r\n]+/,"",s); sub(/[ \t\r\n]+$/,"",s); return s}
    function join5(a,b,c,d,e){return a" "b" "c" "d" "e}
    function isCronField(f){return (f ~ /^(\*|([0-9]+))([,\-\/][0-9]+)*$/)}
    function fiveAreCron(t){return isCronField(t[1])&&isCronField(t[2])&&isCronField(t[3])&&isCronField(t[4])&&isCronField(t[5])}
    BEGIN{
      p=file; usr="root"; sched="@script"; cmd=line
      is_periodic = (file ~ /\/cron\.(daily|hourly|weekly|monthly)\//)
      is_crond   = (file ~ /\/cron\.d\//)
      is_crontab = (file ~ /\/crontab(s)?\//)
      if (is_periodic){ print p US usr US "@periodic" US cmd; exit }
      n=split(line, t, /[ \t]+/)
      macro=(t[1] ~ /^@(reboot|yearly|annually|monthly|weekly|daily|hourly)$/)
      if (is_crond){
        if (macro && n>=3){ sched=t[1]; usr=t[2]; idx=index(line, t[3]); cmd=substr(line, idx) }
        else if (n>=7 && fiveAreCron(t)){ sched=join5(t[1],t[2],t[3],t[4],t[5]); usr=t[6]; idx=index(line, t[7]); cmd=substr(line, idx) }
        else { usr="root"; sched="@script"; cmd=line }
      } else if (is_crontab){
        split(file, f, "/"); owner=f[length(f)]; if(length(owner)==0){owner="root"}
        if (macro && n>=2){ usr=owner; sched=t[1]; idx=index(line, t[2]); cmd=substr(line, idx) }
        else if (n>=6 && fiveAreCron(t)){ usr=owner; sched=join5(t[1],t[2],t[3],t[4],t[5]); idx=index(line, t[6]); cmd=substr(line, idx) }
        else { usr=owner; sched="@script"; cmd=line }
      } else {
        if (macro && n>=2){ usr="root"; sched=t[1]; idx=index(line, t[2]); cmd=substr(line, idx) }
        else if (n>=6 && fiveAreCron(t)){ usr="root"; sched=join5(t[1],t[2],t[3],t[4],t[5]); idx=index(line, t[6]); cmd=substr(line, idx) }
        else { usr="root"; sched="@script"; cmd=line }
      }
      print p US usr US trim(sched) US trim(cmd)
    }')"
  IFS="$US" read -r path usr sched cmd <<EOF
$parsed
EOF
  exe="$(printf '%s\n' "$cmd" | ExtractExecPath)"
  if printf '%s\n' "$cmd" | grep -qE '(/tmp|/dev/shm|/home)'; then
    AddRecord "cron" "$path" "$usr" "$sched" "$cmd" "$exe" "non-standard path in cron"
  fi
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="
BeginNDJSON

find /etc/cron* /var/spool/cron* -type f -print0 2>/dev/null | tr '\0' '\n' | while IFS= read -r file; do
  [ -f "$file" ] || continue
  while IFS= read -r raw || [ -n "$raw" ]; do
    case "$raw" in ""|\#*) continue ;; esac
    ParseCronLine "$raw" "$file" || true
  done < "$file"
done

if command -v systemctl >/dev/null 2>&1; then
  systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print $3}' | grep '\.timer$' 2>/dev/null | \
  while IFS= read -r t; do
    svc="${t%.timer}.service"
    exec=$(systemctl show -p ExecStart "$svc" 2>/dev/null | cut -d= -f2- || true)
    [ -n "$exec" ] || continue
    if printf '%s\n' "$exec" | grep -qE '(/tmp|/dev/shm|/home)'; then
      exe="$(printf '%s\n' "$exec" | ExtractExecPath)"
      AddRecord "systemd_timer" "$svc" "root" "@systemd" "$exec" "$exe" "ExecStart in suspicious path"
    fi
  done
else
  AddError "systemctl not available"
fi

CommitNDJSON
dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : ${dur}s ==="
