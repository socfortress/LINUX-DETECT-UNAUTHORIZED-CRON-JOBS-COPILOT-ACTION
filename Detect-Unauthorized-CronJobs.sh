#!/bin/bash
set -eu

ScriptName="Detect-Unauthorized-CronJobs"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/active-response/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart="$(date +%s)"
US=$'\037'

WriteLog(){ m="$1"; l="${2:-INFO}"; ts="$(date '+%Y-%m-%d %H:%M:%S%z')"; line="[$ts][$l] $m"; printf '%s\n' "$line" >&2; printf '%s\n' "$line" >> "$LogPath"; }
RotateLog(){ [ -f "$LogPath" ]||return 0; kb=$(awk -v s="$(wc -c <"$LogPath")" 'BEGIN{printf "%.0f", s/1024}'); [ "$kb" -le "$LogMaxKB" ]&&return 0; i=$((LogKeep-1)); while [ $i -ge 1 ]; do src="$LogPath.$i"; dst="$LogPath.$((i+1))"; [ -f "$src" ]&&mv -f "$src" "$dst"||true; i=$((i-1)); done; mv -f "$LogPath" "$LogPath.1"; }
escape_json(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

BeginNDJSON(){ TMP_AR="$(mktemp)"; TMP_SEEN="$(mktemp)"; }
Normalize(){ printf '%s' "$1" | tr '\t' ' ' | sed -E 's/  +/ /g; s/^ +//; s/ +$//'; }
ExtractExecPath(){
  awk '{
    for(i=1;i<=NF;i++){
      if($i ~ /^\// && $i !~ /^\*\/[0-9]/){print $i; exit}
    }
  }' <<<"$1" || true
}
Key(){ printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4"; }
SeenOrAdd(){ k="$1"; if grep -Fxq -- "$k" "$TMP_SEEN" 2>/dev/null; then return 0; else printf '%s\n' "$k" >> "$TMP_SEEN"; return 1; fi; }

AddRecord(){
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  source="$1"; path="$2"; user="$3"; sched="$4"; cmd="$5"; exe="$6"; reason="$7"
  ncmd="$(Normalize "$cmd")"
  k="$(Key "$source" "$path" "$exe" "$ncmd")"
  if ! SeenOrAdd "$k"; then
    printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"source":"%s","path":"%s","user":"%s","schedule":"%s","command":"%s","exec_path":"%s","reason":"%s"}\n' \
      "$ts" "$HostName" "$ScriptName" \
      "$(escape_json "$source")" "$(escape_json "$path")" "$(escape_json "$user")" \
      "$(escape_json "$sched")" "$(escape_json "$ncmd")" "$(escape_json "$exe")" "$(escape_json "$reason")" >> "$TMP_AR"
  fi
}

AddInfo(){ ts="$(date '+%Y-%m-%d %H:%M:%S%z')"; printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"ok","message":"%s"}\n' "$ts" "$HostName" "$ScriptName" "$(escape_json "$1")" >> "$TMP_AR"; }
AddError(){ ts="$(date '+%Y-%m-%d %H:%M:%S%z')"; printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"error","message":"%s"}\n' "$ts" "$HostName" "$ScriptName" "$(escape_json "$1")" >> "$TMP_AR"; }

CommitNDJSON(){
  if mv -f "$TMP_AR" "$ARLog" 2>/dev/null; then :; else
    mv -f "$TMP_AR" "$ARLog.new" 2>/dev/null || printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"error","message":"atomic move failed"}\n' "$(date '+%Y-%m-%d %H:%M:%S%z')" "$HostName" "$ScriptName" > "$ARLog.new"
  fi
  rm -f "$TMP_SEEN" 2>/dev/null || true
}

ParseCronLine(){
  raw="$1"; file="$2"
  L="$(Normalize "$raw")"
  parsed="$(awk -v line="$L" -v file="$file" -v US="$US" '
    function trim(s){sub(/^[ \t\r\n]+/,"",s); sub(/[ \t\r\n]+$/,"",s); return s}
    function join5(a,b,c,d,e){return a" "b" "c" "d" "e}
    function isCronField(f){
      return (f ~ /^(\*|([0-9]+))([,\-\/][0-9]+)*$/)
    }
    function fiveAreCron(t){ return isCronField(t[1]) && isCronField(t[2]) && isCronField(t[3]) && isCronField(t[4]) && isCronField(t[5]) }

    BEGIN{
      p=file; usr="root"; sched="@script"; cmd=line
      is_periodic = (file ~ /\/cron\.(daily|hourly|weekly|monthly)\//)
      is_crond   = (file ~ /\/cron\.d\//)
      is_crontab = (file ~ /\/crontab(s)?\//)

      if (is_periodic){ print p US usr US "@periodic" US cmd; exit }

      n=split(line, t, /[ \t]+/)
      macro=(t[1] ~ /^@(reboot|yearly|annually|monthly|weekly|daily|hourly)$/)

      if (is_crond){
        if (macro && n>=3){
          sched=t[1]; usr=t[2]; idx=index(line, t[3]); cmd=substr(line, idx)
        } else if (n>=7 && fiveAreCron(t)){
          sched=join5(t[1],t[2],t[3],t[4],t[5]); usr=t[6]; idx=index(line, t[7]); cmd=substr(line, idx)
        } else {
          usr="root"; sched="@script"; cmd=line
        }
      } else if (is_crontab){
        split(file, f, "/"); owner=f[length(f)]; if(length(owner)==0){owner="root"}
        if (macro && n>=2){
          usr=owner; sched=t[1]; idx=index(line, t[2]); cmd=substr(line, idx)
        } else if (n>=6 && fiveAreCron(t)){
          usr=owner; sched=join5(t[1],t[2],t[3],t[4],t[5]); idx=index(line, t[6]); cmd=substr(line, idx)
        } else {
          usr=owner; sched="@script"; cmd=line
        }
      } else {
        if (macro && n>=2){
          usr="root"; sched=t[1]; idx=index(line, t[2]); cmd=substr(line, idx)
        } else if (n>=6 && fiveAreCron(t)){
          usr="root"; sched=join5(t[1],t[2],t[3],t[4],t[5]); idx=index(line, t[6]); cmd=substr(line, idx)
        } else {
          usr="root"; sched="@script"; cmd=line
        }
      }
      print p US usr US trim(sched) US trim(cmd)
    }')"
  IFS="$US" read -r path usr sched cmd <<<"$parsed"
  exe="$(ExtractExecPath "$cmd")"
  if printf '%s\n' "$cmd" | grep -qE '(/tmp|/dev/shm|/home)'; then
    AddRecord "cron" "$path" "$usr" "$sched" "$cmd" "$exe" "Non-standard path in cron"
  fi
}
   

RotateLog
WriteLog "START $ScriptName"
BeginNDJSON

found=0
while IFS= read -r -d '' file; do
  [ -f "$file" ] || continue
  while IFS= read -r raw; do
    case "$raw" in ""|\#*) continue ;; esac
    ParseCronLine "$raw" "$file" && found=$((found+1)) || true
  done < "$file"
done < <(find /etc/cron* /var/spool/cron* -type f -print0 2>/dev/null || true)

if command -v systemctl >/dev/null 2>&1; then
  timers=$(systemctl list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print $3}' | grep '\.timer$' || true)
  for t in $timers; do
    svc="${t%.timer}.service"
    exec=$(systemctl show -p ExecStart "$svc" 2>/dev/null | cut -d= -f2- || true)
    [ -n "$exec" ] || continue
    if printf '%s\n' "$exec" | grep -qE '(/tmp|/dev/shm|/home)'; then
      exe="$(ExtractExecPath "$exec")"
      AddRecord "systemd_timer" "$svc" "root" "@systemd" "$exec" "$exe" "ExecStart in suspicious path"
      found=$((found+1))
    fi
  done
else
  AddError "systemctl not available"
fi

[ "$found" -eq 0 ] && AddInfo "No suspicious cron entries or timers detected"

CommitNDJSON
dur=$(( $(date +%s) - runStart ))
WriteLog "END $ScriptName in ${dur}s"
