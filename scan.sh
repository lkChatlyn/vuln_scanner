#!/usr/bin/env bash
# Run the vuln-rules profile against this host and every running container,
# then print one line per target and CVE, worst first.
#
# Exit code: 0 = everything PATCHED / MITIGATED / N/A / SKIPPED
#            1 = at least one VULN, PARTIALLY_MITIGATED, UNKNOWN or ERROR
#            2 = usage or missing tool
set -uo pipefail

usage() {
  cat <<EOF
Usage: $0 [-p profile] [-o outdir] [-j jobs] [-n] [-a] [-k] [-v]
  -p  profile path or git URL (default: the directory this script is in)
  -o  report directory (default: <script dir>/reports/<timestamp>)
  -j  targets to scan in parallel (default: 4; each needs ~150-200 MB RAM)
  -n  skip the host, scan containers only
  -a  also list N/A results (product not present)
  -k  keep the raw JSON report per target (large; deleted by default)
  -v  also print Cinc Auditor's full output per target
EOF
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE="$SCRIPT_DIR"
OUT="$SCRIPT_DIR/reports/$(date +%Y%m%d-%H%M%S)"
JOBS=4
SCAN_HOST=1
SHOW_NA=0
KEEP_JSON=0
VERBOSE=0
while getopts 'p:o:j:nakvh' opt; do
  case $opt in
    p) PROFILE=$OPTARG ;;
    o) OUT=$OPTARG ;;
    j) JOBS=$OPTARG ;;
    n) SCAN_HOST=0 ;;
    a) SHOW_NA=1 ;;
    k) KEEP_JSON=1 ;;
    v) VERBOSE=1 ;;
    h) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
case $JOBS in
  ''|*[!0-9]*|0) echo "-j needs a positive number" >&2; exit 2 ;;
esac

for bin in cinc-auditor docker jq; do
  command -v "$bin" >/dev/null || { echo "missing: $bin" >&2; exit 2; }
done
mkdir -p "$OUT"
: > "$OUT/extra.tsv"

# Targets as "name|target". Swarm task names carry 25-character task and node
# IDs (web.1.olm76dous69alhgqa8m5pv2v8); drop them so the table stays readable.
targets=()
[ "$SCAN_HOST" = 1 ] && targets+=("_host|local://")
while read -r id name; do
  short=$(printf '%s' "$name" | sed -E 's/\.[a-z0-9]{25}//g')
  # Keep names unique, since they are also report file names
  if printf '%s\n' "${targets[@]:-}" | cut -d'|' -f1 | grep -qxF "$short"; then
    short="$short.${id:0:6}"
  fi
  targets+=("$short|docker://$id")
done < <(docker ps --format '{{.ID}} {{.Names}}')
[ "${#targets[@]}" -gt 0 ] || { echo "nothing to scan" >&2; exit 0; }

# Scan one "name|target". Runs in parallel, so each target writes only its own
# files; extra.tsv gets one short appended line, which is safe to share.
scan_one() {
  local name=${1%%|*} target=${1#*|}
  local report="$OUT/$name.json" log="$OUT/$name.log" rc msg

  # Cinc Auditor runs every check through sh. Minimal images (distroless,
  # scratch) have none, so say so instead of failing with an opaque error.
  case $target in
    docker://*)
      if ! docker exec "${target#docker://}" sh -c true >/dev/null 2>&1; then
        printf '%s\t-\tSKIPPED\tno shell in container (distroless/scratch image), cannot be checked\n' "$name" >> "$OUT/extra.tsv"
        echo "skipped  $name (no shell)" >&2
        return
      fi
      ;;
  esac

  local kind=container
  [ "$target" = local:// ] && kind=host

  echo "scanning $name" >&2
  if [ "$VERBOSE" = 1 ]; then
    cinc-auditor exec "$PROFILE" -t "$target" --no-color --input "target_kind=$kind" --reporter cli "json:$report" >"$log" 2>&1
  else
    cinc-auditor exec "$PROFILE" -t "$target" --no-color --input "target_kind=$kind" --reporter "json:$report" >/dev/null 2>"$log"
  fi
  rc=$?

  # 0 = all passed, 100 = some failed, 101 = some skipped; anything else is a crash
  case $rc in
    0|100|101) [ "$VERBOSE" = 1 ] || rm -f "$log" ;;
    *)
      msg=$(grep -v '^[[:space:]]*$' "$log" 2>/dev/null | tail -n 1 | cut -c1-200)
      printf '%s\t-\tERROR\tcinc-auditor exit %s: %s (see %s)\n' "$name" "$rc" "${msg:-no output}" "$log" >> "$OUT/extra.tsv"
      rm -f "$report"
      ;;
  esac
}
export -f scan_one
export OUT PROFILE VERBOSE

start=$(date +%s)
printf '%s\n' "${targets[@]}" | xargs -P "$JOBS" -I{} bash -c 'scan_one "$1"' _ {}

if [ "$VERBOSE" = 1 ]; then
  for t in "${targets[@]}"; do
    name=${t%%|*}
    [ -f "$OUT/$name.log" ] || continue
    printf '\n===== %s =====\n' "$name" >&2
    cat "$OUT/$name.log" >&2
  done
fi

# One TSV row per result: target, CVE, state, detail
for f in "$OUT"/*.json; do
  [ -s "$f" ] || continue
  jq -r --arg t "$(basename "$f" .json)" '
    .profiles[].controls[] | .id as $id | .results[] | . as $r |
    if $r.status == "skipped" then
      [$t, $id, "N/A", (($r.skip_message // "") | sub("^Skipped control due to only_if condition: "; ""))]
    else
      (($r.code_desc | capture("^(?<s>[A-Z_]+): (?<r>.*?) (is expected|should)"))
        // {s: "ERROR", r: ($r.message // $r.code_desc)}) as $m
      | [$t, $id, $m.s, ($m.r | gsub("[\t\n]"; " "))]
    end | @tsv' "$f"
done > "$OUT/summary.tsv"
cat "$OUT/extra.tsv" >> "$OUT/summary.tsv"
rm -f "$OUT/extra.tsv"
[ "$KEEP_JSON" = 1 ] || rm -f "$OUT"/*.json

if [ -t 1 ]; then RED=$'\e[31m'; YEL=$'\e[33m'; MAG=$'\e[35m'; GRN=$'\e[32m'; DIM=$'\e[2m'; RST=$'\e[0m'
else RED=''; YEL=''; MAG=''; GRN=''; DIM=''; RST=''; fi

echo
awk -F'\t' -v na="$SHOW_NA" '
  BEGIN { r["VULN"]=0; r["UNKNOWN"]=1; r["ERROR"]=2; r["PARTIALLY_MITIGATED"]=3; r["MITIGATED"]=4; r["PATCHED"]=5; r["SKIPPED"]=6; r["N/A"]=7 }
  $3 == "N/A" && na != 1 { next }
  { print r[$3] "\t" $0 }' "$OUT/summary.tsv" \
  | sort -t $'\t' -k1,1n -k3,3 -k2,2 \
  | cut -f2- \
  | awk -F'\t' -v red="$RED" -v yel="$YEL" -v mag="$MAG" -v grn="$GRN" -v dim="$DIM" -v rst="$RST" '
      { n++; t[n]=$1; c[n]=$2; s[n]=$3; d[n]=$4
        if (length($1) > w1) w1 = length($1); if (length($2) > w2) w2 = length($2); if (length($3) > w3) w3 = length($3) }
      END {
        if (n == 0) { print "Nothing to report: no rule applies to any target (use -a to see N/A)."; exit }
        if (w1 < 6) w1 = 6; if (w2 < 3) w2 = 3; if (w3 < 5) w3 = 5
        fmt = "%-" w1 "s  %-" w2 "s  %s%-" w3 "s%s  %s\n"
        printf fmt, "TARGET", "CVE", "", "STATE", "", "DETAIL"
        for (i = 1; i <= n; i++) {
          col = (s[i] == "VULN") ? red : (s[i] == "PARTIALLY_MITIGATED") ? yel : (s[i] == "UNKNOWN" || s[i] == "ERROR") ? mag : (s[i] == "SKIPPED" || s[i] == "N/A") ? dim : grn
          printf fmt, t[i], c[i], col, s[i], rst, d[i]
        }
      }'

# Totals, so the big picture fits on one line
echo
awk -F'\t' -v n="${#targets[@]}" '
  { seen[$1] = 1; if ($3 != "N/A") relevant[$1] = 1; if ($3 != "N/A") cnt[$3]++ }
  END {
    for (t in seen) if (!(t in relevant)) unaffected++
    line = n " targets"
    split("VULN PARTIALLY_MITIGATED UNKNOWN ERROR MITIGATED PATCHED SKIPPED", order, " ")
    for (i = 1; i <= 7; i++) if (cnt[order[i]]) line = line ", " cnt[order[i]] " " order[i]
    if (unaffected) line = line ", " unaffected " with no affected software"
    print line
  }' "$OUT/summary.tsv"
echo "scanned in $(( $(date +%s) - start ))s ($JOBS parallel), summary: $OUT/summary.tsv" >&2

if awk -F'\t' '$3 == "VULN" || $3 == "PARTIALLY_MITIGATED" || $3 == "UNKNOWN" || $3 == "ERROR" { bad=1 } END { exit !bad }' "$OUT/summary.tsv"; then
  exit 1
fi
exit 0
