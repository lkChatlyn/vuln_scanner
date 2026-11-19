#!/usr/bin/env bash
# Run the vuln-rules profile against this host and every running container,
# then print one line per target and CVE, worst first.
#
# Exit code: 0 = everything PATCHED / MITIGATED / N/A
#            1 = at least one VULN, UNKNOWN or ERROR
#            2 = usage or missing tool
set -uo pipefail

usage() {
  cat <<EOF
Usage: $0 [-p profile] [-o outdir] [-n] [-a] [-v]
  -p  profile path or git URL (default: the directory this script is in)
  -o  report directory (default: ./reports/<timestamp>)
  -n  skip the host, scan containers only
  -a  also list N/A results (product not present)
  -v  also print Cinc Auditor's full output per target
EOF
}

PROFILE="$(cd "$(dirname "$0")" && pwd)"
OUT="./reports/$(date +%Y%m%d-%H%M%S)"
SCAN_HOST=1
SHOW_NA=0
VERBOSE=0
while getopts 'p:o:navh' opt; do
  case $opt in
    p) PROFILE=$OPTARG ;;
    o) OUT=$OPTARG ;;
    n) SCAN_HOST=0 ;;
    a) SHOW_NA=1 ;;
    v) VERBOSE=1 ;;
    h) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

for bin in cinc-auditor docker jq; do
  command -v "$bin" >/dev/null || { echo "missing: $bin" >&2; exit 2; }
done
mkdir -p "$OUT"
: > "$OUT/errors.tsv"

# name|target
targets=()
[ "$SCAN_HOST" = 1 ] && targets+=("_host|local://")
while read -r id name; do
  targets+=("$name|docker://$id")
done < <(docker ps --format '{{.ID}} {{.Names}}')

for t in "${targets[@]}"; do
  name=${t%%|*}
  target=${t#*|}
  report="$OUT/$name.json"
  echo "scanning $name" >&2

  if [ "$VERBOSE" = 1 ]; then
    cinc-auditor exec "$PROFILE" -t "$target" --no-color --reporter cli "json:$report" >&2
  else
    cinc-auditor exec "$PROFILE" -t "$target" --no-color --reporter "json:$report" >/dev/null 2>"$OUT/$name.err"
  fi
  rc=$?

  # 0 = all passed, 100 = some failed, 101 = some skipped; anything else is a crash
  case $rc in
    0|100|101) rm -f "$OUT/$name.err" ;;
    *)
      msg=$(tail -n 1 "$OUT/$name.err" 2>/dev/null)
      printf '%s\t-\tERROR\tcinc-auditor exit %s %s\n' "$name" "$rc" "$msg" >> "$OUT/errors.tsv"
      rm -f "$report"
      ;;
  esac
done

# One TSV row per result: target, CVE, state, reason
for f in "$OUT"/*.json; do
  [ -s "$f" ] || continue
  jq -r --arg t "$(basename "$f" .json)" '
    .profiles[].controls[] | .id as $id | .results[] | . as $r |
    if $r.status == "skipped" then
      [$t, $id, "N/A", (($r.skip_message // "") | sub("^Skipped control due to only_if condition: "; ""))]
    else
      (($r.code_desc | capture("^(?<s>[A-Z]+): (?<r>.*?) (is expected|should)"))
        // {s: "ERROR", r: ($r.message // $r.code_desc)}) as $m
      | [$t, $id, $m.s, $m.r]
    end | @tsv' "$f"
done > "$OUT/summary.tsv"
cat "$OUT/errors.tsv" >> "$OUT/summary.tsv"

if [ -t 1 ]; then RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; DIM=$'\e[2m'; RST=$'\e[0m'
else RED=''; YEL=''; GRN=''; DIM=''; RST=''; fi

echo
awk -F'\t' -v na="$SHOW_NA" '
  BEGIN { r["VULN"]=0; r["UNKNOWN"]=1; r["ERROR"]=2; r["MITIGATED"]=3; r["PATCHED"]=4; r["N/A"]=5 }
  $3 == "N/A" && na != 1 { next }
  { print r[$3] "\t" $0 }' "$OUT/summary.tsv" \
  | sort -t $'\t' -k1,1n -k3,3 -k2,2 \
  | cut -f2- \
  | awk -F'\t' -v red="$RED" -v yel="$YEL" -v grn="$GRN" -v dim="$DIM" -v rst="$RST" '
      BEGIN { printf "%-32s %-16s %-10s %s\n", "TARGET", "CVE", "STATE", "DETAIL" }
      {
        c = ($3 == "VULN") ? red : ($3 == "UNKNOWN" || $3 == "ERROR") ? yel : ($3 == "N/A") ? dim : grn
        printf "%-32s %-16s %s%-10s%s %s\n", $1, $2, c, $3, rst, $4
      }'

echo
echo "${#targets[@]} targets scanned, reports in $OUT" >&2

if awk -F'\t' '$3 == "VULN" || $3 == "UNKNOWN" || $3 == "ERROR" { bad=1 } END { exit !bad }' "$OUT/summary.tsv"; then
  exit 1
fi
exit 0
