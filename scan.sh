#!/usr/bin/env bash
# Run the vuln-rules profile against this host and every running container,
# then print the results grouped per container / host, worst first.
#
# Exit code: 0 = everything PATCHED / MITIGATED / N/A / SKIPPED
#            1 = at least one VULN, PARTIALLY_MITIGATED, UNKNOWN or ERROR
#            2 = usage or missing tool
set -uo pipefail

usage() {
  cat <<EOF
Usage: $0 [-p profile] [-o outdir] [-j jobs] [-f table|json] [-n] [-d] [-a] [-k] [-v]
  -p  profile path or git URL (default: the directory this script is in)
  -o  report directory (default: <script dir>/reports/<timestamp>)
  -j  targets to scan in parallel (default: 4; each needs ~150-200 MB RAM)
  -f  output format: table (default) or json (machine-readable, on stdout;
      always also written to <outdir>/summary.json)
  -n  skip the host, scan containers only
  -d  also list MITIGATED / PATCHED results (by default only counted per target)
  -a  also list N/A results (product not present)
  -k  keep the raw JSON report per target (large; deleted by default)
  -v  also print Cinc Auditor's full output per target
EOF
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE="$SCRIPT_DIR"
OUT="$SCRIPT_DIR/reports/$(date +%Y%m%d-%H%M%S)"
JOBS=4
FORMAT=table
SCAN_HOST=1
SHOW_NA=0
SHOW_ALL=0
KEEP_JSON=0
VERBOSE=0
while getopts 'p:o:j:f:ndakvh' opt; do
  case $opt in
    p) PROFILE=$OPTARG ;;
    o) OUT=$OPTARG ;;
    j) JOBS=$OPTARG ;;
    f) FORMAT=$OPTARG ;;
    n) SCAN_HOST=0 ;;
    d) SHOW_ALL=1 ;;
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
case $FORMAT in
  table|json) ;;
  *) echo "-f must be table or json" >&2; exit 2 ;;
esac
STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

for bin in cinc-auditor docker jq; do
  command -v "$bin" >/dev/null || { echo "missing: $bin" >&2; exit 2; }
done
mkdir -p "$OUT"
: > "$OUT/extra.tsv"

# Targets as "name|target". Replicas of the same deployment run the same image
# with the same config, so only one of them is scanned and listed:
#   - Swarm service    (label com.docker.swarm.service.name) + image
#   - Compose service  (labels com.docker.compose.project/.service) + image
# The name then becomes e.g. "windmill_worker (3 replicas)". Replicas on
# different images (mid rolling update) stay separate. Other containers are
# scanned one by one, even with the same image, since their config can differ.
# Remaining Swarm task/node IDs (web.1.olm76dous69alhgqa8m5pv2v8) are dropped
# from names so the table stays readable.
targets=()
[ "$SCAN_HOST" = 1 ] && targets+=("_host|local://")
ids=$(docker ps -q)
if [ -n "$ids" ]; then
  # shellcheck disable=SC2086
  docker inspect -f '{{.Id}}|{{.Name}}|{{.Image}}|{{index .Config.Labels "com.docker.swarm.service.name"}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}' $ids
fi | awk -F'|' '
  function set(v) { return v != "" && v != "<no value>" }
  {
    id = substr($1, 1, 12); name = $2; sub(/^\//, "", name)
    img = $3; sub(/^sha256:/, "", img); img = substr(img, 1, 12)
    if (set($4))      { key = "s|" $4 "|" img; label = $4 }
    else if (set($6)) { key = "c|" $5 "|" $6 "|" img; label = (set($5) ? $5 "-" : "") $6 }
    else              { key = "i|" id; label = name; gsub(/\.[a-z0-9]{25}/, "", label) }
    if (!(key in rep)) { rep[key] = id; lab[key] = label; kind[key] = substr(key, 1, 1); order[++n] = key; uses[label]++ }
    cnt[key]++; all[key] = all[key] (all[key] == "" ? "" : ",") id
  }
  END {
    for (i = 1; i <= n; i++) {
      k = order[i]; l = lab[k]
      if (uses[l] > 1 && kind[k] != "i") { split(k, p, "|"); l = l " img " p[length(p)] }
      if (cnt[k] > 1) l = l " (" cnt[k] " replicas)"
      print l "\t" rep[k] "\t" cnt[k] "\t" all[k]
    }
  }' > "$OUT/targets.tsv"

# targets.meta: name, kind, replicas, container IDs (for the JSON output)
# containers.map: every container ID -> target name (Go results found from the
# host are filed under the container they run in, replicas included)
: > "$OUT/containers.map"
if [ "$SCAN_HOST" = 1 ]; then printf '_host\thost\t1\t\n' > "$OUT/targets.meta"; else : > "$OUT/targets.meta"; fi
while IFS=$'\t' read -r short id count all; do
  # Keep names unique, since they are also report file names
  if printf '%s\n' "${targets[@]:-}" | cut -d'|' -f1 | grep -qxF "$short"; then
    short="$short.${id:0:6}"
  fi
  targets+=("$short|docker://$id")
  printf '%s\tcontainer\t%s\t%s\n' "$short" "$count" "$all" >> "$OUT/targets.meta"
  for c in ${all//,/ }; do printf '%s\t%s\n' "$c" "$short" >> "$OUT/containers.map"; done
done < "$OUT/targets.tsv"
rm -f "$OUT/targets.tsv"
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

# Results found on the host but belonging to a container ("[@<id>] ..." in the
# detail, from the Go rules) move to that container's group. Replicas report
# the same row, so duplicates are dropped.
awk -F'\t' -v OFS='\t' -v map="$OUT/containers.map" '
  BEGIN { while ((getline l < map) > 0) { split(l, a, "\t"); name[a[1]] = a[2] } }
  $4 ~ /^\[@[0-9a-f]+\] / {
    cid = substr($4, 3, index($4, "]") - 3)
    $4 = substr($4, index($4, "]") + 2)
    $1 = (cid in name) ? name[cid] : "container " cid
  }
  { print }' "$OUT/summary.tsv" | sort -u > "$OUT/summary.tmp" && mv "$OUT/summary.tmp" "$OUT/summary.tsv"
[ "$KEEP_JSON" = 1 ] || rm -f "$OUT"/*.json

containers=$(printf '%s\n' $ids | grep -c .)
if awk -F'\t' '$3 == "VULN" || $3 == "PARTIALLY_MITIGATED" || $3 == "UNKNOWN" || $3 == "ERROR" { bad=1 } END { exit !bad }' "$OUT/summary.tsv"; then
  rc=1
else
  rc=0
fi

# Machine-readable result, always written; printed instead of the table with -f json
version=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
jq -n --rawfile rows "$OUT/summary.tsv" --rawfile meta "$OUT/targets.meta" \
      --arg host "$(hostname)" --arg started "$STARTED" --arg version "$version" \
      --argjson duration "$(( $(date +%s) - start ))" --argjson containers "$containers" \
      --argjson show_na "$SHOW_NA" --argjson rc "$rc" '
  def rank: {"VULN": 0, "UNKNOWN": 1, "ERROR": 2, "PARTIALLY_MITIGATED": 3, "SKIPPED": 4,
             "MITIGATED": 5, "PATCHED": 6, "N/A": 7}[.] // 8;
  def tsv: split("\n") | map(select(length > 0) | split("\t"));
  def counts: group_by(.state) | map({(.[0].state): length}) | add // {};
  ($rows | tsv | map({target: .[0], cve: .[1], state: .[2], detail: .[3]})
         | map(select(.state != "N/A" or $show_na == 1))) as $r
  | ($meta | tsv | map({name: .[0], kind: .[1], replicas: (.[2] | tonumber),
                       container_ids: ((.[3] // "") | split(",") | map(select(length > 0)))})) as $m
  | ([$m[].name]) as $known
  | ($m + ([$r[].target] | unique | map(select(. as $t | $known | any(. == $t) | not))
           | map({name: ., kind: "container", replicas: 1, container_ids: []}))) as $all
  | [ $all[] | . as $t
      | ([$r[] | select(.target == $t.name) | del(.target)] | sort_by((.state | rank), .cve)) as $res
      | $t + { worst: (if ($res | length) == 0 then null else ($res | map(.state) | min_by(rank)) end),
               counts: ($res | counts),
               results: $res }
      | .display_name = .name
      | .name |= sub(" \\([0-9]+ replicas\\)$"; "") ] as $targets
  | { scanner: "vuln_scanner", profile_version: $version, host: $host,
      started_at: $started, duration_s: $duration, status: (if $rc == 0 then "ok" else "fail" end),
      totals: { targets: ($targets | length), containers: $containers, counts: ($r | counts) },
      targets: ($targets | sort_by(((.worst // "N/A") | rank), .name)) }' > "$OUT/summary.json"
rm -f "$OUT/targets.meta" "$OUT/containers.map"

if [ "$FORMAT" = json ]; then
  cat "$OUT/summary.json"
else
  if [ -t 1 ]; then RED=$'\e[31m'; YEL=$'\e[33m'; MAG=$'\e[35m'; GRN=$'\e[32m'; DIM=$'\e[2m'; RST=$'\e[0m'
  else RED=''; YEL=''; MAG=''; GRN=''; DIM=''; RST=''; fi

  # Grouped by target, worst target first. Problem rows (VULN, PARTIALLY_MITIGATED,
  # UNKNOWN, ERROR, SKIPPED) are always listed; MITIGATED / PATCHED only with -d,
  # N/A only with -a. Targets where no rule applies are left out (see totals).
  echo
  awk -F'\t' -v na="$SHOW_NA" '
    BEGIN { n = split("VULN UNKNOWN ERROR PARTIALLY_MITIGATED SKIPPED MITIGATED PATCHED N/A", o, " ")
            for (i = 1; i <= n; i++) r[o[i]] = i }
    $3 == "N/A" && na != 1 { next }
    NR == FNR { if (!($1 in worst) || r[$3] < worst[$1]) worst[$1] = r[$3]; next }
    { print worst[$1] "\t" $1 "\t" r[$3] "\t" $2 "\t" $3 "\t" $4 }' "$OUT/summary.tsv" "$OUT/summary.tsv" \
    | sort -t $'\t' -k1,1n -k2,2 -k3,3n -k4,4 \
    | awk -F'\t' -v all="$SHOW_ALL" -v red="$RED" -v yel="$YEL" -v mag="$MAG" -v grn="$GRN" -v dim="$DIM" -v rst="$RST" '
        function color(st) {
          return (st == "VULN") ? red : (st == "PARTIALLY_MITIGATED") ? yel : (st == "UNKNOWN" || st == "ERROR") ? mag : (st == "SKIPPED" || st == "N/A") ? dim : grn
        }
        function flush(   i, line, st, safe) {
          if (cur == "") return
          line = ""; safe = 1
          for (i = 1; i <= no; i++) {
            st = o[i]
            if (cnt[st]) line = line (line == "" ? "" : ", ") cnt[st] " " st
            if (cnt[st] && st != "MITIGATED" && st != "PATCHED" && st != "N/A") safe = 0
          }
          name = (cur == "_host") ? "Docker host" : cur
          printf "%s%s%s  %s%s\n", color(first), name, rst, line, safe ? "  " grn "ok" rst : ""
          for (i = 1; i <= m; i++) print rows[i]
          print ""
          m = 0; split("", cnt); shown++
        }
        BEGIN { no = split("VULN PARTIALLY_MITIGATED UNKNOWN ERROR SKIPPED MITIGATED PATCHED N/A", o, " ") }
        {
          if ($2 != cur) { flush(); cur = $2; first = $5 }
          cnt[$5]++
          problem = ($5 != "MITIGATED" && $5 != "PATCHED" && $5 != "N/A")
          if (problem || all == 1 || $5 == "N/A") {
            if ($4 == "-") rows[++m] = sprintf("    %s%-19s%s  %s", color($5), $5, rst, $6)
            else rows[++m] = sprintf("    %s%-19s%s  %-20s  %s", color($5), $5, rst, $4, $6)
          }
        }
        END {
          flush()
          if (shown == 0) print "Nothing to report: no rule applies to any target (use -a to see N/A)."
        }'

  # Totals, so the big picture fits on one line
  awk -F'\t' -v n="${#targets[@]}" -v c="$containers" -v host="$SCAN_HOST" '
    { seen[$1] = 1; if ($3 != "N/A") relevant[$1] = 1; if ($3 != "N/A") cnt[$3]++ }
    END {
      for (t in seen) if (!(t in relevant)) unaffected++
      line = n " targets (" c " containers" (host == 1 ? " + host" : "") ", one replica per service)"
      split("VULN PARTIALLY_MITIGATED UNKNOWN ERROR MITIGATED PATCHED SKIPPED", order, " ")
      for (i = 1; i <= 7; i++) if (cnt[order[i]]) line = line ", " cnt[order[i]] " " order[i]
      if (unaffected) line = line ", " unaffected " with no affected software"
      print line
    }' "$OUT/summary.tsv"
fi
echo "scanned in $(( $(date +%s) - start ))s ($JOBS parallel), results: $OUT/summary.json" >&2
exit "$rc"
