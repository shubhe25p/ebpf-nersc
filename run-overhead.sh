#!/usr/bin/env bash
##############################################################################
# ior_benchmark.sh – IOR baseline + three Python monitors (stats ON & OFF)
#   • Phase‑1 (stats ON): captures bpftool stats **per monitor**
#   • Phase‑2 (stats OFF): repeats runs without bpftool
#   • Prints timing table for both phases
#   • For phase‑1 prints one BPF table *per monitor*, deduplicated by program
##############################################################################

set -euo pipefail
trap 'echo "ERROR on line $LINENO: $BASH_COMMAND" >&2' ERR

# ───────── 0. Common setup ─────────────────────────────────────────────────
export LD_LIBRARY_PATH=/usr/lib64/mpi/gcc/openmpi4/lib64:${LD_LIBRARY_PATH:-}
export PATH=/usr/lib64/mpi/gcc/openmpi4/bin:$HOME/ior-4.0.0/src:$HOME/ebpf-nersc:$HOME/bpftool/src:${PATH}

command -v mpirun  >/dev/null
command -v ior     >/dev/null
command -v bpftool >/dev/null
sudo -n true 2>/dev/null || { echo "sudo needs a password; run 'sudo true' first." >&2; exit 1; }

# Updated monitor list ------------------------------------------------------
MONITORS=(catch_mpiio.py fs-latency.v3.py tp_read_iops.py)
for py in "${MONITORS[@]}"; do [[ -f $py ]]; done

IOR_CMD="mpirun -n 2 ior -a MPIIO -b 16m -s 32 -F"

declare -gA T_on=()       # timings with stats ON
declare -gA T_off=()      # timings with stats OFF
declare -gA BPF_FILE=()   # monitor label → bpftool log (phase‑1)

# ───────── helper: avg_ior() ───────────────────────────────────────────────
avg_ior() {
  local sum=0
  for _ in {1..5}; do
    tmp=$(mktemp)
    start=$(date +%s.%N)
    if ! $IOR_CMD >"$tmp" 2>&1; then echo "IOR run failed:" >&2; cat "$tmp" >&2; rm -f "$tmp"; return 1; fi
    end=$(date +%s.%N); rm -f "$tmp"
    dur=$(awk -v s="$start" -v e="$end" 'BEGIN{print e-s}')
    sum=$(awk -v a="$sum" -v b="$dur" 'BEGIN{print a+b}')
  done
  awk -v s="$sum" 'BEGIN{printf "%.3f", s/5}'
}

# ───────── function: run_phase(flag) ───────────────────────────────────────
run_phase() {
  local flag=$1
  local prefix=$([ "$flag" = "1" ] && echo "on" || echo "off")
  declare -n Tarr="T_${prefix}"

  echo -e "\n======== Phase ${prefix^^} (bpf_stats_enabled=${flag}) ========"
  sudo sysctl -qw kernel.bpf_stats_enabled=${flag}

  echo "  • Warm‑up (silent)"; for _ in {1..5}; do $IOR_CMD >/dev/null; done

  Tarr[baseline]=$(avg_ior); echo "  • baseline_${prefix}=${Tarr[baseline]}s"

  for py in "${MONITORS[@]}"; do
    label=$(echo "${py%.py}" | sed 's/[^A-Za-z0-9]/_/g')
    ts=$(date +%Y%m%d_%H%M%S)
    run_log="${label}_${prefix}_${ts}.log"

    echo "    · sudo python3 $py → ${run_log}"
    sudo python3 "$py" >"$run_log" 2>&1 &
    pid=$!

    Tarr[$label]=$(avg_ior); echo "    · ${label}_${prefix}=${Tarr[$label]}s"

    if [[ $flag == 1 ]]; then
      bpf_log="${label}_bpftool_${ts}.log"
      pushd "$HOME/bpftool/src" >/dev/null
      sudo bpftool prog list >"$OLDPWD/$bpf_log"
      popd >/dev/null
      BPF_FILE[$label]="$bpf_log"
    fi

    sudo kill -INT "$pid"
    for i in {1..10}; do
      if ! sudo kill -0 "$pid" 2>/dev/null; then break; fi
      sleep 1
    done
    if sudo kill -0 "$pid" 2>/dev/null; then echo "      killing hung monitor"; sudo kill -9 "$pid"; fi
    wait "$pid" 2>/dev/null || true
  done
}

# ───────── Run both phases ─────────────────────────────────────────────────
run_phase 1   # stats ON
run_phase 0   # stats OFF

# ───────── Timing summary table ────────────────────────────────────────────
printf "\nTiming (seconds)\n"
header=(baseline); for py in "${MONITORS[@]}"; do header+=( "$(echo "${py%.py}" | sed 's/[^A-Za-z0-9]/_/g')" ); done
printf "%-18s" ""; for h in "${header[@]}"; do printf "%-18s" "${h}_on"; done; for h in "${header[@]}"; do printf "%-18s" "${h}_off"; done; printf "\n"
printf "%-18s" "time"; for h in "${header[@]}"; do printf "%-18s" "${T_on[$h]:-NA}s"; done; for h in "${header[@]}"; do printf "%-18s" "${T_off[$h]:-NA}s"; done; printf "\n"

# ───────── BPF program tables (deduped) ────────────────────────────────────
for label in "${!BPF_FILE[@]}"; do
  log_file=${BPF_FILE[$label]}
  [[ -f $log_file ]] || continue
  printf "\nBPF runtimes for %s (stats enabled)\n" "$label"
  printf "%-25s %-15s %-10s %-15s\n" "prog_name" "run_time_ns" "run_cnt" "avg_ns"
  awk '
    /^[0-9]+:/ {
      name=""; rt=""; cnt="";
      for(i=1;i<=NF;i++){
        if($i=="name"){name=$(i+1)}
        if($i=="run_time_ns"){rt=$(i+1)}
        if($i=="run_cnt"){cnt=$(i+1)}
      }
      if(name!="" && rt!="" && cnt!="" && cnt!=0 && !seen[name]++){
        avg=rt/cnt;
        printf "%-25s %-15s %-10s %-15.1f\n", name, rt, cnt, avg
      }
    }' "$log_file"
done

echo -e "\nAll DONE ✔"