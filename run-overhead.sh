#!/usr/bin/env bash
##############################################################################
# ior_benchmark.sh – IOR baseline + three Python monitors
# ▸ date‑based timing (no external “time”)
# ▸ enables kernel.bpf_stats_enabled
# ▸ records bpftool prog list for each monitor and prints summary table
##############################################################################

set -euo pipefail
trap 'echo "ERROR on line $LINENO: $BASH_COMMAND" >&2' ERR

# ─── STEP 1 : Environment ───────────────────────────────────────────────────
echo "STEP 1/9 : Setting environment …"

export LD_LIBRARY_PATH=/usr/lib64/mpi/gcc/openmpi4/lib64:${LD_LIBRARY_PATH:-}
export PATH=$HOME/bpftool/src:/usr/lib64/mpi/gcc/openmpi4/bin:$HOME/ior-4.0.0/src:$HOME/ebpf-nersc:$HOME/bpftool/src:${PATH}

command -v mpirun   >/dev/null
command -v ior      >/dev/null
command -v bpftool  >/dev/null
sudo -n true 2>/dev/null || { echo "sudo needs a password; run 'sudo true' first." >&2; exit 1; }

MONITORS=(catch_mpiio.py fs-latency.v3.py fs-write-latency.py)
for py in "${MONITORS[@]}"; do [[ -f $py ]]; done

IOR_CMD="mpirun -n 2 ior -a MPIIO -b 16m -s 32 -F"

declare -A T           # timing summary
BPF_LOGS=()            # keep list of bpftool files for final table

# ─── helper: 5× IOR → average seconds (date timing) ─────────────────────────
avg_ior() {
  local total=0
  for run in {1..5}; do
    tmp=$(mktemp)
    start=$(date +%s.%N)
    if ! $IOR_CMD >"$tmp" 2>&1; then
      echo "IOR run $run failed — full output:" >&2
      cat "$tmp" >&2; rm -f "$tmp"; return 1
    fi
    end=$(date +%s.%N); rm -f "$tmp"
    dur=$(awk -v s="$start" -v e="$end" 'BEGIN{print e-s}')
    total=$(awk -v t="$total" -v d="$dur" 'BEGIN{print t+d}')
  done
  awk -v sum="$total" 'BEGIN{printf "%.3f", sum/5}'
}

# ─── STEP 2 : Enable BPF stats ──────────────────────────────────────────────
echo "STEP 2/9 : Enabling kernel.bpf_stats_enabled …"
sudo sysctl -qw kernel.bpf_stats_enabled=1

# ─── STEP 3 : Warm‑up ───────────────────────────────────────────────────────
echo "STEP 3/9 : Warm‑up (5 silent IOR runs) …"
for _ in {1..5}; do $IOR_CMD >/dev/null; done

# ─── STEP 4 : Baseline ──────────────────────────────────────────────────────
echo "STEP 4/9 : Measuring baseline …"
T[baseline]=$(avg_ior)
echo "baseline_time=${T[baseline]}s"

# ─── STEP 5‑8 : Monitor loops ──────────────────────────────────────────────
step=5
for py in "${MONITORS[@]}"; do
  echo "STEP ${step}/9 : Running monitor ${py}"
  ts=$(date +%Y%m%d_%H%M%S)
  run_log="${py%.*}_${ts}.log"
  bpf_log="${py%.*}_bpftool_${ts}.log"
  label=$(echo "${py%.py}" | sed 's/[^A-Za-z0-9]/_/g')

  echo "  • sudo python3 → ${run_log}"
  sudo python3 "$py" >"$run_log" 2>&1 &
  pid=$!

  avg=$(avg_ior); T["$label"]=$avg
  echo "  • ${label}_time=${avg}s"

  echo "  • capturing bpftool prog list → ${bpf_log}"
  sudo bpftool prog list >"$bpf_log"
  BPF_LOGS+=("$bpf_log")

  echo "  • sending SIGINT (10 s timeout)…"
  sudo kill -INT "$pid"
  for i in {1..10}; do
    if ! sudo kill -0 "$pid" 2>/dev/null; then echo "    ▸ exited after ${i}s"; break; fi
    sleep 1
  done
  if sudo kill -0 "$pid" 2>/dev/null; then echo "    ▸ still alive; SIGKILL"; sudo kill -9 "$pid"; wait "$pid" 2>/dev/null || true; fi
  echo
  step=$((step+1))
done

# ─── STEP 9 : Summary tables ───────────────────────────────────────────────
# Timing table
printf "\n%-18s" "baseline"
for py in "${MONITORS[@]}"; do printf "%-18s" "$(echo "${py%.py}" | sed 's/[^A-Za-z0-9]/_/g')"; done
printf "\n%-18s" "${T[baseline]}s"
for py in "${MONITORS[@]}"; do label=$(echo "${py%.py}" | sed 's/[^A-Za-z0-9]/_/g'); printf "%-18s" "${T[$label]}s"; done
printf "\n\n"

# BPF stats table header
printf "%-25s %-15s %-10s %-15s\n" "prog_name" "run_time_ns" "run_cnt" "avg_ns"

# parse each bpftool file
for bl in "${BPF_LOGS[@]}"; do
  awk '
  /^[0-9]+:/ {name=""; rt=""; cnt=""}
  / name /  {for(i=1;i<=NF;i++) if($i=="name") {name=$(i+1); break}}
  / run_time_ns / {for(i=1;i<=NF;i++){ if($i=="run_time_ns"){rt=$(i+1)}; if($i=="run_cnt"){cnt=$(i+1)} }}
  (name!="" && rt!="" && cnt!="" && cnt!=0){avg=rt/cnt; printf "%-25s %-15s %-10s %-15.1f\n", name, rt, cnt, avg}
  ' "$bl"
done

echo -e "\nSTEP 9/9 : All DONE ✔"
