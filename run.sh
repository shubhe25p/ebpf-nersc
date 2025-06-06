#!/usr/bin/env bash
##############################################################################
# ior_benchmark.sh – IOR baseline + three Python monitors
##############################################################################

set -euo pipefail
trap 'echo "ERROR on line $LINENO: $BASH_COMMAND" >&2' ERR

# ─── STEP 1 : Environment ───────────────────────────────────────────────────
echo "STEP 1/7 : Setting environment …"

export LD_LIBRARY_PATH=/usr/lib64/mpi/gcc/openmpi4/lib64:${LD_LIBRARY_PATH:-}
export PATH=/usr/lib64/mpi/gcc/openmpi4/bin:$HOME/ior-4.0.0/src:$HOME/ebpf-nersc:${PATH}

command -v mpirun >/dev/null
command -v ior    >/dev/null
sudo -n true 2>/dev/null || { echo "sudo needs a password; run 'sudo true' first." >&2; exit 1; }

MONITORS=(catch_mpiio.py fs-latency.v3.py fs-write-latency.py)
for py in "${MONITORS[@]}"; do [[ -f $py ]]; done

IOR_CMD="mpirun -n 2 ior -a MPIIO -b 16m -s 32 -F"

declare -A T        # associative array to collect final times

# ─── helper: 5× IOR → average seconds (date timing) ─────────────────────────
avg_ior() {
  local total=0
  for run in {1..5}; do
    tmp=$(mktemp)
    start=$(date +%s.%N)
    if ! $IOR_CMD >"$tmp" 2>&1; then
      echo "IOR run $run failed — full output:" >&2
      cat "$tmp" >&2
      rm -f "$tmp"
      return 1
    fi
    end=$(date +%s.%N)
    rm -f "$tmp"
    dur=$(awk -v s="$start" -v e="$end" 'BEGIN{print e-s}')
    total=$(awk -v t="$total" -v d="$dur" 'BEGIN{print t+d}')
  done
  awk -v sum="$total" 'BEGIN{printf "%.3f", sum/5}'
}

# ─── STEP 2 : Warm‑up ───────────────────────────────────────────────────────
echo "STEP 2/7 : Warm‑up (5 silent IOR runs) …"
for _ in {1..5}; do $IOR_CMD >/dev/null; done

# ─── STEP 3 : Baseline ──────────────────────────────────────────────────────
echo "STEP 3/7 : Measuring baseline …"
T[baseline]=$(avg_ior)
echo "baseline_time=${T[baseline]}s"

# ─── STEP 4‑7 : Monitors ────────────────────────────────────────────────────
step=4
for py in "${MONITORS[@]}"; do
  echo "STEP ${step}/7 : Running monitor ${py}"
  ts=$(date +%Y%m%d_%H%M%S)
  log="${py%.*}_${ts}.log"

  echo "  • starting with sudo → ${log}"
  sudo python3 "$py" >"$log" 2>&1 &
  pid=$!

  avg=$(avg_ior)
  label=$(echo "${py%.py}" | sed 's/[^A-Za-z0-9]/_/g')
  T["$label"]=$avg
  echo "  • ${label}_time=${avg}s"

  echo "  • sending SIGINT to PID ${pid} (up to 10 s)…"
  sudo kill -INT "$pid"

  for i in {1..10}; do
    if ! sudo kill -0 "$pid" 2>/dev/null; then
      echo "    ▸ exited after ${i}s"
      break
    fi
    sleep 1
  done

  if sudo kill -0 "$pid" 2>/dev/null; then
    echo "    ▸ still alive; SIGKILL"
    sudo kill -9 "$pid"
    wait "$pid" 2>/dev/null || true
  fi

  echo "  • monitor stopped; output saved in ${log}"
  echo
  step=$((step+1))
done

# ─── Summary table ──────────────────────────────────────────────────────────
printf "\n%-15s" "baseline"
for py in "${MONITORS[@]}"; do
  printf "%-15s" "$(echo "${py%.py}" | sed 's/[^A-Za-z0-9]/_/g')"
done
printf "\n%-15s" "${T[baseline]}s"
for py in "${MONITORS[@]}"; do
  label=$(echo "${py%.py}" | sed 's/[^A-Za-z0-9]/_/g')
  printf "%-15s" "${T[$label]}s"
done
printf "\n"

echo -e "\nSTEP 7/7 : All DONE ✔"
