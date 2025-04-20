#!/usr/bin/env bash
# ior_benchmark.sh
set -euo pipefail

# --- 0. env setup ----------------------------------------------------------
export LD_LIBRARY_PATH=/usr/lib64/mpi/gcc/openmpi4/lib64:${LD_LIBRARY_PATH:-}
export PATH=/usr/lib64/mpi/gcc/openmpi4/bin:${PATH}
export PATH="$HOME/ior-4.0.0/src:$HOME/ebpf-nersc:${PATH}"

CMD="mpirun -n 2 ior -a MPIIO -b 16m -s 32 -F"

# sanity checks
command -v ior   >/dev/null || { echo "ior not in PATH"; exit 1; }
command -v mpirun>/dev/null || { echo "mpirun not in PATH"; exit 1; }
for py in catch_mpiio.py fs-latency.v3.py fs-write-latency.py; do
  [[ -f $py ]] || { echo "missing $py"; exit 1; }
done
command -v time >/dev/null || { echo "'time' command missing"; exit 1; }

# helper: run CMD 5× and echo average seconds
avg_ior() {
  local sum=0
  for i in {1..5}; do
    dur=$(time -f "%e" $CMD 1>/dev/null 2>&1)
    sum=$(awk -v a="$sum" -v b="$dur" 'BEGIN{print a+b}')
  done
  awk -v s="$sum" 'BEGIN{printf "%.3f\n", s/5}'
}

# --- 1. warm‑up ------------------------------------------------------------
echo "Warm‑up (5 runs)…"
for i in {1..5}; do $CMD >/dev/null; done

# --- 2. baseline -----------------------------------------------------------
echo "Measuring baseline…"
baseline_time=$(avg_ior)
echo "baseline_time=${baseline_time}s"

# --- 3. monitors -----------------------------------------------------------
for py in catch_mpiio.py fs-latency.v3.py fs-write-latency.py; do
  ts=$(date +%Y%m%d_%H%M%S)
  log="${py%.*}_out.${ts}"

  echo "=== ${py} ==="
  python3 "$py" >"$log" 2>&1 &
  pid=$!
  echo "PID $pid, logging to $log"

  avg=$(avg_ior)
  echo "${py%.*}_ior_time=${avg}s"

  echo "Stopping ${py}"
  kill -INT "$pid"
  wait "$pid" 2>/dev/null || true
  echo
done

echo "All done."
