#!/usr/bin/env bash
# ior_benchmark_verbose.sh
# Purpose: run IOR baselines and benchmarks while three Python monitors
#          are attached, with VERY verbose output.

##############################################################################
# 1. Strict error handling + command trace
##############################################################################
set -euo pipefail      # die on first error, unset var, or pipe failure
set -x                 # echo every command as it is executed
PS4='[$(date +%H:%M:%S)] '  # timestamp each traced line

##############################################################################
# 2. Environment
##############################################################################
export LD_LIBRARY_PATH=/usr/lib64/mpi/gcc/openmpi4/lib64:${LD_LIBRARY_PATH:-}
export PATH=/usr/lib64/mpi/gcc/openmpi4/bin:${PATH}
export PATH="$HOME/ior-4.0.0/src:$HOME/ebpf-nersc:${PATH}"

##############################################################################
# 3. Sanity checks
##############################################################################
command -v mpirun   >/dev/null
command -v ior      >/dev/null
command -v time >/dev/null
for py in catch_mpiio.py fs-latency.v3.py fs-write-latency.py; do
    [[ -f $py ]]
done

##############################################################################
# 4. Helper: run IOR five times and return average (prints each run)
##############################################################################
avg_ior() {
    local total=0
    for i in {1..5}; do
        echo "---- IOR run $i ----"
        # /usr/bin/time prints elapsed seconds (%e)
        local dur=$(time -f "%e" mpirun -n 2 ior -a MPIIO -b 16m -s 32 -F \
                    1>/dev/null 2>&1 | tee /dev/fd/2)
        echo "elapsed=${dur}s"
        total=$(awk -v a="$total" -v b="$dur" 'BEGIN{print a+b}')
    done
    awk -v t="$total" 'BEGIN{printf "%.3f", t/5}'
}

##############################################################################
# 5. Warm‑up (ignored timings)
##############################################################################
echo "========== WARM‑UP (5 runs) =========="
for i in {1..5}; do
    echo "-- warm‑up run $i --"
    mpirun -n 2 ior -a MPIIO -b 16m -s 32 -F >/dev/null
done

##############################################################################
# 6. Baseline measurement
##############################################################################
echo "========== BASELINE (5 runs) =========="
baseline_time=$(avg_ior)
echo "baseline_time=${baseline_time}s"

##############################################################################
# 7. Loop over Python monitors
##############################################################################
for py in catch_mpiio.py fs-latency.v3.py fs-write-latency.py; do
    ts=$(date +%Y%m%d_%H%M%S)
    log="${py%.*}_out.${ts}"

    echo "========== ${py} =========="
    echo "Starting ${py} (log → ${log})"
    python3 "$py" >"$log" 2>&1 &
    pid=$!
    echo "PID ${pid}"

    echo "----- Running IOR with ${py} active -----"
    avg=$(avg_ior)
    echo "${py%.*}_ior_time=${avg}s"

    echo "Stopping ${py} with SIGINT (Ctrl‑C)…"
    kill -INT "$pid"
    wait "$pid" 2>/dev/null || true
    echo "${py} stopped; output saved to ${log}"
done

echo "========== ALL DONE =========="
