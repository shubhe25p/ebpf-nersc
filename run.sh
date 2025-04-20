#!/usr/bin/env bash
##############################################################################
# ior_benchmark.sh  —  Quiet but informative IOR benchmark runner
##############################################################################

set -euo pipefail
trap 'echo "ERROR on line $LINENO: $BASH_COMMAND" >&2' ERR

##############################################################################
# STEP 1/6 : Environment
##############################################################################
echo "STEP 1/6 : Setting environment …"

export LD_LIBRARY_PATH=/usr/lib64/mpi/gcc/openmpi4/lib64:${LD_LIBRARY_PATH:-}
export PATH=/usr/lib64/mpi/gcc/openmpi4/bin:$HOME/ior-4.0.0/src:$HOME/ebpf-nersc:${PATH}

# locate required commands
command -v mpirun >/dev/null
command -v ior    >/dev/null
sudo -n true 2>/dev/null || { echo "sudo needs a password; run 'sudo true' first." >&2; exit 1; }

MONITORS=(catch_mpiio.py fs-latency.v3.py fs-write-latency.py)
for py in "${MONITORS[@]}"; do [[ -f $py ]]; done

IOR_CMD="mpirun -n 2 ior -a MPIIO -b 16m -s 32 -F"

##############################################################################
# helper: run IOR 5×, return average seconds (date‑based timing; no GNU time)
##############################################################################
avg_ior() {
    local total=0                              # running sum (float via awk)
    for n in {1..5}; do
        tmp=$(mktemp)                          # capture output for diagnostics
        start=$(date +%s.%N)
        if ! $IOR_CMD >"$tmp" 2>&1; then
            echo "IOR run $n failed — full output:" >&2
            cat "$tmp" >&2
            rm -f "$tmp"
            return 1                           # triggers trap → abort script
        fi
        end=$(date +%s.%N)
        rm -f "$tmp"
        dur=$(awk -v s="$start" -v e="$end" 'BEGIN{print e-s}')
        total=$(awk -v t="$total" -v d="$dur" 'BEGIN{print t+d}')
    done
    awk -v s="$total" 'BEGIN{printf "%.3f", s/5}'
}

##############################################################################
# STEP 2/6 : Warm‑up (no output)
##############################################################################
echo "STEP 2/6 : Warm‑up (5 silent IOR runs) …"
for _ in {1..5}; do $IOR_CMD >/dev/null; done

##############################################################################
# STEP 3/6 : Baseline measurement
##############################################################################
echo "STEP 3/6 : Measuring baseline …"
baseline_time=$(avg_ior)
echo "baseline_time=${baseline_time}s"

##############################################################################
# STEP 4/6‑6/6 : Loop through monitors
##############################################################################
step=4
for py in "${MONITORS[@]}"; do
    echo "STEP ${step}/6 : Running ${py} monitor"
    ts=$(date +%Y%m%d_%H%M%S)
    log="${py%.*}_out.${ts}"

    echo "  → starting with sudo (log → ${log})"
    sudo python3 "$py" >"$log" 2>&1 &
    pid=$!

    avg=$(avg_ior)
    echo "  → ${py%.*}_ior_time=${avg}s"

    echo "  → sending Ctrl‑C to ${py} (PID ${pid})"
    sudo kill -INT "$pid"
    wait "$pid" 2>/dev/null || true
    echo "  → ${py} stopped; output saved in ${log}"
    echo
    step=$((step+1))
done

echo "All DONE ✔"
