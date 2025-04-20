#!/usr/bin/env bash
##############################################################################
# ior_benchmark.sh  –  Sequential IOR benchmark with three Python monitors
##############################################################################

set -euo pipefail
trap 'echo "ERROR on line $LINENO: $BASH_COMMAND" >&2' ERR

#
# STEP 1/7 ────────────────────────────────────────────────────────────────────
# Environment
#
echo "STEP 1/7 : Setting environment …"

export LD_LIBRARY_PATH=/usr/lib64/mpi/gcc/openmpi4/lib64:${LD_LIBRARY_PATH:-}
export PATH=/usr/lib64/mpi/gcc/openmpi4/bin:$HOME/ior-4.0.0/src:$HOME/ebpf-nersc:${PATH}

# Required commands & files --------------------------------------------------
command -v mpirun >/dev/null
command -v ior    >/dev/null
command -v time   >/dev/null          # POSIX 'time' with -p support

sudo -n true 2>/dev/null || { echo "sudo needs a password; run 'sudo true' first." >&2; exit 1; }

MONITORS=(catch_mpiio.py fs-latency.v3.py fs-write-latency.py)
for py in "${MONITORS[@]}"; do [[ -f $py ]]; done

IOR_CMD="mpirun -n 2 ior -a MPIIO -b 16m -s 32 -F"

#
# Helper: Run IOR 5×, return average seconds
#
avg_ior() {
    local total=0
    for n in {1..5}; do
        # Capture both the command's status and 'time' output
        out=$( { time -p $IOR_CMD 1>/dev/null; } 2>&1 ) || {
            echo "IOR run $n failed — full output:" >&2
            echo "$out" >&2
            return 1
        }
        dur=$(echo "$out" | awk '/^real / {print $2}')
        total=$(awk -v a="$total" -v b="$dur" 'BEGIN{print a+b}')
    done
    awk -v s="$total" 'BEGIN{printf "%.3f", s/5}'
}

#
# STEP 2/7 ────────────────────────────────────────────────────────────────────
# Warm‑up (silent)
#
echo "STEP 2/7 : Warm‑up (5 silent IOR runs) …"
for _ in {1..5}; do $IOR_CMD >/dev/null; done

#
# STEP 3/7 ────────────────────────────────────────────────────────────────────
# Baseline
#
echo "STEP 3/7 : Measuring baseline …"
baseline_time=$(avg_ior)
echo "baseline_time=${baseline_time}s"

#
# STEP 4–7 ────────────────────────────────────────────────────────────────────
# Loop over monitors
#
step=4
for py in "${MONITORS[@]}"; do
    echo "STEP ${step}/7 : Running monitor ${py}"
    ts=$(date +%Y%m%d_%H%M%S)
    log="${py%.*}_${ts}.log"

    echo "  • starting with sudo → ${log}"
    sudo python3 "$py" >"$log" 2>&1 &
    pid=$!

    avg=$(avg_ior)
    echo "  • ${py%.*}_ior_time=${avg}s"

    echo "  • sending Ctrl‑C (SIGINT) to PID ${pid}"
    sudo kill -INT "$pid"
    wait "$pid" 2>/dev/null || true
    echo "  • monitor stopped; output saved in ${log}"
    echo

    step=$((step+1))
done

echo "STEP 7/7 : All DONE ✔"
