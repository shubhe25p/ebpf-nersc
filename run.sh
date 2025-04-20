#!/usr/bin/env bash
# ior_benchmark_quiet.sh
# Runs IOR baseline + three Python monitors, printing only essential info.
# On any failure you’ll see:  "Error on line <n>: <command>"

##############################################################################
# 0. Strict error handling with detailed error trap
##############################################################################
set -euo pipefail              # stop on first error / unset var / pipe failure
trap 'echo "Error on line $LINENO: $BASH_COMMAND" >&2' ERR

##############################################################################
# 1. Environment
##############################################################################
export LD_LIBRARY_PATH=/usr/lib64/mpi/gcc/openmpi4/lib64:${LD_LIBRARY_PATH:-}
export PATH=/usr/lib64/mpi/gcc/openmpi4/bin:$HOME/ior-4.0.0/src:$HOME/ebpf-nersc:${PATH}

##############################################################################
# 2. Locate required commands
##############################################################################
command -v mpirun >/dev/null
command -v ior    >/dev/null

for py in catch_mpiio.py fs-latency.v3.py fs-write-latency.py; do
    [[ -f $py ]]
done

IOR_CMD="mpirun -n 2 ior -a MPIIO -b 16m -s 32 -F"

##############################################################################
# 3. Helper: run IOR 5× and return average seconds (silently)
##############################################################################
##############################################################################
# Helper: run IOR 5× → average seconds
#   • prints nothing on success except the final average
#   • on ANY IOR error, shows full output then aborts
##############################################################################
avg_ior() {
    local total=0
    for n in {1..5}; do
        tmp=$(mktemp)
        # Run IOR; GNU time writes elapsed seconds to stdout
        if ! dur=$(time -f "%e" $IOR_CMD 1>"$tmp" 2>&1); then
            echo "IOR run $n failed — full output:" >&2
            cat "$tmp" >&2
            rm -f "$tmp"
            return 1           # triggers trap and stops the script
        fi
        rm -f "$tmp"
        total=$(awk -v a="$total" -v b="$dur" 'BEGIN{print a+b}')
    done
    awk -v s="$total" 'BEGIN{printf "%.3f", s/5}'
}


##############################################################################
# 4. Warm‑up (no output)
##############################################################################
for _ in {1..5}; do $IOR_CMD >/dev/null; done

##############################################################################
# 5. Baseline
##############################################################################
echo "Measuring baseline…"
baseline_time=$(avg_ior)
echo "baseline_time=${baseline_time}s"

##############################################################################
# 6. Loop through monitors
##############################################################################
for py in catch_mpiio.py fs-latency.v3.py fs-write-latency.py; do
    ts=$(date +%Y%m%d_%H%M%S)
    log="${py%.*}_out.${ts}"

    echo "Running ${py} (logging → ${log})"
    sudo python3 "$py" >"$log" 2>&1 &
    pid=$!

    avg=$(avg_ior)
    echo "${py%.*}_ior_time=${avg}s"

    kill -INT "$pid"
    wait "$pid" 2>/dev/null || true
done

echo "All done."
