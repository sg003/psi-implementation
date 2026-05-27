#!/usr/bin/env bash
set -e

BINARY="./experiment"
DATASET="cards.txt"
RUNS=5

# ── Sweep A: set size sweep ───────────────────────────────────────────────────
# Covers: size vs communication, size vs timing, size vs FP rate
# All protocols, K fixed at 30

echo "=== Sweep A: set size (2^8 to 2^20, step 2^4) ==="

SIZE_EXPONENTS=(8 10 12 14 16)
K_FIXED=30

for proto in psi psi_ca apsi apsi_ca; do
    output="results_${proto}.csv"
    for exp in "${SIZE_EXPONENTS[@]}"; do
        size=$((1 << exp))
        printf "[sweep-A | %-8s] size=2^%02d (%7d)  " "$proto" "$exp" "$size"
        t0=$SECONDS
        "$BINARY" \
            --protocol "$proto" \
            --client   "$size"  \
            --server   "$size"  \
            -k         "$K_FIXED" \
            --runs     "$RUNS"  \
            --output   "$output" \
            --dataset  "$DATASET"
        printf "done (%ds)\n" "$((SECONDS - t0))"
    done
done

# ── Sweep B: K sweep ──────────────────────────────────────────────────────────
# Covers: K vs FP rate
# Fixed size 2^10, sweep K from 5 to 30

echo ""
echo "=== Sweep B: K sweep (5 to 30, step 5) at size=2^10 ==="

K_VALUES=(5 10 15 20 25 30)
K_SWEEP_SIZE=$((1 << 10))

for proto in psi psi_ca; do
    output="results_k_${proto}.csv"
    for k in "${K_VALUES[@]}"; do
        printf "[sweep-B | %-8s] K=%2d  " "$proto" "$k"
        t0=$SECONDS
        "$BINARY" \
            --protocol "$proto"        \
            --client   "$K_SWEEP_SIZE" \
            --server   "$K_SWEEP_SIZE" \
            -k         "$k"            \
            --runs     "$RUNS"         \
            --output   "$output"       \
            --dataset  "$DATASET"
        printf "done (%ds)\n" "$((SECONDS - t0))"
    done
done

echo ""
echo "Output files:"
echo "  Sweep A: results_<proto>.csv / results_<proto>_avg.csv"
echo "  Sweep B: results_k_<proto>.csv / results_k_<proto>_avg.csv"
