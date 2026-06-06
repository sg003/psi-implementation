#!/usr/bin/env bash
set -e

BINARY="./experiment"
DATASET="cards.txt"
RUNS=5
K_FIXED=40

# ── Sweep A: set size sweep ───────────────────────────────────────────────────
# Covers: size vs communication, size vs timing, size vs FP rate
# All protocols, K fixed at 40, universe = 3x size → E[intersection] ≈ size/3

echo "=== Sweep A: set size (2^8 to 2^16, step 2^2) ==="

SIZE_EXPONENTS=(8 10 12 14 16)

for proto in apsi_ca apsi; do
    output="results_${proto}.csv"
    for exp in "${SIZE_EXPONENTS[@]}"; do
        size=$((1 << exp))
        universe=$((3 * size))
        printf "[sweep-A | %-8s] size=2^%02d (%7d)  " "$proto" "$exp" "$size"
        t0=$SECONDS
        "$BINARY" \
            --protocol "$proto"    \
            --client   "$size"     \
            --server   "$size" \
            -k         "$K_FIXED"  \
            --universe "$universe" \
            --runs     "$RUNS"     \
            --output   "$output"   \
            --dataset  "$DATASET"
        printf "done (%ds)\n" "$((SECONDS - t0))"
    done
    echo "Cooling down for 5 minutes..."
    sleep 300
done

# # ── Sweep B: K sweep ──────────────────────────────────────────────────────────
# # Covers: K vs FP rate
# # Fixed size 2^10, sweep K from 5 to 30

# echo ""
# echo "=== Sweep B: K sweep (5 to 30, step 5) at size=2^10 ==="

# K_VALUES=(15 20 25 30 35 40)
# K_SWEEP_SIZE=$((1 << 10))
# K_SWEEP_UNIVERSE=$((3 * K_SWEEP_SIZE))

# for proto in psi_ca psi apsi_ca apsi; do
#     output="results_k_${proto}.csv"
#     for k in "${K_VALUES[@]}"; do
#         printf "[sweep-B | %-8s] K=%2d  " "$proto" "$k"
#         t0=$SECONDS
#         "$BINARY" \
#             --protocol "$proto"             \
#             --client   "$K_SWEEP_SIZE"      \
#             --server   "$K_SWEEP_SIZE"      \
#             -k         "$k"                 \
#             --universe "$K_SWEEP_UNIVERSE"  \
#             --runs     "$RUNS"              \
#             --output   "$output"            \
#             --dataset  "$DATASET"
#         printf "done (%ds)\n" "$((SECONDS - t0))"
#     done
#     echo "Cooling down for 5 minutes..."
#     sleep 300
# done



# # ── Sweep C: client size sweep (server fixed at 2^14) ─────────────────────────
# # Covers: asymmetric set sizes — how client size affects timing/intersection
# # Server = 2^14, client varies 2^8 to 2^16, K = 40
# # Universe = 3 × max(server, client) so E[intersection] stays well-defined

# echo ""
# echo "=== Sweep C: client size sweep (server fixed at 2^14, client 2^8 to 2^16) ==="

# SERVER_FIXED=$((1 << 14))
# CLIENT_EXPONENTS=(8 10 12 14 16)

# for proto in psi_ca psi apsi_ca apsi; do
#     output="results_varying_client_${proto}.csv"
#     for exp in "${CLIENT_EXPONENTS[@]}"; do
#         client=$((1 << exp))
#         larger=$(( client > SERVER_FIXED ? client : SERVER_FIXED ))
#         universe=$((3 * larger))
#         printf "[sweep-C | %-8s] client=2^%02d (%6d)  " "$proto" "$exp" "$client"
#         t0=$SECONDS
#         "$BINARY" \
#             --protocol "$proto"        \
#             --client   "$client"       \
#             --server   "$SERVER_FIXED" \
#             -k         "$K_FIXED"      \
#             --universe "$universe"     \
#             --runs     "$RUNS"         \
#             --output   "$output"       \
#             --dataset  "$DATASET"
#         printf "done (%ds)\n" "$((SECONDS - t0))"
#     done
#     echo "Cooling down for 5 minutes..."
#     sleep 300
# done

# # ── Sweep D: server size sweep (client fixed at 2^14) ─────────────────────────
# # Covers: asymmetric set sizes — how server size affects timing/communication
# # Client = 2^14, server varies 2^8 to 2^16, K = 40
# # Universe = 3 × max(client, server) so E[intersection] stays well-defined

# echo ""
# echo "=== Sweep D: server size sweep (client fixed at 2^14, server 2^8 to 2^16) ==="

# CLIENT_FIXED=$((1 << 14))
# SERVER_EXPONENTS=(8 10 12 14 16)

# for proto in psi_ca psi apsi_ca apsi; do
#     output="results_varying_server_${proto}.csv"
#     for exp in "${SERVER_EXPONENTS[@]}"; do
#         server=$((1 << exp))
#         larger=$(( server > CLIENT_FIXED ? server : CLIENT_FIXED ))
#         universe=$((3 * larger))
#         printf "[sweep-D | %-8s] server=2^%02d (%6d)  " "$proto" "$exp" "$server"
#         t0=$SECONDS
#         "$BINARY" \
#             --protocol "$proto"        \
#             --client   "$CLIENT_FIXED" \
#             --server   "$server"       \
#             -k         "$K_FIXED"      \
#             --universe "$universe"     \
#             --runs     "$RUNS"         \
#             --output   "$output"       \
#             --dataset  "$DATASET"
#         printf "done (%ds)\n" "$((SECONDS - t0))"
#     done
#     echo "Cooling down for 5 minutes..."
#     sleep 300
# done

# echo ""
# echo "Output files:"
# echo "  Sweep A: results_<proto>.csv / results_<proto>_avg.csv"
# echo "  Sweep B: results_k_<proto>.csv / results_k_<proto>_avg.csv"
# echo "  Sweep C: results_varying_client_<proto>.csv / results_varying_client_<proto>_avg.csv"
# echo "  Sweep D: results_varying_server_<proto>.csv / results_varying_server_<proto>_avg.csv"
