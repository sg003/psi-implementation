#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <cstdint>
#include <cstddef>

// ── Network ───────────────────────────────────────────────────────────────────
constexpr int      PSI_PORT      = 9999;
constexpr int      CA_PORT       = 9001;

// ── Bloom filter / protocol ───────────────────────────────────────────────────
// K doubles as the number of BF hash functions and the φ output length.
// False positive rate = 1/2^K.  K=30 → negligible collisions with ≤10k elements.
// inline (not constexpr) so experiment.cpp can set it at runtime via --k.
inline size_t      K             = 30;

// ── Set sizes ─────────────────────────────────────────────────────────────────
constexpr size_t   SERVER_SET_SIZE = 100;   // v  (server's sample from the universe)
constexpr size_t   CLIENT_SET_SIZE = 50;    // w  (client's sample from the universe)

// ── Sampling seeds ────────────────────────────────────────────────────────────
// Different seeds ensure partial overlap between client and server sets.
constexpr uint64_t SERVER_SEED   = 2;
constexpr uint64_t CLIENT_SEED   = 4;

// ── GM key size ───────────────────────────────────────────────────────────────
constexpr unsigned GM_KEY_BITS   = 2048;

// ── Dataset ───────────────────────────────────────────────────────────────────
constexpr const char* DATASET_PATH = "cards.txt";

// ── Experiment defaults (overridable via CLI args) ────────────────────────────
constexpr const char* EXP_PROTOCOL   = "psi";      // psi | psi_ca | apsi | apsi_ca
constexpr int         EXP_RUNS       = 1;
constexpr const char* EXP_OUTPUT     = "results.csv";

#endif
