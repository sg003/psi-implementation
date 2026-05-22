# psi-implementation

PSI-CA, PSI, APSI-CA, APSI from Debnath & Dutta (ISC 2015).

## Build & Setup

```bash
make
./generate_dataset 1000 cards.txt  # count must exceed your largest --client or --server size
```

## Configuration

Key parameters in `config.hpp`:

| Parameter | Default | Effect |
|---|---|---|
| `K` | 30 | BF hash count and φ output length. FPR = 1/2^K. Must be ≥ 30 for correct PSI results |
| `SERVER_SET_SIZE` | 100 | Default server set size |
| `CLIENT_SET_SIZE` | 50 | Default client set size |
| `SERVER_SEED` / `CLIENT_SEED` | 2 / 4 | Sampling seeds — controls overlap between sets |
| `EXP_PROTOCOL` | `"psi"` | Default protocol for `./experiment` |
| `EXP_RUNS` | 1 | Default number of runs |

## Running Protocols (manual)

### For `psi_ca`, `psi`, and `apsi`:
```bash
# Terminal 1
./psi_server <protocol>

# Terminal 2
./psi_client <protocol>
```

### For `apsi_ca`:
```bash
# Terminal 1: Start the CA authority (listens on port 9001)
./psi_ca_authority

# Terminal 2: Start the server
./psi_server apsi_ca

# Terminal 3: Start the client (provide CA host and port)
./psi_client apsi_ca 127.0.0.1 9001
```

Protocols: `psi_ca` | `psi` | `apsi_ca` | `apsi`

## Experiment Runner

Runs both client and server in-process over localhost. Records per-step timing, communication volume, and intersection correctness.

```bash
make experiment

# Single run with defaults from config.hpp
./experiment

# Specify protocol and set sizes
./experiment --protocol psi --client 100 --server 100

# PSI-CA with larger sets
./experiment --protocol psi_ca --client 200 --server 500

# Multiple runs (same seeds — measures timing variance)
./experiment --protocol psi --runs 5 --output bench.csv

# Custom dataset file
./experiment --protocol psi --dataset cards.txt
```

### Flags

| Flag | Default (config.hpp) |
|---|---|
| `--protocol` | `EXP_PROTOCOL` |
| `--client` | `CLIENT_SET_SIZE` |
| `--server` | `SERVER_SET_SIZE` |
| `--runs` | `EXP_RUNS` |
| `--output` | `EXP_OUTPUT` |
| `--dataset` | `DATASET_PATH` |

### Output files

- `results.csv` — appended after each run; columns: timing (ms), communication (bytes), result size, true intersection, false positives/negatives, FP rate
- `intersection_<protocol>_c<N>_s<M>_run<R>.txt` — intersection elements (PSI only)

### Communication cost at different bandwidths

The CSV includes `total_bytes`. To derive transmission time for a given bandwidth:

```
transmission_ms = (total_bytes × 8) / bandwidth_bps × 1000
total_time_ms   = compute_time_ms + transmission_ms
```

## Testing

```bash
./test_gm      # GM encryption unit tests
./test_client  # Bloom filter unit tests
```
# TO-DO

- update readme
- add random seeds and average results over multiple runs.
- add arguments --client-seed and --server-seed so that we can fix them for testing
- log seeds used in csv output for reproducibility