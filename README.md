# psi-implementation

PSI-CA, PSI, APSI-CA, APSI from Debnath & Dutta (ISC 2015).

## Build & Setup

```bash
make
./generate_dataset 1000 cards.txt
```

## Run


### Running Protocols

#### For `psi_ca`, `psi`, and `apsi`:
```bash
# Terminal 1
./psi_server <protocol>

# Terminal 2
./psi_client <protocol>
```

#### For `apsi_ca`:
```bash
# Terminal 1: Start the CA authority
./psi_ca_authority apsi_ca

# Terminal 2: Start the server
./psi_server apsi_ca

# Terminal 3: Start the client (provide CA host and port)
./psi_client apsi_ca <CA_HOST> <CA_PORT>
# Example:
# ./psi_client apsi_ca 127.0.0.1 9001
```

Protocols: `psi_ca` | `psi` | `apsi_ca` | `apsi`

## Testing GM

```bash
make test_gm
./test_gm
```

# Build and run:


make experiment
./experiment --protocol psi --client 50 --server 100
Override any setting via CLI — defaults come from config.hpp:


# PSI-CA, different sizes
./experiment --protocol psi_ca --client 200 --server 500

# Multiple runs, custom output file
./experiment --protocol psi --runs 5 --output bench.csv

# All defaults from config.hpp (no args needed)
./experiment
