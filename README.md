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

## Server TODO

- Receive GM public key: `recv_mpz(fd, pk.n)` then `recv_mpz(fd, pk.u)`
- Send server set size `v` as `uint32_t` via `send_all`
- Receive encrypted BF: `uint32_t` size prefix, then `m` ciphertexts via `recv_mpz`
- For each `si` in `X`: compute `k` hash indices, rerandomize those ciphertexts with `gm.rerandomize`
- Send back `v` groups of `k` ciphertexts via `send_mpz` — no size prefix, in order
