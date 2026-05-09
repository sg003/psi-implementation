# psi-implementation

PSI-CA, PSI, APSI-CA, APSI from Debnath & Dutta (ISC 2015).

## Build & Setup

```bash
make
./generate_dataset 1000 cards.txt
```

## Run

```bash
# Terminal 1
./server <protocol>

# Terminal 2
./client <protocol>
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
