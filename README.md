# PQC Signing Benchmark

[![Rust](https://github.com/hfunke/pqc_signing_benchmark/actions/workflows/rust.yml/badge.svg)](https://github.com/hfunke/pqc_signing_benchmark/actions/workflows/rust.yml)

A simple benchmark for comparing the performance of different post-quantum cryptography (PQC) signing algorithms. Written in Rust as a command line tool to ensure it runs on various operating systems.

## Algorithms

Three NIST-standardized algorithm families are compared:

| Family | Standard | Basis | Variants |
|---|---|---|---|
| **ML-DSA** | FIPS 204 | Lattice (Module-LWE) | 44, 65, 87 (security levels I–III) |
| **SPHINCS+** | FIPS 205 | Hash-based | SHA2/SHAKE × 128/192/256 × fast/small |
| **Falcon** | FIPS 206 | NTRU lattice | 512, 1024 (with/without padding) |

- **ML-DSA** (formerly CRYSTALS-Dilithium): lattice-based, good balance of key size and performance.
- **SPHINCS+**: stateless hash-based signatures, conservative security, larger signatures.
- **Falcon**: NTRU-lattice-based, very compact signatures, requires constant-time hardware.

## Prerequisites

- Rust toolchain ≥ 1.70 ([rustup.rs](https://rustup.rs))
- C compiler (for building the underlying C reference implementations via `pqcrypto`)

AVX2 (x86_64) and aarch64 NEON optimizations are used automatically if the CPU supports them.

## Build & Run

```bash
cargo build --release
cargo run --release
```

## Output

For each algorithm family a table is printed with the following metrics:

| Row | Description |
|---|---|
| Key Gen (ms/op) | Average time to generate a key pair |
| Sign (ms/op) | Average time to sign a message |
| Verify (ms/op) | Average time to verify a signature |
| Public Key (B) | Public key size in bytes |
| Secret Key (B) | Secret key size in bytes |
| Signature (B) | Signature size in bytes |

Example output (Apple M3, 10 cycles):

```
┌────────────────┬────────────┬────────────┬────────────┐
│                │  ML-DSA-44 │  ML-DSA-65 │  ML-DSA-87 │
├────────────────┼────────────┼────────────┼────────────┤
│ Key Gen (ms/op)│      0.027 │      0.040 │      0.054 │
│ Sign (ms/op)   │      0.063 │      0.095 │      0.123 │
│ Verify (ms/op) │      0.021 │      0.031 │      0.041 │
│ Public Key (B) │       1312 │       1952 │       2592 │
│ Secret Key (B) │       2560 │       4032 │       4896 │
│ Signature (B)  │       2420 │       3293 │       4595 │
└────────────────┴────────────┴────────────┴────────────┘
```

Notes:
* ML-DSA-65/87: The signature sizes in pqcrypto v0.18.1 are 3309 and 4627 bytes respectively — the FIPS 204 draft values (3293 / 4595) differ.

* Falcon-padded: The library buffers up to the respective maximum length (666 / 1280 bytes), not to separate, larger fixed values.

## Dependencies

- [`pqcrypto v0.18.1`](https://crates.io/crates/pqcrypto) — Rust bindings to the NIST PQC reference implementations in C
- [`indicatif v0.18`](https://crates.io/crates/indicatif) — progress bars
- [`cli-table v0.5`](https://crates.io/crates/cli-table) — terminal table rendering

## License

MIT license
