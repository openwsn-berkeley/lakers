# edhoc-rs

A microcontroller-optimized implementation of EDHOC in Rust (`no_std`).

Supports:
* Roles: Initiator, Responder (hacspec only)
* Authentication mode: STAT-STAT
* Cipher suite: 2 (AES-CCM-16-64-128, SHA-256, 8, P-256, ES256, AES-CCM-16-64-128, SHA-256)

## Installation

1. Make sure you have Rust installed (see instructions in the [website](https://www.rust-lang.org/tools/install)).

2. Download, compile, and run the tests:
```
git clone git@github.com:geonnave/edhoc-rs.git && cd edhoc-rs
cargo build
cargo test
```

## Example

In one terminal, run an example CoAP server:
```
./target/debug/coapserver
```

In another one, run the client:
```
./target/debug/coapclient
```

In the output you should find the EDHOC handshake messages and the derived OSCORE secret/salt.

## Selecting target / crypto backend

TO-DO
