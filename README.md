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
git clone git@github.com:openwsn-berkeley/edhoc-rs.git && cd edhoc-rs
cargo build
cargo test
```

## Example

In one terminal, run an example CoAP server:
```
cargo run --bin coapserver
```

In another one, run the client:
```
cargo run --bin coapclient
```

In the output you should find the EDHOC handshake messages and the derived OSCORE secret/salt.

The source code for these examples is at `examples/coap/src/bin`.

## Selecting target / crypto backend

To see more examples on how to build it using different crypto backends, check the [Github Actions file](./.github/workflows/rust.yml).

## Directory structure
This library is structured as a Workspace, a feature from Cargo which makes it easy to manage more than one package / application in the same repository. Here are its the main folders:

- `lib`: The main library for the EDHOC implementation.
- `examples`: Example applications that demonstrate how to use the EDHOC library. There are several subdirectories, each containing a different example application (e.g., coap, edhoc-rs-cc2538, edhoc-rs-no_std).
- `consts`: Defines constants used throughout the project.
- `crypto`: Implement wrappers from cryptographic operations that work in different targets (native, nrf52840 with and without hardware-accelerated crypto, etc.).
- `hacspec`: Leverages the Hacspec cryptographic specification language to implement the EDHOC protocol (the RFC stuff).

To see how to select a different feature, check the [Github Actions file](./.github/workflows/rust.yml).
