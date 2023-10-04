# edhoc-rs

[![Build and test](https://github.com/openwsn-berkeley/edhoc-rs/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/openwsn-berkeley/edhoc-rs/actions/workflows/build-and-test.yml)

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

`edhoc_rs` can be compiled with different configurations depending on the enabled features. To learn what are the available features and how to select them for several configurations of build and test, check the [Github Actions file](./.github/workflows/rust.yml).

## Example: EDHOC over CoAP on native host

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

## Example: EDHOC on nRF52840 device with different crypto backends

To build an example application that works on the [nrf52840dk](https://www.nordicsemi.com/Products/Development-hardware/nrf52840-dk), do as follows:

```bash
# head to the example `no_std` example
cd ./examples/edhoc-rs-no_std

# build using the psa crypto backend (software-based)
cargo build --target="thumbv7em-none-eabihf" --no-default-features --features="crypto-psa, rtt" --release

# build using the cryptocell310 crypto backend (hardware-accelerated)
cargo build --target="thumbv7em-none-eabihf" --no-default-features --features="crypto-cryptocell310, rtt"
```

To build **and** flash to the board, replace the word `build` with `embed` in the commands above (you may need to `cargo install cargo-embed`).

For example: `cargo embed --target="thumbv7em-none-eabihf" --no-default-features --features="cryptocell310, rtt"`

## Directory structure
This library is structured as a Workspace, a feature from Cargo which makes it easy to manage more than one package / application in the same repository. Here are its the main folders:

- `lib`: The main library for the EDHOC implementation.
- `examples`: Example applications that demonstrate how to use the EDHOC library. There are several subdirectories, each containing a different example application (e.g., coap, edhoc-rs-cc2538, edhoc-rs-no_std).
- `consts`: Defines constants and structs used throughout the project.
- `crypto`: Diferent cryptographic backends (e.g. psa, cryptocell310, hacspec).
