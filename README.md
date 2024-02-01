# lakers: EDHOC implemented in Rust

[![Build and test](https://github.com/openwsn-berkeley/lakers/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/openwsn-berkeley/lakers/actions/workflows/build-and-test.yml)

A microcontroller-optimized implementation of EDHOC in Rust (`no_std`, static memory).

`lakers` provides an implementation of the following drafts produced by the [Lightweight Authenticated Key Exchange (LAKE)](https://datatracker.ietf.org/wg/lake/about/) working group at the IETF:

- [Ephemeral Diffie-Hellman Over COSE (EDHOC)](https://datatracker.ietf.org/doc/draft-ietf-lake-edhoc/)
- [Lightweight Authorization using EDHOC](https://datatracker.ietf.org/doc/draft-ietf-lake-authz/)

It supports:
* Roles: Initiator, Responder
* Authentication mode: STAT-STAT
* Cipher suite: 2 (AES-CCM-16-64-128, SHA-256, 8, P-256, ES256, AES-CCM-16-64-128, SHA-256)

## Installation

1. Make sure you have [Rust](https://www.rust-lang.org/tools/install) installed.

2. Download, compile, and run the tests:
```
git clone git@github.com:openwsn-berkeley/lakers.git && cd lakers
cargo build
cargo test
```

`lakers` can be compiled with different configurations depending on the enabled features. To learn what are the available features and how to select them for several configurations of build and test, check the [Github Actions file](./.github/workflows/rust.yml).

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
cd ./examples/lakers-no_std

# build using the cryptocell310 crypto backend (hardware-accelerated)
cargo build --target="thumbv7em-none-eabihf" --release

# build using the psa crypto backend (software-based)
cargo build --target="thumbv7em-none-eabihf" --no-default-features --features="crypto-psa, ead-none, rtt" --release

```

To build **and** flash to the board, replace the word `build` with `embed` in the commands above (you may need to `cargo install cargo-embed`).

For example: `cargo embed --target="thumbv7em-none-eabihf" --no-default-features --features="crypto-psa, ead-none, rtt"`

## Directory structure
This library is structured as a [cargo workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html).
Its main members are:

- `lib`: The main library providing the EDHOC implementation.
- `crypto`: Diferent cryptographic backends (e.g. psa, cryptocell310, hacspec).
- `ead`: Implementation of extensions to EDHOC via the External Authorization Data (EAD) field.
- `shared`: Defines shared structs and modules used throughout the workspace members.
- `lakers-c`: Provides a foreign function interface that enables using `lakers` from C code.
- `examples`: Example applications that demonstrate how to use the library.
