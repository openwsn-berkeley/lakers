# lakers: EDHOC implemented in Rust

[![Build and test](https://github.com/openwsn-berkeley/lakers/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/openwsn-berkeley/lakers/actions/workflows/build-and-test.yml)

An implementation of [EDHOC](https://datatracker.ietf.org/doc/draft-ietf-lake-edhoc/) in Rust:
- up-to-date with the [latest draft version (23)](https://datatracker.ietf.org/doc/draft-ietf-lake-edhoc/23/)
- microcontroller-optimized: `no_std`, no heap allocations, zero-dependencies (other than crypto backends)
- configurable crypto backends
- bindings for [C](https://github.com/openwsn-berkeley/lakers/releases/) and [Python](https://pypi.org/project/lakers-python/)
- support for EDHOC extensions, including [zero-touch authorization](https://datatracker.ietf.org/doc/draft-ietf-lake-authz/)

It currently supports authentication mode STAT-STAT and Cipher Suite 2 (AES-CCM-16-64-128, SHA-256, 8, P-256, ES256, AES-CCM-16-64-128, SHA-256).

Here's a quick look at the API for the Initiator role (for the Responder role, and more details, check the examples or the unit tests):
```rust
let initiator = EdhocInitiator::new(default_crypto());

let (initiator, message_1) = initiator.prepare_message_1(None, &None)?; // c_i and ead_1 are set to None

let (initiator, _c_r, id_cred_r, _ead_2) = initiator.parse_message_2(&message_2)?;
let valid_cred_r = credential_check_or_fetch(Some(CRED_R), id_cred_r)?; // CRED_R contains Responder's public key
let initiator = initiator.verify_message_2(I, cred_i, valid_cred_r)?; // I is Initiator's private key

let (mut initiator, message_3, i_prk_out) = initiator.prepare_message_3(CredentialTransfer::ByReference, &None)?; // no ead_3
```

## Installation

To use `lakers` in your Rust project, simply add it to your Cargo.toml: `lakers = "0.5.1"` (check for the [latest version here](https://crates.io/crates/lakers)).

### C API
C-compatible static libraries and headers are available for download in [the releases page](https://github.com/openwsn-berkeley/lakers/releases).

### Python API
`lakers-python` is [available on PyPI](https://pypi.org/project/lakers-python/), to install it run `pip install lakers-python`.

### Development
To work on `lakers` itself, follow the instructions below:

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

To build **and** flash to the board:
1. install [cargo-embed](https://crates.io/crates/cargo-embed)
1. run one of the commands above, but use the command `embed` in place of `build`. For example: `cargo embed --target="thumbv7em-none-eabihf"`

## Directory structure
This library is structured as a [cargo workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html).
Its main members are:

- `lib`: The main library providing the EDHOC implementation.
- `crypto`: Diferent cryptographic backends (e.g. psa, cryptocell310, hacspec).
- `ead`: Implementation of extensions to EDHOC via the External Authorization Data (EAD) field.
- `shared`: Defines shared structs and modules used throughout the workspace members.
- `lakers-c`: Provides a foreign function interface that enables using `lakers` from C code.
- `lakers-python`: API for using `lakers` in Python.
- `examples`: Example applications that demonstrate how to use the library.
