# Introduction

This folder contains a bare metal (no_std) example of EDHOC Initiator and EDHOC Responder for nRF52840-DK.
The Initiator and Responder communicate over a raw BLE radio.

The example is configured to be ran on nRF52840-DK board.

## Prerequisites

- install probe-rs
- `rustup target add thumbv7m-none-eabi`

## How to use

This folder's `.cargo/config.toml` configures the target (`thumbv7m-none-eabi`) and the probe-rs runner so the things should just work:

    cargo run --bin initiator
    cargo run --bin responder

You may want to prefix the commands above with e.g. PROBE_RS_PROBE=1366:1051:001050288491 in order to specify which board you want to connect to.
You can get the name of your probes by running:

    probe-rs list
