#!/bin/bash

set -e

# This script builds the static library for a cortex-m4 target
# It also generates the header files for the c wrapper
# The script takes one argument: the cargo feature to use

# This script should not be necessary, it exists due to several flags clashing and preventing CI from passing.
# The main reason being that the build behaves differently then crate-type is set to staticlib,
# for example, running tests required a panic handler and an "eh_personality" function, but then
# this would clash when building the static library or the no_std example.

# cargo_features=$1

# if [[ $cargo_features != "crypto-cryptocell310" && $cargo_features != "crypto-psa-baremetal" ]]; then
#     echo "Select one of: crypto-cryptocell310, crypto-psa-baremetal"
#     echo "Example: ./build_static_lib.sh crypto-cryptocell310"
#     exit 1
# fi

# generate the static library
# cargo build --target thumbv7em-none-eabihf --package edhoc-rs --package lakers-crypto --package lakers-ead  --features="$cargo_features" --release
cargo build --target=thumbv7em-none-eabihf -p lakers-ffi --no-default-features --features="crypto-cryptocell310" --release

# generate the headers
cbindgen --config shared/cbindgen.toml --crate lakers-shared --output target/include/lakers_shared.h -v
cbindgen --config lakers-ffi/cbindgen.toml --crate lakers-ffi --output target/include/lakers_ffi.h -v

# # zip to a single file
# cd target
# zip -r staticlib-"$cargo_features"-thumbv7em-none-eabihf.zip include/
# zip -u -j staticlib-"$cargo_features"-thumbv7em-none-eabihf.zip thumbv7em-none-eabihf/release/libedhoc_rs.a
# cd -
