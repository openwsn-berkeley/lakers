#!/bin/bash

# This script builds the static library for a cortex-m4 target
# It also generates the header files for the c wrapper
# The script takes one argument: the cargo feature to use

# This script should not be necessary, it exists due to several flags clashing and preventing CI from passing.
# The main reason being that the build behaves differently then crate-type is set to staticlib,
# for example, running tests required a panic handler and an "eh_personality" function, but then
# this would clash when building the static library or the no_std example.

cargo_features=$1

if [[ $cargo_features != "rust-cryptocell310" && $cargo_features != "rust-psa-baremetal" ]]; then
    echo "Select one of: rust-cryptocell310, rust-psa-baremetal"
    echo "Example: ./build_static_lib.sh rust-cryptocell310"
    exit 1
fi

original_value=`grep crate-type lib/Cargo.toml`

new_value='crate-type = ["staticlib"]'
echo "Changing crate-type to:   $new_value"
sed -i -E "s/crate-type.*/$new_value/" lib/Cargo.toml

# generate the static library
cargo build --target thumbv7em-none-eabihf --package edhoc-rs --package edhoc-crypto --package edhoc-ead  --features="$cargo_features" --release

# generate the headers
cbindgen --config consts/cbindgen.toml --crate edhoc-consts --output ./target/include/edhoc_consts.h -v
cbindgen --config lib/cbindgen.toml --crate edhoc-rs --output ./target/include/edhoc_rs.h -v

echo "Reverting crate-type to original value:   $original_value"
sed -i -E "s/crate-type.*/$original_value/" lib/Cargo.toml
