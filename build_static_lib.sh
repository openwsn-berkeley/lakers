#!/bin/bash

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

cargo build --target thumbv7em-none-eabihf --package edhoc-rs --package edhoc-crypto --package edhoc-ead  --features="$cargo_features" --release

echo "Reverting crate-type to original value:   $original_value"
sed -i -E "s/crate-type.*/$original_value/" lib/Cargo.toml
