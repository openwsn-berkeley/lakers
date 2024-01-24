#!/bin/bash

set -e

# This script builds the static library for a cortex-m4 target
# It also generates the header files for the c wrapper
# It takes one argument: the selected crypto backend

feature_crypto=$1
if [[ $feature_crypto != "crypto-cryptocell310" && $feature_crypto != "crypto-psa-baremetal" && $feature_crypto != "crypto-psa" ]]; then
    echo "crypto should be one of: crypto-cryptocell310, crypto-psa-baremetal, crypto-psa"
    echo "Example: ./build_static_lib.sh crypto-cryptocell310"
    exit 1
fi

if [[ $feature_crypto == "crypto-cryptocell310" || $feature_crypto == "crypto-psa-baremetal" ]]; then
    rust_target=thumbv7em-none-eabihf
else
    rust_target=`rustc -vV | sed -n 's|host: ||p'`
fi

# hardcoded for now
feature_ead=ead-authz

# generate the static library
cargo build --target="$rust_target" -p lakers-ffi --no-default-features  --features="$feature_crypto, $feature_ead" #--release
# cargo build --target=thumbv7em-none-eabihf -p lakers-ffi --no-default-features --features="crypto-cryptocell310, ead-authz" --release
# cargo build --target=thumbv7em-none-eabihf -p lakers-ffi --no-default-features --features="crypto-psa-baremetal, ead-authz" --release

# generate the headers
cbindgen --config shared/cbindgen.toml --crate lakers-shared --output target/include/lakers_shared.h -v
cbindgen --config lakers-ffi/cbindgen.toml --crate lakers-ffi --output target/include/lakers_ffi.h -v
cbindgen --config ead/lakers-ead-authz/cbindgen.toml --crate lakers-ead-authz --output target/include/lakers_ead_authz.h -vv

# # zip to a single file
# cd target
# zip -r staticlib-"$cargo_features"-thumbv7em-none-eabihf.zip include/
# zip -u -j staticlib-"$cargo_features"-thumbv7em-none-eabihf.zip thumbv7em-none-eabihf/release/libedhoc_rs.a
# cd -
