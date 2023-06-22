extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let generated_code_warning = "/*
* ================================================================================================
*  WARNING: This file is automatically generated by cbindgen. Manual edits are likely to be lost.
* ================================================================================================
*/";

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .with_header(generated_code_warning)
        .with_include("edhoc_consts.h")
        .with_parse_expand_all_features(false)
        .with_parse_expand_features(&["rust-cryptocell310"])
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("../include/edhoc_rs.h");
}
