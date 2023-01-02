// build.rs
use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let home_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let include_dir = Path::new(&home_dir)
        .join("vendor")
        .join("nrf_cc310")
        .join("include");
    let common_dir = Path::new(&home_dir).join("vendor").join("common");
    let lib_dir = Path::new(&home_dir)
        .join("vendor")
        .join("nrf_cc310")
        .join("lib")
        .join("cortex-m4")
        .join("hard-float")
        .join("no-interrupts");

    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}", out_dir.to_str().unwrap()))
        .clang_arg(format!("-I{}", include_dir.to_str().unwrap()))
        .clang_arg(format!("-I{}", common_dir.to_str().unwrap()))
        .rustfmt_bindings(true)
        .header("src/c/wrapper.h")
        .blocklist_type("max_align_t")
        .generate_comments(false)
        .size_t_is_usize(true)
        .use_core()
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rustc-link-lib=static=nrf_cc310_0.9.13");
    println!("cargo:rustc-link-search={}", lib_dir.to_str().unwrap());
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");
}
