fn main() {
    println!("cargo:rustc-link-lib=dylib=patchfinder");
    println!("cargo:rustc-link-search=./patchfinder64/");
}
