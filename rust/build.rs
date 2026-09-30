//! The crate's build script, for one binary: `cellward-oc-auth`, the only
//! one linked with libopenconnect (`docs/PERMISSIONS.md` §11.17). The
//! library's progress callback is printf-style, which stable Rust cannot
//! define: a few lines of C (`src/bin/oc_auth_shim.c`) format the line for
//! it. libopenconnect is linked into that binary alone, so that no other
//! process of cellward carries it and what it pulls in.

fn main() {
    println!("cargo:rerun-if-changed=src/bin/oc_auth_shim.c");
    cc::Build::new()
        .file("src/bin/oc_auth_shim.c")
        .warnings(true)
        .compile("cellward_oc_shim");
    // Where it is, as pkg-config says; linked by the binary's own argument.
    match pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("openconnect")
    {
        Ok(lib) => {
            for dir in &lib.link_paths {
                println!("cargo:rustc-link-search=native={}", dir.display());
            }
        }
        Err(e) => println!("cargo:warning=pkg-config does not know openconnect: {e}"),
    }
    println!("cargo:rustc-link-arg-bin=cellward-oc-auth=-lopenconnect");
}
