use std::env;
use std::path::PathBuf;

/// The *target* OS for the cargo build. Build scripts run on the HOST, so
/// `cfg!(target_os = ...)` reflects the HOST, not the build target. The target
/// OS is exposed via the `CARGO_CFG_TARGET_OS` env var cargo sets for build
/// scripts.
fn target_os() -> String {
    env::var("CARGO_CFG_TARGET_OS").unwrap_or_default()
}

fn is_ios() -> bool {
    target_os() == "ios"
}

/// True when cross-compiling for Android (NDK). 1054 Android port.
fn is_android() -> bool {
    target_os() == "android"
}

/// Link against the OpenMP runtime (only when OpenFHE was built WITH_OPENMP).
/// On iOS / Android there is no linked system OpenMP runtime; OpenFHE is built
/// single-threaded (WITH_OPENMP=OFF) so we link nothing.
fn link_openmp() {
    let tos = target_os();
    if tos == "ios" || tos == "android" {
        // iOS/Android: OpenFHE built single-threaded (WITH_OPENMP=OFF). Nothing to link.
        return;
    }
    if tos == "macos" {
        // Homebrew libomp locations (Apple Silicon vs Intel)
        let omp_paths = ["/opt/homebrew/opt/libomp/lib", "/usr/local/opt/libomp/lib"];
        for path in &omp_paths {
            let lib_path = PathBuf::from(path);
            if lib_path.join("libomp.dylib").exists() {
                println!("cargo::rustc-link-search=native={path}");
                println!("cargo::rustc-link-lib=omp");
                return;
            }
        }
        eprintln!("cargo::warning=libomp not found; OpenFHE may have been built without OpenMP");
        return;
    }
    if tos == "linux" {
        // libgomp (GCC) / libomp (LLVM) found in standard paths.
        println!("cargo::rustc-link-lib=gomp");
    }
}

/// Resolve the OpenFHE install dir.
///
/// Priority:
///   1. `OPENFHE_INSTALL_DIR` env var (absolute path) — lets a cross build
///      point at a target-specific prebuilt OpenFHE (e.g. an iOS device vs
///      simulator, or an aarch64-linux-android cone) without clobbering the
///      desktop `vendor/openfhe-install`.
///   2. `<workspace>/vendor/openfhe-install` (the desktop default).
fn resolve_openfhe_install(workspace_root: &std::path::Path) -> PathBuf {
    if let Ok(dir) = env::var("OPENFHE_INSTALL_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    workspace_root.join("vendor/openfhe-install")
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let openfhe_install = resolve_openfhe_install(workspace_root);

    let openfhe_include = openfhe_install.join("include/openfhe");
    let openfhe_lib = openfhe_install.join("lib");

    // Verify OpenFHE was built for this target.
    if !openfhe_lib.join("libOPENFHEpke_static.a").exists() {
        panic!(
            "OpenFHE static libraries not found at {openfhe_lib:?}.\n\
             Desktop: run `just build-openfhe` first.\n\
             iOS / Android cross build: build OpenFHE for the target and point \
             OPENFHE_INSTALL_DIR at its install prefix \
             (see recrypt-openfhe-sys build.rs / 1054 openfhe evidence)."
        );
    }

    // Build the cxx bridge. The `cc`/`cxx-build` crates auto-derive the Apple
    // sysroot / `-target arm64-apple-ios*` (or the NDK aarch64-linux-android
    // sysroot from CC_aarch64_linux_android) from CARGO's target triple, so we
    // only add include dirs + std flags here.
    let mut bridge = cxx_build::bridge("src/lib.rs");
    bridge
        .file("src/wrapper.cc")
        .include(&openfhe_include)
        .include(openfhe_include.join("core"))
        .include(openfhe_include.join("pke"))
        .include(openfhe_include.join("binfhe"))
        .include(openfhe_include.join("core/include"))
        .include(openfhe_include.join("pke/include"))
        .include(openfhe_include.join("third-party/include"))
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-O2")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-sign-compare")
        .flag_if_supported("-Wno-missing-field-initializers");
    if is_ios() || is_android() {
        // OpenFHE headers trip -Werror under iOS/Android clang; downgrade.
        bridge.flag_if_supported("-Wno-error");
    }
    bridge.compile("recrypt_openfhe_sys");

    println!("cargo::rustc-link-search=native={}", openfhe_lib.display());
    // Use the propagating `rustc-link-lib` form (NOT `rustc-link-arg`, which is
    // NOT forwarded to dependent crates' final cdylib/bin links) with the
    // `+whole-archive` modifier. OpenFHE pke/core/binfhe are mutually circular
    // and a cdylib tolerates undefined symbols, so plain `static=` leaves the
    // CKKS typeinfo/vtable (e.g. _ZTIN8lbcrypto23CryptoParametersCKKSRNSE)
    // UNDEFINED in libnaoms_core.so -> on-device dlopen fails with
    // "typeinfo for lbcrypto::CryptoParametersCKKSRNS is missing".
    // `+whole-archive` force-includes every member AND propagates transitively
    // to naoms-core's cdylib link, so the definitions land in the .so. (1054)
    println!("cargo::rustc-link-lib=static:+whole-archive=OPENFHEpke_static");
    println!("cargo::rustc-link-lib=static:+whole-archive=OPENFHEcore_static");
    println!("cargo::rustc-link-lib=static:+whole-archive=OPENFHEbinfhe_static");

    // Link the C++ standard library. Apple platforms (macOS + iOS) use libc++.
    // Android (NDK) uses LLVM libc++ too, but the runtime is `c++_shared`
    // (the APK must bundle libc++_shared.so — the NDK convention for cdylibs).
    match target_os().as_str() {
        "macos" | "ios" => println!("cargo::rustc-link-lib=c++"),
        "android" => println!("cargo::rustc-link-lib=c++_shared"),
        "linux" => println!("cargo::rustc-link-lib=stdc++"),
        _ => println!("cargo::rustc-link-lib=c++"),
    }

    // Link OpenMP runtime when applicable (no-op on iOS/Android).
    link_openmp();

    println!("cargo::rerun-if-changed=src/lib.rs");
    println!("cargo::rerun-if-changed=src/wrapper.h");
    println!("cargo::rerun-if-changed=src/wrapper.cc");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=OPENFHE_INSTALL_DIR");
}
