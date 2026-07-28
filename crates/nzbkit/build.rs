//! Build rapidyenc (vendor/rapidyenc) as a static library - decode + CRC only.
//!
//! We drive the `cc` crate rather than cmake (cmake is not installed on the
//! dev machine). This replicates upstream CMakeLists.txt: every kernel source
//! is compiled with the arch flags it needs; the sources self-guard with
//! `#ifdef PLATFORM_X86` / `__aarch64__` etc., so files for a foreign ISA
//! compile to empty objects. Runtime CPU detection in decoder.cc / crc.cc
//! picks the best kernel (NEON + ARMv8 CRC/PMULL on Apple Silicon).
//!
//! Encoder is excluded (RAPIDYENC_DISABLE_ENCODE) - nzbfast only decodes.
//! crcutil is excluded (YENC_DISABLE_CRCUTIL) - rapidyenc's own slice-by-4
//! generic CRC covers the no-SIMD case, and this keeps the Apache-2.0
//! crcutil code out of our binaries entirely.

use std::path::Path;

const VENDOR: &str = "../../vendor/rapidyenc";

fn base_build() -> cc::Build {
    let mut b = cc::Build::new();
    b.cpp(true)
        .include(VENDOR)
        .define("RAPIDYENC_DISABLE_ENCODE", "1")
        .define("YENC_DISABLE_CRCUTIL", "1")
        .opt_level(3)
        .flag_if_supported("-fno-exceptions")
        .flag_if_supported("-fno-rtti")
        .flag_if_supported("-fwrapv")
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-fomit-frame-pointer")
        .warnings(false);
    b
}

fn compile_group(lib: &str, files: &[&str], flags: &[&str]) {
    let mut b = base_build();
    for f in files {
        b.file(Path::new(VENDOR).join(f));
    }
    for fl in flags {
        b.flag_if_supported(fl);
    }
    b.compile(lib);
}

fn main() {
    println!("cargo:rerun-if-changed={VENDOR}/rapidyenc.cc");
    println!("cargo:rerun-if-changed={VENDOR}/rapidyenc.h");
    println!("cargo:rerun-if-changed={VENDOR}/src");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let is_x86 = arch == "x86_64" || arch == "x86";
    let is_arm64 = arch == "aarch64";

    // Core: dispatchers, generic kernels, the C API wrapper. No arch flags -
    // these must run on any CPU of the target family.
    let mut core: Vec<&str> = vec![
        "src/platform.cc",
        "src/decoder.cc",
        "src/crc.cc",
        "rapidyenc.cc",
    ];
    // NEON is baseline on aarch64: no extra flags needed, so it can live in
    // the core group (upstream compiles decoder_neon64.cc with no flags too).
    if is_arm64 {
        core.push("src/decoder_neon64.cc");
    } else if !is_x86 {
        core.push("src/decoder_neon.cc"); // self-guards; empty off-ARM
    }
    // Self-guarding no-ops off their ISA; harmless to include everywhere.
    core.push("src/decoder_rvv.cc");
    core.push("src/crc_riscv.cc");
    compile_group("rapidyenc_core", &core, &[]);

    if is_x86 {
        compile_group("ry_dec_sse2", &["src/decoder_sse2.cc"], &["-msse2"]);
        compile_group("ry_dec_ssse3", &["src/decoder_ssse3.cc"], &["-mssse3"]);
        compile_group(
            "ry_dec_avx",
            &["src/decoder_avx.cc"],
            &["-mavx", "-mpopcnt"],
        );
        compile_group(
            "ry_dec_avx2",
            &["src/decoder_avx2.cc"],
            &["-mavx2", "-mpopcnt", "-mbmi", "-mbmi2", "-mlzcnt"],
        );
        compile_group(
            "ry_dec_vbmi2",
            &["src/decoder_vbmi2.cc"],
            &[
                "-mavx512vbmi2",
                "-mavx512vl",
                "-mavx512bw",
                "-mpopcnt",
                "-mbmi",
                "-mbmi2",
                "-mlzcnt",
            ],
        );
        compile_group(
            "ry_crc_fold",
            &["src/crc_folding.cc"],
            &["-mssse3", "-msse4.1", "-mpclmul"],
        );
        compile_group(
            "ry_crc_fold256",
            &["src/crc_folding_256.cc"],
            &["-mavx2", "-mvpclmulqdq", "-mpclmul"],
        );
    } else {
        // Off-x86 these compile empty, but decoder.cc's x86 dispatch table is
        // fully #ifdef'd out, so we can simply skip them. ARM CRC kernels do
        // need their feature flags:
        compile_group("ry_crc_arm", &["src/crc_arm.cc"], &["-march=armv8-a+crc"]);
        compile_group(
            "ry_crc_pmull",
            &["src/crc_arm_pmull.cc"],
            &["-march=armv8-a+crypto+crc"],
        );
    }
}
