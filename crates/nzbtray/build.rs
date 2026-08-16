// Embed the app icon + version info. The release recipe cross-compiles
// from a Mac with x86_64-w64-mingw32-windres on PATH (brew mingw-w64);
// an MSVC build goes through rc.exe instead. If neither tool is found
// the tray ships without the embedded resource - it falls back to the
// stock application glyph, and installer.iss's TrayUnderstandsQuit
// reads the missing VERSIONINFO as "older than 1.0.9".
//
// TWIN FILE: crates/nzbfast/build.rs does the same job for the daemon
// and carries the same rc_path / find_rc_exe / compile_rc_* helpers.
// They diverged once - §172 fixed this file for MSVC and left that one
// on windres, which cost the first ARM64 release build an LNK1112 on an
// x86_64 windres object. Change both together.
fn main() {
    println!("cargo:rerun-if-changed=../../packaging/icon/nzbfast.ico");
    println!("cargo:rerun-if-changed=../../packaging/windows/nzbfast.manifest");
    // Beta serial, embedded exactly as the engine's build.rs embeds its
    // own (crates/nzbfast/build.rs): the §98 upgrade handshake compares
    // "what this tray ships" against "what the running engine serves",
    // and a deploy build ("1.0.14 beta 5") must outrank the release it
    // grew from ("1.0.14"). Before the cfg(windows) early-return - the
    // probe_body module that does the comparison compiles and tests on
    // every host.
    println!("cargo:rerun-if-changed=../../packaging/beta-serial.txt");
    let beta =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/beta-serial.txt");
    let beta = std::fs::read_to_string(beta)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "0")
        .unwrap_or_default();
    println!("cargo:rustc-env=NZBTRAY_BETA={beta}");
    if std::env::var("CARGO_CFG_WINDOWS").is_err() {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let ico = root.join("packaging/icon/nzbfast.ico").canonicalize();
    let Ok(ico) = ico else {
        println!("cargo:warning=nzbfast.ico missing - building without an embedded icon");
        return;
    };
    let ver = std::env::var("CARGO_PKG_VERSION").unwrap();
    let ver_commas = ver.replace('.', ",");

    // RT_MANIFEST (type 24, id 1). gnu only: MSVC's linker embeds its own
    // default manifest and rejects a second. Type 24 and ICON are
    // different resource types, so both can be id 1.
    let gnu = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu");
    let manifest = root
        .join("packaging/windows/nzbfast.manifest")
        .canonicalize()
        .ok();
    let manifest_line = match (&manifest, gnu) {
        (Some(m), true) => format!("1 24 \"{}\"\n", rc_path(m)),
        _ => String::new(),
    };

    let rc = out.join("nzbtray.rc");
    // Icon resource id 1 (loaded with MAKEINTRESOURCE(1) in main.rs).
    std::fs::write(
        &rc,
        format!(
            r#"1 ICON "{ico}"
{manifest_line}1 VERSIONINFO
FILEVERSION {ver_commas},0
PRODUCTVERSION {ver_commas},0
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "nzbfast"
      VALUE "ProductName", "nzbfast"
      VALUE "FileDescription", "nzbfast tray"
      VALUE "InternalName", "nzbtray"
      VALUE "OriginalFilename", "nzbtray.exe"
      VALUE "FileVersion", "{ver}"
      VALUE "ProductVersion", "{ver}"
      VALUE "LegalCopyright", "GPL-3.0-or-later"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
            ico = rc_path(&ico),
        ),
    )
    .unwrap();
    if gnu {
        compile_rc_windres(&rc, &out);
    } else {
        compile_rc_msvc(&rc, &out);
    }
}

/// Spell a path the way an .rc file wants it.
///
/// Two Windows-only hazards, both no-ops on the mac cross-build that has
/// produced every shipped tray so far - which is exactly why neither was
/// noticed until a native build was attempted:
///
///   - `canonicalize()` returns a VERBATIM path (`\\?\C:\...`) on Windows.
///     Neither `rc.exe` nor `windres` accepts that prefix.
///   - a backslash inside an .rc string literal is an ESCAPE character,
///     so `"C:\Users\..."` is read as `C:Users...`. Both compilers take
///     forward slashes, which need no escaping.
fn rc_path(p: &std::path::Path) -> String {
    let s = p.display().to_string();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    s.replace('\\', "/")
}

/// mingw: `windres` straight to a COFF object, link-arg'd in.
fn compile_rc_windres(rc: &std::path::Path, out: &std::path::Path) {
    let windres =
        std::env::var("WINDRES").unwrap_or_else(|_| "x86_64-w64-mingw32-windres".to_string());
    let res = out.join("nzbtray.res.o");
    match std::process::Command::new(&windres)
        .args([
            rc.to_str().unwrap(),
            "-O",
            "coff",
            "-o",
            res.to_str().unwrap(),
        ])
        .status()
    {
        Ok(s) if s.success() => println!("cargo:rustc-link-arg={}", res.display()),
        _ => println!("cargo:warning={windres} unavailable - no embedded icon/version resource"),
    }
}

/// MSVC: `rc.exe` to a .res, which `link.exe` takes as an ordinary input.
///
/// This arm used to be `windres` under a different name, which is never on
/// PATH on a Windows box, so EVERY MSVC build shipped a tray with no icon
/// and - the part that bites - no VERSIONINFO at all. installer.iss reads
/// that resource: `TrayUnderstandsQuit` treats "no version info" as "older
/// than 1.0.9" and skips the graceful quit, so the uninstaller cannot stop
/// the stack it is about to delete and fails with "Access is denied". That
/// was a documented wart while MSVC builds were dev-only; the Windows ARM64
/// package is built with MSVC, so it had to be fixed before shipping one.
///
/// A .res is architecture-neutral - the linker places it - so the same
/// x64-host rc.exe serves the ARM64 cross-build.
fn compile_rc_msvc(rc: &std::path::Path, out: &std::path::Path) {
    let Some(rc_exe) = find_rc_exe() else {
        println!("cargo:warning=rc.exe not found - no embedded icon/version resource");
        return;
    };
    let res = out.join("nzbtray.res");
    match std::process::Command::new(&rc_exe)
        .args([
            "/nologo",
            "/fo",
            res.to_str().unwrap(),
            rc.to_str().unwrap(),
        ])
        .status()
    {
        Ok(s) if s.success() => println!("cargo:rustc-link-arg={}", res.display()),
        _ => println!(
            "cargo:warning={} failed - no embedded icon/version resource",
            rc_exe.display()
        ),
    }
}

/// Locate `rc.exe`: the `RC` override, then PATH, then the Windows SDK.
///
/// The SDK sweep is what makes this work unattended. rc.exe ships with the
/// Windows Kits, and nothing puts it on PATH outside a Visual Studio
/// developer prompt - a plain `cargo build` on a Windows box, and a GitHub
/// `windows-latest` runner, both have the SDK installed and rc.exe
/// unreachable. Highest SDK version wins; the host-x64 binary is the one to
/// run whatever the target is.
fn find_rc_exe() -> Option<std::path::PathBuf> {
    if let Ok(explicit) = std::env::var("RC") {
        return Some(std::path::PathBuf::from(explicit));
    }
    if std::process::Command::new("rc.exe")
        .arg("/?")
        .output()
        .is_ok()
    {
        return Some(std::path::PathBuf::from("rc.exe"));
    }
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    for var in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Ok(pf) = std::env::var(var) {
            roots.push(std::path::PathBuf::from(pf).join("Windows Kits/10/bin"));
        }
    }
    let mut found: Vec<std::path::PathBuf> = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in entries.flatten() {
            // Both layouts exist: bin/<sdk-version>/x64/rc.exe on modern
            // kits, bin/x64/rc.exe on older ones.
            for cand in [e.path().join("x64/rc.exe"), e.path().join("rc.exe")] {
                if cand.is_file() {
                    found.push(cand);
                }
            }
        }
    }
    // read_dir order is unspecified, so sort rather than trust it. Lexical
    // order over `10.0.<build>.0` directory names is version order.
    found.sort();
    found.pop()
}
