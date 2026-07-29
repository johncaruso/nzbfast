// Embed the app icon, a VERSIONINFO block and an application manifest
// into nzbfast.exe on Windows builds.
//
// The daemon shipped without any of this until 1.0.9: a PE carrying no
// version resource, no icon and no manifest reads as hand-assembled
// rather than built by a toolchain, which is a (small) input to the
// reputation scoring that flagged us. nzbtray.exe has had a version
// resource all along, so this brings the daemon in line with it.
//
// Same constraint as the tray's build.rs: this needs windres, which the
// mingw cross-build has and a native MSVC build does not. Without it the
// binary simply builds unadorned, exactly as before.

fn main() {
    println!("cargo:rerun-if-changed=../../packaging/icon/nzbfast.ico");
    println!("cargo:rerun-if-changed=../../packaging/windows/nzbfast.manifest");
    // Beta serial: local deploys and tester builds carry "beta N" after
    // the version so anyone can tell a between-releases build from the
    // published release it grew out of. packaging/beta-serial.txt is
    // bumped by the deploy-daemon / release-bundle workflows and RESET
    // TO 0 by publish-release, so a release build shows a bare version.
    // Missing file or 0 (or a public-repo build, which has no file)
    // means "not a beta": the suffix simply never appears.
    println!("cargo:rerun-if-changed=../../packaging/beta-serial.txt");
    let beta = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/beta-serial.txt");
    let beta = std::fs::read_to_string(beta)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .map(|n| n.to_string())
        .unwrap_or_default();
    println!("cargo:rustc-env=NZBFAST_BETA={beta}");
    if std::env::var("CARGO_CFG_WINDOWS").is_err() {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let Ok(ico) = root.join("packaging/icon/nzbfast.ico").canonicalize() else {
        println!("cargo:warning=nzbfast.ico missing - building without an embedded icon");
        return;
    };
    let ver = std::env::var("CARGO_PKG_VERSION").unwrap();
    let ver_commas = ver.replace('.', ",");

    // RT_MANIFEST (resource type 24, id 1) only for the gnu toolchain.
    // MSVC's linker embeds a default manifest of its own and a second one
    // is a hard link error, so leave that target alone.
    let gnu = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu");
    let manifest = root.join("packaging/windows/nzbfast.manifest").canonicalize().ok();
    let manifest_line = match (&manifest, gnu) {
        (Some(m), true) => format!("1 24 \"{}\"\n", m.display().to_string().replace('\\', "/")),
        _ => String::new(),
    };

    let rc = out.join("nzbfast.rc");
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
      VALUE "ProductName", "nzbfast"
      VALUE "FileDescription", "nzbfast download engine"
      VALUE "InternalName", "nzbfast"
      VALUE "OriginalFilename", "nzbfast.exe"
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
            ico = ico.display().to_string().replace('\\', "/"),
        ),
    )
    .unwrap();

    let windres = std::env::var("WINDRES").unwrap_or_else(|_| {
        if gnu { "x86_64-w64-mingw32-windres".into() } else { "windres".into() }
    });
    let res = out.join("nzbfast.res.o");
    match std::process::Command::new(&windres)
        .args([rc.to_str().unwrap(), "-O", "coff", "-o", res.to_str().unwrap()])
        .status()
    {
        Ok(s) if s.success() => println!("cargo:rustc-link-arg={}", res.display()),
        _ => println!("cargo:warning={windres} unavailable - no embedded icon/version resource"),
    }
}
