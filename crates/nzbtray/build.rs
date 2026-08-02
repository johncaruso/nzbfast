// Embed the app icon + version info via windres (mingw). The release
// recipe cross-compiles from a Mac with x86_64-w64-mingw32-windres on
// PATH (brew mingw-w64); a native MSVC build has no windres and simply
// ships without the embedded icon - the tray falls back to the stock
// application glyph, nothing breaks.
fn main() {
    println!("cargo:rerun-if-changed=../../packaging/icon/nzbfast.ico");
    println!("cargo:rerun-if-changed=../../packaging/windows/nzbfast.manifest");
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
        (Some(m), true) => format!("1 24 \"{}\"\n", m.display().to_string().replace('\\', "/")),
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
            ico = ico.display(),
        ),
    )
    .unwrap();
    let windres = std::env::var("WINDRES").unwrap_or_else(|_| {
        if gnu {
            "x86_64-w64-mingw32-windres".into()
        } else {
            "windres".into()
        }
    });
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
        Ok(s) if s.success() => {
            println!("cargo:rustc-link-arg={}", res.display());
        }
        _ => println!("cargo:warning={windres} unavailable - no embedded icon/version resource"),
    }
}
