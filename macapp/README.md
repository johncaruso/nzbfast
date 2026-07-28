# NzbFast.app - the Mac wrapper (installer spec, chip A)

WKWebView shell over the web dashboard - the dashboard is the ONLY UI.
The app owns a bundled `nzbfast` engine (Contents/Resources/bin,
universal) and manages its lifecycle:

- **attach-or-spawn**: if the persisted port answers `mode=version` as
  nzbfast, attach; else free-port scan from 6789, spawn with
  `NZBFAST_BUNDLED=1`, data in `~/Library/Application Support/nzbfast/`,
  downloads in `~/Downloads/nzbfast/`, log → `daemon.log` (5 MB rotate).
- **Quit** = `mode=shutdown` (queue persists, journals resume), ≤5 s,
  then hard-kill. Daemons the app merely attached to are never touched.
- Menus: About, Start at Login (SMAppService), Open .nzb…, Open in
  Browser, Open Downloads, User Manual. Finder-opened `.nzb` files POST
  to `addfile` (queued through cold start).

```sh
# proper app bundle → macapp/build/NzbFast.app (universal, ad-hoc signed)
./make-app.sh
# reuse a prebuilt engine binary
ENGINE=/path/to/nzbfast ./make-app.sh

# styled DMG → packaging/mac/build/nzbfast-<ver>-macos.dmg
../packaging/mac/make-dmg.sh
```

Version stamps from `crates/nzbfast/Cargo.toml`. Signing is ad-hoc
inside-out (nested engine first, then the app) until the real identity
lands - the bundle layout already matches what notarization will need.
