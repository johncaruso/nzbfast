# nzbfast Scoop bucket

The official [Scoop](https://scoop.sh) bucket for
[nzbfast](https://github.com/nzbfast/nzbfast), the fast Usenet
downloader.

## Install

```powershell
scoop bucket add nzbfast https://github.com/nzbfast/scoop-bucket
scoop install nzbfast
```

This installs the portable build: `nzbfast.exe` (CLI and daemon) and
`nzbtray.exe` (tray launcher) on your PATH, plus a Start Menu shortcut
for the tray app.

## Update

```powershell
scoop update nzbfast
```

The manifest is regenerated from each GitHub release's published
SHA256SUMS.txt, so hashes always match the release assets.

## Links

- Website and manual: https://nzbfast.github.io/nzbfast/
- Releases: https://github.com/nzbfast/nzbfast/releases
- Issues: https://github.com/nzbfast/nzbfast/issues
