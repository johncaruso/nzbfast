# Self-host app catalogue submissions

Each directory here is our source of truth for a listing in somebody
else's app catalogue. They all run the same published multi-arch image
(`nzbfast/nzbfast` on Docker Hub, `ghcr.io/nzbfast/nzbfast` on ghcr) with
the exception of Proxmox, whose house rule is a bare-metal LXC install, so
that one deploys the Linux release tarball instead.

The catalogues are third-party repos with their own review processes.
These files are what we submit; the listing itself is theirs to merge.
`TODO.md` records what went where, with the PR links, so a later session
can chase a stalled review or refresh a version bump.

```
casaos/Apps/nzbfast/           -> IceWhaleTech/CasaOS-AppStore  (Apps/nzbfast/)
umbrel/nzbfast/                -> getumbrel/umbrel-apps         (nzbfast/)
truenas/ix-dev/community/...   -> truenas/apps                  (ix-dev/community/nzbfast/)
proxmox/{ct,install,json}/     -> community-scripts/ProxmoxVED  (same three paths)
```

The layout under each directory mirrors the target repo exactly, so a
submission is a copy rather than a translation.

## Rules that apply to every one of them

- **Absolute mount paths, always.** A relative `-v ./config:/config`
  resolves against whatever directory the command ran from, so the same
  install comes back empty when it is recreated from somewhere else. That
  is the reported "all my settings are gone" failure; see MANUAL §14 and
  §17. Every manifest here binds absolute host paths.
- **The config mount is the install.** Settings, the API key, the queue,
  history and the index database all live there. It has to survive the
  container being recreated, and on Proxmox it lives in
  `/opt/nzbfast_data`, deliberately outside the program directory that an
  update replaces.
- **No API key is ever baked in.** nzbfast generates one on first run and
  the container refuses to start keyless on a published port. Manifests
  may expose `NZBFAST_APIKEY` as an empty, operator-supplied field so a
  key survives a redeploy, but they must never ship a value, and must
  never mint one themselves - a key that appears under a running install
  locks out every *arr already paired with it.
- **Port 6789** is the dashboard and the SABnzbd-compatible API. The image
  locks the container port there (`NZBFAST_PORT_LOCKED`), so a catalogue
  that needs a different host port maps onto it rather than moving the
  listener.

## Refreshing a listing for a new release

Update the image tag, the version field and the release notes in the
manifest, then re-run that catalogue's own validator (each one is named in
the TODO entry) before opening the update PR. Umbrel additionally pins the
image by digest, so it needs the new manifest-list digest:

```bash
docker buildx imagetools inspect nzbfast/nzbfast:latest
```

## Two things the target repos expect that are not kept here

- **TrueNAS `templates/library/`.** Every app in `truenas/apps` tracks a
  copy of `library/<lib_version>/` under `templates/library/base_v<x_y_z>/`,
  and their `ci.py` places it. It is ~78 vendored Python files that are
  theirs, not ours, so it is not duplicated into this repo - regenerate it
  by running their `ci.py` before opening the PR, and check the resulting
  `lib_version_hash` in `app.yaml` matches.
- **CasaOS images.** See `casaos/ASSETS.md`.
