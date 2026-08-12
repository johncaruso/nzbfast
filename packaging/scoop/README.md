# Scoop manifest

`nzbfast.json` is the Scoop app manifest for the portable Windows zip
(`nzbfast-<version>-windows-x64.zip`, inner dir `nzbfast-windows/`).
It is GENERATED - run `packaging/make-pkg-manifests.sh <version>` after
a release is published.

The manifest carries `checkver` + `autoupdate` blocks, so wherever it is
hosted, Scoop's excavator bot (or `checkver -u`) can bump future
versions automatically from the GitHub release and SHA256SUMS.txt.

## Where it gets published

The own bucket is LIVE (decided 11 Aug 2026):
`https://github.com/nzbfast/scoop-bucket`, manifest at
`bucket/nzbfast.json`, README from `bucket-README.md` here. Users run

```powershell
scoop bucket add nzbfast https://github.com/nzbfast/scoop-bucket
scoop install nzbfast
```

At release time, after `make-pkg-manifests.sh` has regenerated the
manifest from the published release:

```sh
packaging/scoop/bump-bucket.sh --push
```

It checks the anon identity, re-hashes the published zip against the
manifest, and pushes manifest + README to the bucket. The bucket has
no excavator or checkver workflow, so this bump is the ONLY update
path - see the publish-release skill, step 5c.

Still open: a `ScoopInstaller/Extras` PR once the project has a track
record (discoverable via plain `scoop install nzbfast`). Not exclusive
with the own bucket. All public operations run under
`GH_CONFIG_DIR=~/.config/gh-nzbfast`.
