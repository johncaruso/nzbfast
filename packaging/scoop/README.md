# Scoop manifest

`nzbfast.json` is the Scoop app manifest for the portable Windows zip
(`nzbfast-<version>-windows-x64.zip`, inner dir `nzbfast-windows/`).
It is GENERATED - run `packaging/make-pkg-manifests.sh <version>` after
a release is published.

The manifest carries `checkver` + `autoupdate` blocks, so wherever it is
hosted, Scoop's excavator bot (or `checkver -u`) can bump future
versions automatically from the GitHub release and SHA256SUMS.txt.

## Where it gets published (decision pending)

Two viable homes, not yet chosen:

1. **Own bucket** - a `nzbfast/scoop-bucket` repo under the release
   account. Users run
   `scoop bucket add nzbfast https://github.com/nzbfast/scoop-bucket`
   then `scoop install nzbfast`. No third-party review, live the same
   day, updated by us at release time.
2. **Community bucket PR** - `ScoopInstaller/Extras`. Discoverable via
   plain `scoop install nzbfast` for everyone with the extras bucket
   added, but subject to their review and their bot thereafter.

They are not exclusive: the usual path is own bucket first, community
bucket once the project has a track record. Do not publish to either
without an explicit go-ahead; all public operations run under
`GH_CONFIG_DIR=~/.config/gh-nzbfast`.
