# CasaOS submission assets

The store PR carries image files next to `docker-compose.yml`. They are
copies of files that already live in this repo, so they are not duplicated
here - copy them into the submission with these names:

| PR filename       | source in this repo               |
|-------------------|-----------------------------------|
| `icon.svg`        | `packaging/icon/icon.svg`         |
| `screenshot-1.png`| `website/assets/dash-hero.png`    |
| `screenshot-2.png`| `website/assets/dash-browse.png`  |
| `screenshot-3.png`| `website/assets/dash-queue-drawer.png` |
| `screenshot-4.png`| `website/assets/settings-top.png` |

`x-casaos.icon` and `x-casaos.screenshot_link` point at the jsDelivr CDN
path those files will have once merged. The store's build downloads them,
converts the screenshots to webp and rewrites both fields, so the URLs only
have to resolve after the merge - which is what every app in that store
does.
