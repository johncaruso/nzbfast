# nzbfast on a Synology NAS

nzbfast runs on Synology DSM 7 as a Docker container through **Container
Manager** (Package Center → *Container Manager*; on DSM 6 the same app is
called *Docker*). One container gives you the full web dashboard, the
SABnzbd/NZBGet-compatible API for Sonarr/Radarr, and the built-in indexer.

The image is multi-arch, so it runs on both Intel and ARM (Realtek/RTD,
Annapurna) Synology models with no change. It's published to two
registries that serve the **identical** image - `nzbfast/nzbfast` on
Docker Hub (this is the one Container Manager can *search* for) and
`ghcr.io/nzbfast/nzbfast` on GitHub. Use whichever you prefer; the guide
uses the Docker Hub name.

There are two ways in. **Route A is the one to take** - a single compose
file, which is also the only way to have the container keep itself up to
date. Route B is search-and-click, with no text file at all, at the cost
of updating by hand.

---

## Before you start: your PUID / PGID (30 seconds)

The container writes your downloads as a specific user ID so the files
belong to *you*, not to root. Find yours once:

1. Control Panel → **Terminal & SNMP** → tick **Enable SSH service**.
2. SSH in and run:

   ```sh
   id your_dsm_username
   ```

   Note the `uid=` and `gid=` numbers. On most Synology boxes the first
   user is `uid=1026` and the primary group is `users` `gid=100` - but
   use whatever `id` prints.
3. Turn SSH back off afterwards if you like; you won't need it again.

You'll drop those two numbers into `PUID` and `PGID` below.

---

## Route A - Container Manager Project (one compose file)

One file you can back up, re-use, and update with a single click. Take
this route if you want nzbfast to keep itself current.

1. File Station → create the project folder, e.g. `/docker/nzbfast`.
2. Container Manager → **Project** → **Create**.
   - **Project name:** `nzbfast`
   - **Path:** `/docker/nzbfast`
   - **Source:** *Create docker-compose.yml* and paste:

   ```yaml
   services:
     nzbfast:
       image: nzbfast/nzbfast:latest
       container_name: nzbfast
       restart: unless-stopped
       ports:
         - "6789:6789"
       environment:
         - PUID=1026          # ← your uid  (id your_dsm_username)
         - PGID=100           # ← your gid
         - TZ=Europe/London   # ← your timezone
         # - NZBFAST_APIKEY=change-me   # optional: pick your own key instead
         #                              # of the one nzbfast generates
       volumes:
         - ./config:/config          # settings + index database
         - ./downloads:/downloads    # finished files
         - ./watch:/watch            # drop an .nzb here to auto-download

     # Optional: checks nightly for a newer nzbfast image and recreates the
     # container when one ships. Delete this service to update by hand.
     watchtower:
       image: containrrr/watchtower
       container_name: nzbfast-watchtower
       restart: unless-stopped
       environment:
         - TZ=Europe/London   # same timezone, so the schedule below is your 04:00
       volumes:
         - /var/run/docker.sock:/var/run/docker.sock
       command: --cleanup --schedule "0 0 4 * * *" nzbfast   # daily 04:00, nzbfast only
   ```

   The `./config`, `./downloads`, `./watch` paths are created for you
   inside the project folder.
3. Finish the wizard - Container Manager pulls the images and starts
   them. Then jump to [First run](#first-run-add-your-provider).

**About that last service.** Watchtower is what keeps nzbfast current,
and it needs the Docker socket to recreate containers. That access is
root-equivalent on your NAS, so it is a real trade: convenience against
handing one container broad control. If you would rather not, delete the
`watchtower` block and update by hand (see [Updating](#updating)). As
written it is scoped to the `nzbfast` container by the name at the end of
the `command` line, so it will never touch your other containers.

---

## Route B - Container Manager (search & click)

No text files at all. The trade-off: a container built this way **cannot
auto-update**, because Container Manager's volume picker only browses
shared folders and so cannot mount the Docker socket that Watchtower
needs. You update it by hand, a few clicks each release.

1. **Make the folders.** File Station → create a shared folder or a
   sub-tree to hold the container's data, e.g.:

   ```
   /docker/nzbfast/config       ← settings + index database
   /docker/nzbfast/downloads    ← finished files land here
   /docker/nzbfast/watch        ← drop an .nzb here to auto-download it
   ```

2. **Get the image.** Container Manager → **Registry** → search
   **`nzbfast`** → select **`nzbfast/nzbfast`** → **Download** → tag
   **`latest`**.

3. **Create the container.** Container Manager → **Image** → select
   `nzbfast/nzbfast:latest` → **Run**. In the wizard:

   - **General:** turn on *Enable auto-restart*.
   - **Port Settings:** map **Local port `6789` → Container port `6789`**
     (change the Local port only if 6789 is already taken on your NAS).
   - **Volume Settings - add three folder mounts:**

     | Folder (on your NAS)          | Mount path in container |
     | ----------------------------- | ----------------------- |
     | `/docker/nzbfast/config`      | `/config`               |
     | `/docker/nzbfast/downloads`   | `/downloads`            |
     | `/docker/nzbfast/watch`       | `/watch`                |

   - **Environment:** add these variables:

     | Variable | Value                         |
     | -------- | ----------------------------- |
     | `PUID`   | your uid (e.g. `1026`)        |
     | `PGID`   | your gid (e.g. `100`)         |
     | `TZ`     | your timezone, e.g. `Europe/London` |

4. **Run it**, then jump to [First run](#first-run-add-your-provider).

---

## First run - add your provider

There is **no config file to edit.** Open the dashboard:

```
http://YOUR_NAS_IP:6789
```

The page asks for an **API key** before it shows you anything. nzbfast
generated one for itself when the container first started, so that your
dashboard is not open to everything on your network. Two places to find
it:

- **Container Manager → your container → Log.** It is printed once, near
  the top of the first start, on the line beginning `API key:`.
- **File Station → `/docker/nzbfast/config/apikey`** - the same value, kept
  so it survives restarts and image updates.

Paste it in once; the browser remembers it. Keep it to hand, because
Sonarr, Radarr and phone apps need the same value. To pick your own
instead, set `NZBFAST_APIKEY` on the container, or change it later in
Settings → Security.

Then a **Welcome** panel asks for your Usenet server. Enter the
host, username, password and (optionally) connection count from your
provider's welcome email, and click save. It applies immediately - no
restart. That's it; drop an `.nzb` on the dashboard, or into the `watch`
folder, and it downloads.

---

## Connecting Sonarr / Radarr / Prowlarr

nzbfast speaks the SABnzbd API. In your *arr app, add a **SABnzbd**
download client:

- **Host:** your NAS IP  **Port:** `6789`
- **API Key:** the same key you typed into the dashboard - the generated
  one from [First run](#first-run-add-your-provider), or whatever you set
  as `NZBFAST_APIKEY` on the container (Environment tab, or the commented
  line in the compose file).

It also exposes the NZBGet JSON-RPC API, so nzb360 / LunaSea connect the
same way.

---

## Updating

The **image is the update channel** - nzbfast in a container never swaps
its own binary (it's a managed/"bundled" install), so you move it forward
by pulling a newer image. Your `config` and `downloads` survive, because
they live in your NAS folders and not inside the container.

- **Automatically**, if you took Route A and kept the `watchtower`
  service: nothing to do. It checks nightly at 04:00 and recreates the
  container when a new version ships.
- **By hand, in a Project:** Container Manager → **Project** → `nzbfast`
  → **Stop**, then **Build** (this re-pulls `latest`), then **Start**.
- **By hand, Route B:** Container Manager → **Registry** → re-download
  the `latest` tag → then **Container** → stop nzbfast → **Action →
  Reset/Clear** to recreate it on the new image.

**Check your image tag first.** All of the above assumes your container
is on `nzbfast/nzbfast:latest`. If it is pinned to a version, say
`:1.0.3`, then neither Watchtower nor a re-pull will ever move it: both
fetch the tag the container was created with. Container Manager →
**Container** → **Details** shows which one you have.

---

## Troubleshooting

- **Downloads folder "permission denied" / files owned by root** - your
  `PUID`/`PGID` don't match the folder's owner. Re-check them with
  `id your_dsm_username` and fix the Environment values. This is the
  single most common issue.
- **Can't reach the dashboard** - confirm the container is running and
  that you mapped the port. If something else on the NAS uses 6789,
  remap the *local* side (e.g. `6889:6789`) and browse to `:6889`.
- **`nzbfast` doesn't appear in Registry search** - make sure you're
  searching the **Registry** tab (not *Image*), and that your NAS has
  internet access. You can also pull it by exact name
  `nzbfast/nzbfast`.
- **Nothing downloads** - open the dashboard; if the Welcome panel is
  still showing, the provider hasn't been saved yet.
- **Auto-update never fires** - check the container is on the `latest`
  tag rather than a pinned version, and that the schedule ran in your
  timezone (set `TZ` on the watchtower service, or `0 0 4 * * *` means
  04:00 UTC). `sudo docker logs nzbfast-watchtower` shows its next run.

---

## Which Synology models?

Any DSM 7 model with Container Manager (and most DSM 6 models with
Docker). Both Intel (x86-64) and ARM64 units are covered by the same
multi-arch image. Very low-end ARMv7/32-bit models are not supported -
they're below the workload nzbfast is built for.
