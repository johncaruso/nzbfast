use super::*;

/// The library pointer Jellyfin/Emby index: a one-line .strm whose URL
/// plays (and on first play, downloads) the job. 127.0.0.1 is a
/// placeholder - the daemon only knows its own port, not its public host.
pub(super) fn write_strm(
    out_dir: &std::path::Path,
    name: &str,
    port: u16,
    nzo_id: &str,
    token: &str,
) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;
    let path = out_dir.join(nzbkit::disk::sanitize_filename(&format!("{name}.strm")));
    std::fs::write(
        &path,
        format!("http://127.0.0.1:{port}/stream/{nzo_id}?t={token}\n"),
    )?;
    info!(target: "library", "wrote {}", path.display());
    Ok(())
}

/// Largest media-extension writer in the extractor owned by `want` (the
/// M11 active stream when `want` is None), if any. Resolving ownership and
/// reading the writers off the same cloned extractor keeps the pick tied to
/// the job the caller verified.
/// What counts as the thing a player wants. One list, so the live pick
/// and the finished-download pick cannot disagree about which file the
/// ▶ button means.
pub(super) const MEDIA_EXTS: [&str; 6] = [".mkv", ".mp4", ".avi", ".m4v", ".ts", ".wmv"];

pub(super) fn is_media_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    MEDIA_EXTS.iter().any(|x| l.ends_with(x))
}

pub(super) fn pick_media(
    d: &Daemon,
    want: Option<&str>,
) -> Option<(String, Arc<nzbkit::disk::FileWriter>)> {
    let ex = d.hub.extractor_for(want)?;
    let mut ws = ex.writers_snapshot();
    ws.retain(|(n, _)| is_media_name(n));
    ws.sort_by_key(|(_, w)| std::cmp::Reverse(w.size));
    ws.into_iter().next()
}

/// The biggest media file inside a finished job's output folder - the
/// feature, not the sample or the extra. Season packs unpack into
/// subfolders, so the walk descends, but only a little: a bounded walk
/// cannot be talked into scanning a whole disk by a deep archive.
///
/// Symlinks are never followed and never served. A RAR can carry one,
/// and "biggest .mkv in the folder" would otherwise happily resolve a
/// planted link to any file the daemon can read.
pub(super) fn find_completed_media(dir: &std::path::Path) -> Option<PathBuf> {
    const MAX_DEPTH: u32 = 4;
    const MAX_ENTRIES: usize = 5_000;
    let mut best: Option<(u64, PathBuf)> = None;
    let mut seen = 0usize;
    let mut stack = vec![(dir.to_path_buf(), 0u32)];
    while let Some((d, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            if seen >= MAX_ENTRIES {
                break;
            }
            seen += 1;
            let p = e.path();
            // symlink_metadata: a link is judged as a link, not as
            // whatever it points at.
            let Ok(md) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if md.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((p, depth + 1));
                }
            } else if md.is_file()
                && is_media_name(&e.file_name().to_string_lossy())
                && best.as_ref().is_none_or(|(sz, _)| md.len() > *sz)
            {
                best = Some((md.len(), p));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Serve a file from disk with Range support, for players. The live
/// [`serve_range`] cannot do this job: it reads through a
/// `FileWriter` and blocks waiting for a write frontier that, for a
/// finished download, will never move again.
pub(super) fn serve_file_range(req: tiny_http::Request, path: &std::path::Path) {
    let Ok(mut f) = std::fs::File::open(path) else {
        let _ = req.respond(tiny_http::Response::from_string("gone").with_status_code(410));
        return;
    };
    let total = f.metadata().map(|m| m.len()).unwrap_or(0);
    let range = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Range"))
        .and_then(|h| byte_range(h.value.as_str(), total));
    let (start, end, status) = match range {
        Some((s, e)) => (s, e, 206),
        None => (0, total, 200),
    };
    use std::io::{Read, Seek};
    if f.seek(std::io::SeekFrom::Start(start)).is_err() {
        let _ = req.respond(tiny_http::Response::from_string("unreadable").with_status_code(500));
        return;
    }
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ctype: &[u8] = if name.to_ascii_lowercase().ends_with(".mp4") {
        b"video/mp4"
    } else {
        b"video/x-matroska"
    };
    let len = end - start;
    let mut resp = tiny_http::Response::new(
        tiny_http::StatusCode(status),
        vec![
            tiny_http::Header::from_bytes(&b"Content-Type"[..], ctype).unwrap(),
            tiny_http::Header::from_bytes(&b"Accept-Ranges"[..], &b"bytes"[..]).unwrap(),
            tiny_http::Header::from_bytes(&b"Content-Length"[..], len.to_string().into_bytes())
                .unwrap(),
        ],
        f.take(len),
        Some(len as usize),
        None,
    )
    // Identity encoding with an exact length, as the live path does:
    // players seek against Content-Length and dislike chunked video.
    .with_chunked_threshold(usize::MAX);
    if status == 206 {
        resp.add_header(
            tiny_http::Header::from_bytes(
                &b"Content-Range"[..],
                format!("bytes {start}-{}/{total}", end - 1).into_bytes(),
            )
            .unwrap(),
        );
    }
    let _ = req.respond(resp);
}

/// One /stream request. `want = None` keeps the M11 contract (active
/// download, single attempt). `want = Some(id)` is M14i on-demand playback:
/// a parked library job is force-enqueued and we wait (≤30 s) for its
/// writers to appear before giving up. `authed` (API key or per-job token,
/// always true on keyless installs) gates that force-enqueue - it mutates
/// queue state, and nzo_ids are enumerable, so without the gate any LAN
/// host or CSRF page could start downloads past a user pause.
pub(super) fn stream_request(
    d: Arc<Daemon>,
    req: tiny_http::Request,
    want: Option<String>,
    authed: bool,
) {
    let mut deadline = Instant::now();
    if let Some(id) = &want {
        let parked = d
            .history
            .lock()
            .unwrap()
            .iter()
            .find(|j| j.lock_ok().nzo_id == *id)
            .cloned();
        let queued = d
            .queue
            .lock()
            .unwrap()
            .iter()
            .any(|j| j.lock_ok().nzo_id == *id);
        if parked.is_none() && !queued {
            let _ = req
                .respond(tiny_http::Response::from_string("unknown nzo_id").with_status_code(404));
            return;
        }
        if let Some(job) = parked {
            // Never-fetched library entry: this play IS the download
            // trigger. Front of the queue, force → starts even if paused.
            let trigger = {
                let mut j = job.lock_ok();
                if j.library && !j.fetched && j.state == JobState::Completed {
                    if !authed {
                        drop(j);
                        let blocked = d.note_auth_failure(peer_ip(&req), "stream start");
                        let _ = req.respond(if blocked {
                            tiny_http::Response::from_string("too many bad keys")
                                .with_status_code(429)
                        } else {
                            tiny_http::Response::from_string(
                                "starting this download needs an apikey or stream token (?t=)",
                            )
                            .with_status_code(401)
                        });
                        return;
                    }
                    j.state = JobState::Queued;
                    // Force priority: pick_job starts it even while the
                    // queue is paused (the M14a semantics).
                    j.priority = 2;
                    j.paused = false;
                    true
                } else {
                    false
                }
            };
            if trigger {
                d.history.lock_ok().retain(|x| !Arc::ptr_eq(x, &job));
                d.queue.lock_ok().push_front(job);
                d.save_queue();
                info!(target: "library", "/stream/{id} → fetching now");
            } else {
                // A download that already FINISHED: its bytes are on
                // disk, not in the pipeline, so the live path below would
                // wait 30 s for media that is never coming and then 404.
                // That gap was visible in the UI - "play the copy you
                // have" could only open the file in the daemon's own
                // player, which does nothing a remote viewer can see.
                //
                // Byte-serving the LIVE pipeline is deliberately open
                // (players cannot send API keys, and it only ever carries
                // the download in front of you). A finished job is
                // different: nzo_ids are enumerable, so this would hand
                // any LAN host the user's library a guess at a time. It
                // takes the same key-or-token gate as the library
                // trigger, and the /m3u handoff already embeds the token.
                // `filed` + the stem + the tail it was FILED with come
                // along because a filed job's out_dir is the shared
                // `Show/Season NN` folder: "the biggest media file in
                // there" is a sibling episode as often as not.
                let (done, dir, filed, stem, tail) = {
                    let j = job.lock_ok();
                    let sfx = delete_tail(&j, || d.job_suffix(filed_stem(&j)));
                    (
                        j.state == JobState::Completed && j.fetched && !j.tombstone,
                        j.out_dir.clone(),
                        j.filed,
                        filed_stem(&j).to_string(),
                        sfx,
                    )
                };
                if done {
                    if !authed {
                        let blocked = d.note_auth_failure(peer_ip(&req), "stream completed");
                        let _ = req.respond(if blocked {
                            tiny_http::Response::from_string("too many bad keys")
                                .with_status_code(429)
                        } else {
                            tiny_http::Response::from_string(
                                "playing a finished download needs an apikey or stream token (?t=)",
                            )
                            .with_status_code(401)
                        });
                        return;
                    }
                    // A private out_dir is all this job's, so the biggest
                    // media file in it is the feature. A shared season
                    // folder is not, and only the episode this job filed
                    // may be served out of it.
                    let found = if filed {
                        crate::smart::find_filed_episode_media(&dir, &stem, &tail)
                    } else {
                        find_completed_media(&dir)
                    };
                    match found {
                        Some(p) => serve_file_range(req, &p),
                        // Moved away by hand, deleted, or a download with
                        // no video in it. Say which, rather than the live
                        // path's "no active media".
                        None => {
                            let _ = req.respond(
                                tiny_http::Response::from_string(
                                    "this download has no playable file on disk any more",
                                )
                                .with_status_code(404),
                            );
                        }
                    }
                    return;
                }
            }
        }
        deadline = Instant::now() + std::time::Duration::from_secs(30);
    }
    loop {
        // Only serve hub bytes that belong to the requested job.
        let owner_ok = match &want {
            None => true,
            Some(id) => d.active_stream.lock_ok().as_deref() == Some(id.as_str()),
        };
        if owner_ok && let Some((name, w)) = pick_media(&d, want.as_deref()) {
            // Encrypted store outputs are ciphertext on disk until the
            // finish decrypt - open_stream hands back a decryptor so
            // they stream mid-download, and the fd it returns stays
            // valid straight through the decrypt (that pass publishes
            // by rename and never mutates the inode we hold), so there
            // is nothing to wait for. Cloning through extractor_for
            // ties the open to the SAME job that owns `name`, so a job
            // transition mid-request cannot serve another job's bytes.
            let opened = d
                .hub
                .extractor_for(want.as_deref())
                .map(|ex| ex.open_stream(&name));
            let (pre_opened, crypt) = match opened {
                Some(nzbkit::extract::StreamOpen::Encrypted(f, c)) => (Some(f), Some(c)),
                _ => (None, None),
            };
            let seek = d.hub.seek.lock_ok().clone();
            serve_range(
                req,
                &name,
                w,
                pre_opened,
                crypt,
                seek,
                d.hub.stream_readers.clone(),
                d.hub.stream_gen.clone(),
                d.hub.stream_alive.clone(),
            );
            return;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = req.respond(tiny_http::Response::from_string("no active media").with_status_code(404));
}

// ---------------------------------------------------------------------------
// §73 phase 1: the preview-and-verify probe
// ---------------------------------------------------------------------------

/// The still-downloading main video of `id`, as something the probe can
/// read: its output name, its writer, and a reader that answers
/// `WouldBlock` for bytes that have not landed.
///
/// `None` means there is nothing to read yet - `id` is not the job the
/// pipeline is running, it has written no media file (an archive shape
/// that only produces one at unpack time), or the writer's backing file
/// has already been published away because the job finished. That last
/// case is NOT an error: the answer moved to disk, and both callers fall
/// through to the on-disk path.
///
/// Encrypted-store outputs are ciphertext on disk until the finish
/// decrypt, so this hands back the same decryptor the byte-serving path
/// uses.
pub(super) fn open_live_probe(
    d: &Daemon,
    id: &str,
) -> Option<(
    String,
    Arc<nzbkit::disk::FileWriter>,
    nzbkit::mediaprobe::LiveProbeReader,
)> {
    let live = d.active_stream.lock_ok().as_deref() == Some(id);
    if !live {
        return None;
    }
    let (name, w) = pick_media(d, Some(id))?;
    let (f, crypt) = match d
        .hub
        .extractor_for(Some(id))
        .map(|ex| ex.open_stream(&name))
    {
        Some(nzbkit::extract::StreamOpen::Encrypted(f, c)) => (f, Some(c)),
        _ => (std::fs::File::open(&w.path).ok()?, None),
    };
    let r = nzbkit::mediaprobe::LiveProbeReader {
        w: w.clone(),
        f,
        crypt,
        pos: 0,
    };
    Some((name, w, r))
}

/// The finished main video of `job` on disk. A private `out_dir` is all
/// this job's, so the biggest media file in it is the feature; a shared
/// season folder is not, and only the episode this job filed may be read
/// out of it.
pub(super) fn finished_media_path(d: &Daemon, job: &Arc<Mutex<Job>>) -> Option<PathBuf> {
    let (dir, filed, stem, tail) = {
        let j = job.lock_ok();
        let sfx = delete_tail(&j, || d.job_suffix(filed_stem(&j)));
        (j.out_dir.clone(), j.filed, filed_stem(&j).to_string(), sfx)
    };
    if filed {
        crate::smart::find_filed_episode_media(&dir, &stem, &tail)
    } else {
        find_completed_media(&dir)
    }
}

/// One `GET /preview/probe/{nzo_id}` - what the file IS, from whatever
/// bytes have landed.
///
/// Deliberately cheap and deliberately non-blocking: the probe reads
/// container headers only (a few hundred KB at most, and never the
/// payload), and reports a region that has not downloaded yet as
/// "pending" rather than waiting for it. The client polls; nothing here
/// holds a worker thread the way [`stream_request`] can.
///
/// The one thing it DOES ask the download for is a promotion: a file
/// whose index sits at the end (a moov-at-end MP4, Matroska's
/// SeekHead-indexed Chapters) cannot be read until that tail arrives, so
/// the probe pulls the same tail window the playhead promotion keeps hot
/// and answers "pending" this time round. The next poll usually has it.
pub(super) fn preview_probe_request(d: Arc<Daemon>, req: tiny_http::Request, id: String) {
    let mut body = serde_json::json!({
        "nzo_id": id,
        "file": serde_json::Value::Null,
        "size": 0,
        "coverage": serde_json::Value::Null,
        "source": "none",
        "pending": false,
        "media": serde_json::Value::Null,
    });

    if let Some((name, w, mut r)) = open_live_probe(&d, &id) {
        let need_tail = fill_live_probe(&mut body, &name, &w, || {
            nzbkit::mediaprobe::probe(
                &mut r,
                nzbkit::mediaprobe::ProbeHint {
                    filename: Some(name.clone()),
                    known_size: Some(w.size),
                },
            )
        });
        if need_tail && let Some(sc) = d.hub.seek.lock_ok().clone() {
            // The index is in the part that has not arrived. Ask for it
            // the same way a seek does; the poll after next reads it.
            let (n, _) = promote_playhead(&sc, &name, &w, 0);
            if n > 0 {
                info!(target: "preview", "{id}: promoted {n} article(s) for the file index");
            }
        }
        let _ = req.respond(json_resp(body));
        return;
    }

    // Not the live job: a finished download's bytes are on disk.
    let Some(job) = d.history_job(&id) else {
        let _ = req.respond(
            json_resp(serde_json::json!({"error": "unknown or not yet downloading"}))
                .with_status_code(404),
        );
        return;
    };
    let Some(path) = finished_media_path(&d, &job) else {
        let _ = req.respond(
            json_resp(serde_json::json!({"error": "no playable file on disk"}))
                .with_status_code(404),
        );
        return;
    };
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    body["file"] = name.clone().into();
    body["size"] = size.into();
    body["source"] = "disk".into();
    body["coverage"] = serde_json::json!({"head_bytes": size, "pct": 100.0, "tail_ok": true});
    match std::fs::File::open(&path) {
        Ok(mut f) => {
            match nzbkit::mediaprobe::probe(
                &mut f,
                nzbkit::mediaprobe::ProbeHint {
                    filename: Some(name),
                    known_size: Some(size),
                },
            ) {
                Ok(info) => {
                    body["media"] = serde_json::to_value(&info).unwrap_or(serde_json::Value::Null)
                }
                Err(e) => body["error"] = e.to_string().into(),
            }
            let _ = req.respond(json_resp(body));
        }
        Err(_) => {
            let _ = req.respond(json_resp(body).with_status_code(410));
        }
    }
}

/// The live half of a probe answer: what the walk read, and the
/// coverage it ran under. Returns true when the file's index sits in
/// bytes that have not arrived, so the caller should promote the tail.
///
/// **The order is the contract: walk first, sample coverage after.**
/// Coverage only ever grows, and the walk cannot read a byte that is
/// not covered, so a snapshot taken first can describe less of the file
/// than the parse went on to read - and `head_bytes: 0` beside a fully
/// parsed container is not a state the download was ever in, it is two
/// instants in one answer. Sampling last cannot under-report what the
/// parse used, which makes the whole class structurally impossible
/// rather than merely unlikely. The reverse staleness is harmless: a
/// region that lands mid-walk shows up as coverage the parse did not
/// use yet, and the next poll reads it.
fn fill_live_probe(
    body: &mut serde_json::Value,
    name: &str,
    w: &Arc<nzbkit::disk::FileWriter>,
    probe: impl FnOnce() -> Result<nzbkit::mediaprobe::MediaInfo, nzbkit::mediaprobe::ProbeError>,
) -> bool {
    let info = probe();
    let covered = w.contiguous_from_start();
    let tail_from = w.size.saturating_sub(TAIL_KEEP);
    let tail_ok = w.covered(tail_from, w.size - tail_from);
    body["file"] = name.into();
    body["size"] = w.size.into();
    body["source"] = "live".into();
    body["coverage"] = serde_json::json!({
        "head_bytes": covered,
        "pct": if w.size > 0 { (covered as f64 * 100.0 / w.size as f64 * 10.0).round() / 10.0 } else { 0.0 },
        "tail_ok": tail_ok,
    });
    match info {
        Ok(info) => {
            let need_tail = !info.complete && !tail_ok;
            body["pending"] = (!info.complete).into();
            body["media"] = serde_json::to_value(&info).unwrap_or(serde_json::Value::Null);
            need_tail
        }
        // Not enough bytes to even identify the container: a poll, not
        // an error - this is a download that just started.
        Err(nzbkit::mediaprobe::ProbeError::NotYet) => {
            body["pending"] = true.into();
            false
        }
        Err(e) => {
            body["error"] = e.to_string().into();
            false
        }
    }
}

// ---------------------------------------------------------------------------
// M11: HTTP range streaming over a still-downloading file
// ---------------------------------------------------------------------------

/// Reader that refuses to run ahead of the writer: each chunk waits until
/// its bytes are really on disk (bounded poll), so a media player can sit
/// on a socket while the download races ahead of the playhead.
pub(super) struct LiveRangeReader {
    w: Arc<nzbkit::disk::FileWriter>,
    f: std::fs::File,
    /// Present iff the backing file is encrypted-store ciphertext:
    /// reads are CBC-decrypted on the fly (holds a live-reader lease so
    /// finish() temp+renames rather than mutating this file's inode).
    crypt: Option<nzbkit::extract::StreamCrypt>,
    pos: u64,
    end: u64,
    /// M11 seek promotion: handle + our output name. `promoted_to` is the
    /// end of the last promoted window - the reader keeps it rolling
    /// AHEAD of the playhead so the next span is fetching before the
    /// player ever blocks on it (reactive-only promotion guaranteed a
    /// visible stall at every window boundary).
    seek: Option<Arc<crate::SeekCtl>>,
    name: String,
    promoted_to: u64,
    /// Attached-reader gauge (drives the pool's hot lane); decremented on
    /// drop so an abandoned player connection frees the lane.
    readers: Arc<std::sync::atomic::AtomicUsize>,
    /// This reader's generation vs the set of ALIVE readers: only the
    /// newest living /stream request may promote (players open a fresh
    /// request per seek; a superseded reader steering the queue causes
    /// ping-pong, and a dead probe must hand rights back).
    my_gen: u64,
    alive: Arc<std::sync::Mutex<std::collections::BTreeSet<u64>>>,
}

impl LiveRangeReader {
    fn newest_alive(&self) -> bool {
        self.alive.lock_ok().iter().next_back() == Some(&self.my_gen)
    }

    /// Is plaintext `[pos, pos+len)` serveable now? For an encrypted
    /// stream this widens to the ciphertext blocks (plus the CBC IV
    /// block) that decrypting the range requires.
    fn covered(&self, pos: u64, len: u64) -> bool {
        match &self.crypt {
            Some(c) => {
                let (lo, clen) = c.covered_bounds(pos, len);
                self.w.covered(lo, clen)
            }
            None => self.w.covered(pos, len),
        }
    }
}

impl Drop for LiveRangeReader {
    fn drop(&mut self) {
        self.readers.fetch_sub(1, Ordering::Relaxed);
        self.alive.lock_ok().remove(&self.my_gen);
    }
}

/// Bytes promoted ahead of the playhead (~85 ms of line time at 3 Gbps -
/// a promoted window lands before the player drains its own buffer).
pub(super) const SEEK_READAHEAD: u64 = 32_000_000;
/// Re-promote when the playhead gets this close to the promoted edge -
/// the next window is fetching while the current one still has runway.
pub(super) const ROLL_MARGIN: u64 = 12_000_000;

/// Runway: after a blocked read (a stall - the span wasn't there), hold
/// the response until this much contiguous data PAST the position has
/// landed, so the player buffers once and then streams smoothly instead
/// of stuttering span by span. Env NZBFAST_STREAM_RUNWAY_MB overrides
/// (0 = first covered chunk streams immediately, the old behavior).
pub(super) fn stream_runway() -> u64 {
    static RUNWAY: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *RUNWAY.get_or_init(|| {
        std::env::var("NZBFAST_STREAM_RUNWAY_MB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|mb| mb * 1_000_000)
            .unwrap_or(16_000_000)
    })
}

/// Bytes of file tail kept hot alongside the playhead window (matches the
/// queue-build tail burst; MKV Cues / MP4 moov live there).
pub(super) const TAIL_KEEP: u64 = 8_000_000;
/// Bytes promoted BEHIND the position: after a seek, players commonly
/// read slightly before the byte target too (preceding keyframe cluster,
/// audio preroll) - without this each such read is its own serial
/// blocked round-trip.
pub(super) const PRE_ROLL: u64 = 4_000_000;

/// One promotion covering the playhead window AND - while it's still
/// uncovered - the file tail. A single call because each promote rewrites
/// the queue's promoted set: promoting only [pos, pos+window] would
/// displace the tail-burst articles, and a player asks for the tail
/// (seek index) at any moment.
pub(super) fn promote_playhead(
    sc: &crate::SeekCtl,
    name: &str,
    w: &nzbkit::disk::FileWriter,
    pos: u64,
) -> (usize, u64) {
    let end = (pos + SEEK_READAHEAD).min(w.size);
    let tail = w.size.saturating_sub(TAIL_KEEP);
    let mut spans = vec![(pos.saturating_sub(PRE_ROLL), end)];
    if !w.covered(tail, w.size - tail) {
        spans.push((tail, w.size));
    }
    (sc.promote_output_spans(name, w.size, &spans, true), end)
}

impl std::io::Read for LiveRangeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.end {
            return Ok(0);
        }
        // Keep the pool's stream mode fresh for as long as the player
        // actually reads - pipelines stay shallow, promotions stay fast.
        if let Some(sc) = &self.seek {
            sc.note_stream();
        }
        let n = (buf.len() as u64).min(self.end - self.pos).min(256 * 1024) as usize;
        // Rolling readahead: keep [pos, pos+SEEK_READAHEAD] promoted as
        // the playhead advances. A no-op when the span is already fetched
        // (nothing pending to move), so linear playback behind the
        // frontier costs one compare per read.
        let current = self.newest_alive();
        if let Some(sc) = &self.seek {
            // promoted_to == size means the window already reaches EOF -
            // without that check the margin test fires on every read for
            // the file's last few MB (promote spam).
            if current
                && self.promoted_to < self.w.size
                && self.pos + ROLL_MARGIN > self.promoted_to
            {
                let (moved, end) = promote_playhead(sc, &self.name, &self.w, self.pos);
                self.promoted_to = end;
                if moved > 0 {
                    info!(
                        target: "stream",
                        "readahead@{} → promoted {moved} article(s)",
                        self.pos
                    );
                }
            }
        }
        // Wait (up to 5 min) for the span to land - a stalled provider
        // should buffer the player, not corrupt the stream. If we block
        // at all, wait for RUNWAY bytes, not just this chunk: the player
        // shows one buffering pause instead of a stutter per span.
        if !self.covered(self.pos, n as u64) {
            let runway = (n as u64).max((self.end - self.pos).min(stream_runway()));
            let mut waited = 0u64;
            while !self.covered(self.pos, runway) {
                std::thread::sleep(std::time::Duration::from_millis(50));
                waited += 50;
                // Re-issue the promotion occasionally while blocked: the
                // initial one is best-effort (bounded try_lock) and a new
                // fetch run may have started since (queue re-attach).
                if waited.is_multiple_of(2_000)
                    && let Some(sc) = &self.seek
                    && self.newest_alive()
                {
                    promote_playhead(sc, &self.name, &self.w, self.pos);
                }
                if waited > 300_000 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "span never arrived",
                    ));
                }
            }
        }
        match &self.crypt {
            Some(c) => c.decrypt_range(&self.f, self.pos, &mut buf[..n])?,
            None => nzbkit::disk::read_exact_at(&self.f, &mut buf[..n], self.pos)?,
        }
        self.pos += n as u64;
        Ok(n)
    }
}

/// The half-open byte span a `Range:` header asks for, clamped to a file
/// of `total` bytes. None means "no usable range" - serve the whole file.
///
/// Players send two forms and both have to work. `bytes=a-b` (and its
/// open-ended `bytes=a-`) is the seek. `bytes=-n` is the SUFFIX form: the
/// LAST n bytes, which is how a player finds a trailing MP4 moov box or
/// an MKV Cues element before it can play anything. Reading the suffix
/// form as a start offset fails, and the whole-file fallback then answers
/// a tail request with the HEAD of the file - the player waits out the
/// download for bytes it will never use.
pub(super) fn byte_range(v: &str, total: u64) -> Option<(u64, u64)> {
    let v = v.strip_prefix("bytes=")?;
    let (a, b) = v.split_once('-')?;
    if a.is_empty() {
        // Suffix. A tail longer than the file is the whole file, never an
        // underflowed start.
        let n: u64 = b.parse().ok()?;
        let start = total.saturating_sub(n);
        return (n > 0 && start < total).then_some((start, total));
    }
    let start: u64 = a.parse().ok()?;
    let end: u64 = if b.is_empty() {
        total
    } else {
        b.parse::<u64>().ok()?.saturating_add(1).min(total)
    };
    (start < end).then_some((start, end))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn serve_range(
    req: tiny_http::Request,
    name: &str,
    w: Arc<nzbkit::disk::FileWriter>,
    pre_opened: Option<std::fs::File>,
    crypt: Option<nzbkit::extract::StreamCrypt>,
    seek: Option<Arc<crate::SeekCtl>>,
    readers: Arc<std::sync::atomic::AtomicUsize>,
    latest_gen: Arc<std::sync::atomic::AtomicU64>,
    alive: Arc<std::sync::Mutex<std::collections::BTreeSet<u64>>>,
) {
    let total = w.size;
    let range = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Range"))
        .and_then(|h| byte_range(h.value.as_str(), total));
    let (start, end, status) = match range {
        Some((s, e)) => (s, e, 206),
        None => (0, total, 200),
    };
    // Encrypted streams pass their ciphertext fd in (opened under the
    // extractor lock so it can't race the finish rename); plain files
    // open here as before.
    let f = match pre_opened {
        Some(f) => f,
        None => match std::fs::File::open(&w.path) {
            Ok(f) => f,
            Err(_) => {
                let _ = req.respond(tiny_http::Response::from_string("gone").with_status_code(410));
                return;
            }
        },
    };
    // M11: a Range start past the write frontier IS a seek (players open
    // a fresh request per seek) - pull the articles under it to the queue
    // front before we start blocking on them. Becoming the newest
    // generation FIRST silences any superseded reader's re-promotes.
    let my_gen = latest_gen.fetch_add(1, Ordering::Relaxed) + 1;
    alive.lock_ok().insert(my_gen);
    let mut promoted_to = 0u64;
    if let Some(sc) = &seek {
        // Engage pool stream mode on every request, covered or not - the
        // player is here, and the next promote must find shallow windows.
        sc.note_stream();
        if !w.covered(start, (end - start).clamp(1, 1_000_000)) {
            let (n, to) = promote_playhead(sc, name, &w, start);
            promoted_to = to;
            if n > 0 {
                info!(target: "stream", "seek@{start} → promoted {n} article(s)");
            }
        }
    }
    let ctype: &[u8] = if name.to_ascii_lowercase().ends_with(".mp4") {
        b"video/mp4"
    } else {
        b"video/x-matroska"
    };
    readers.fetch_add(1, Ordering::Relaxed);
    let reader = LiveRangeReader {
        w,
        f,
        crypt,
        pos: start,
        end,
        seek,
        name: name.to_string(),
        promoted_to,
        readers,
        my_gen,
        alive,
    };
    // tiny_http chunks any body over ~1 MB even with a known length -
    // players want identity + exact Content-Length for seeking.
    let mut resp = tiny_http::Response::new(
        tiny_http::StatusCode(status),
        vec![
            tiny_http::Header::from_bytes(&b"Content-Type"[..], ctype).unwrap(),
            tiny_http::Header::from_bytes(&b"Accept-Ranges"[..], &b"bytes"[..]).unwrap(),
            tiny_http::Header::from_bytes(
                &b"Content-Length"[..],
                (end - start).to_string().into_bytes(),
            )
            .unwrap(),
        ],
        reader,
        Some((end - start) as usize),
        None,
    )
    .with_chunked_threshold(usize::MAX);
    if status == 206 {
        resp.add_header(
            tiny_http::Header::from_bytes(
                &b"Content-Range"[..],
                format!("bytes {start}-{}/{total}", end - 1).into_bytes(),
            )
            .unwrap(),
        );
    }
    let _ = req.respond(resp);
}

#[cfg(test)]
mod preview_probe_tests {
    use super::*;

    /// A probe answer must never claim less of the file than the parse
    /// it ships with demonstrably read.
    ///
    /// Coverage only ever grows, and the walk cannot read a byte that
    /// is not covered, so `head_bytes: 0` beside a parsed container is
    /// not a state the download was ever in - it is two different
    /// instants in one answer. This lands the head article DURING the
    /// walk, which is the interleaving a loaded box produces: seen as
    /// `{"coverage":{"head_bytes":0,"pct":0.0,"tail_ok":false},...
    /// "source":"live"}` with a fully parsed mkv beside it, twice in
    /// fourteen daemon-suite runs at load ~175.
    #[test]
    fn coverage_never_undercuts_the_parse_it_ships_with() {
        let dir = std::env::temp_dir().join(format!("nzbfast-probe-cov-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("movie.mkv");
        let data = nzbkit::mediaprobe::testmux::mkv_padded(2_000_000);
        let w = Arc::new(nzbkit::disk::FileWriter::create(&path, data.len() as u64).unwrap());
        let mut body = serde_json::json!({});

        let need_tail = fill_live_probe(&mut body, "movie.mkv", &w, || {
            // The article carrying the head lands while the walk runs.
            w.write_at(0, &data[..300_000]).unwrap();
            let mut r = nzbkit::mediaprobe::LiveProbeReader {
                w: w.clone(),
                f: std::fs::File::open(&path).unwrap(),
                crypt: None,
                pos: 0,
            };
            nzbkit::mediaprobe::probe(
                &mut r,
                nzbkit::mediaprobe::ProbeHint {
                    filename: Some("movie.mkv".into()),
                    known_size: Some(data.len() as u64),
                },
            )
        });

        // The walk read the container out of those 300 KB, so the
        // answer must say so.
        assert_eq!(body["media"]["container"], "mkv", "{body}");
        assert_eq!(body["pending"], false, "{body}");
        assert_eq!(body["coverage"]["head_bytes"], 300_000, "{body}");
        // Still mid-download: the tail has not arrived, and a complete
        // parse means there is no index to promote for.
        assert_eq!(body["coverage"]["tail_ok"], false, "{body}");
        assert!(!need_tail, "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod range_header_tests {
    use super::byte_range;

    const FILE: u64 = 100_000_000;

    /// A player that asks for the LAST bytes of the file gets the last
    /// bytes of the file. This is the first request an MP4 with a
    /// trailing moov (or an MKV reading its Cues) makes, and answering it
    /// with the head instead means the player sits through the whole
    /// download before it can start.
    #[test]
    fn a_tail_request_serves_the_tail() {
        assert_eq!(
            byte_range("bytes=-65536", FILE),
            Some((FILE - 65_536, FILE))
        );
        assert_eq!(byte_range("bytes=-1", FILE), Some((FILE - 1, FILE)));
    }

    /// Asking for more tail than there is file is the whole file, not a
    /// wrapped-around start offset near u64::MAX.
    #[test]
    fn a_tail_longer_than_the_file_is_the_whole_file() {
        assert_eq!(byte_range("bytes=-4096", 1_000), Some((0, 1_000)));
        assert_eq!(
            byte_range(&format!("bytes=-{}", u64::MAX), 1_000),
            Some((0, 1_000))
        );
    }

    /// The seek forms every player already used must be unchanged.
    #[test]
    fn seek_ranges_still_work() {
        assert_eq!(byte_range("bytes=0-99999", FILE), Some((0, 100_000)));
        assert_eq!(
            byte_range("bytes=20000000-20050000", FILE),
            Some((20_000_000, 20_050_001))
        );
        assert_eq!(byte_range("bytes=500-", 1_000), Some((500, 1_000)));
        // An end past the file clamps to the file.
        assert_eq!(byte_range("bytes=990-99999", 1_000), Some((990, 1_000)));
    }

    /// Anything we cannot honour is "no range", which serves the whole
    /// file under a 200 - never an empty or inverted span, because
    /// Content-Length is end - start and the reader is built from both.
    #[test]
    fn unusable_ranges_are_no_range_at_all() {
        for v in [
            "bytes=-0",        // zero-length tail
            "bytes=-",         // no number either side
            "bytes=-abc",      // unparseable tail
            "bytes=1000-",     // starts at EOF
            "bytes=1000-2000", // starts past EOF
            "bytes=abc-1",     // unparseable start
            "megabytes=0-1",   // not a byte range
            "0-99",            // no unit
        ] {
            assert_eq!(byte_range(v, 1_000), None, "{v}");
        }
        // A zero-length file has no span to hand out, tail or otherwise.
        assert_eq!(byte_range("bytes=-10", 0), None);
        assert_eq!(byte_range("bytes=0-9", 0), None);
    }

    /// Whatever comes back, the invariant the response headers rely on
    /// holds: a non-empty span inside the file.
    #[test]
    fn every_accepted_range_fits_the_file() {
        for v in [
            "bytes=-65536",
            "bytes=-99999999999",
            "bytes=0-",
            "bytes=0-0",
            "bytes=999-1000000",
            "bytes=1-2",
        ] {
            if let Some((start, end)) = byte_range(v, 1_000) {
                assert!(start < end && end <= 1_000, "{v} -> {start}..{end}");
            }
        }
    }
}
