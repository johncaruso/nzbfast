package app.nzbfast.mobile.api

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Snapshot tests: the parsers run against responses recorded from a
 * real daemon (1.0.16, chaos_serve-backed; see CONTRACT.md for the
 * recording recipe). If the daemon's shapes drift, these fail before
 * the app does.
 */
class ParseSnapshotTest {

    private fun snap(name: String): String =
        javaClass.classLoader!!.getResourceAsStream("snapshots/$name")!!
            .readBytes().toString(Charsets.UTF_8)

    @Test
    fun version() {
        assertEquals("4.5.0", Parse.version(snap("version.json")))
    }

    @Test
    fun queueDownloading() {
        val q = Parse.queue(snap("queue_downloading.json"))
        assertFalse(q.paused)
        assertEquals("Downloading", q.status)
        assertEquals(1, q.slots.size)
        val s = q.slots[0]
        assertEquals("SABnzbd_nzo_nzbfast1", s.nzoId)
        assertEquals("chaos-video", s.name)
        assertEquals("Downloading", s.status)
        assertEquals(7f, s.percentage, 0.01f)
        assertEquals(91.53, s.mb, 0.01)
        assertEquals(84.25, s.mbLeft, 0.01)
        assertEquals("fetching", s.activity)
    }

    @Test
    fun queueEmpty() {
        val q = Parse.queue(snap("queue_empty.json"))
        assertTrue(q.slots.isEmpty())
    }

    @Test
    fun historyCompleted() {
        val h = Parse.history(snap("history_completed.json"))
        assertEquals(1, h.size)
        assertEquals("chaos-video", h[0].name)
        assertEquals("Completed", h[0].status)
        assertEquals("91.5 MB", h[0].size)
        assertTrue(h[0].completedAt > 0)
    }

    @Test
    fun addFileOk() {
        val r = Parse.addResult(snap("addfile.json"))
        assertTrue(r.ok)
        assertEquals(listOf("SABnzbd_nzo_nzbfast1"), r.nzoIds)
        assertNull(r.error)
    }

    @Test
    fun addNzbLnkBad() {
        val r = Parse.addResult(snap("addnzblnk_bad.json"))
        assertFalse(r.ok)
        assertTrue(r.nzoIds.isEmpty())
        assertEquals("that is not an nzblnk link", r.error)
    }

    @Test
    fun probeLiveIsPlayable() {
        val p = Parse.probe(snap("probe_live.json"))
        // Mid-download with the container parsed: media != null is the
        // Play affordance signal, exactly what the dashboard keys on.
        assertTrue(p.mediaReady)
        assertFalse(p.pending)
        assertEquals("Chaos.Test.Pattern.2026.720p.WEB.x264-BENCH.mkv", p.file)
    }

    @Test
    fun probeDiskIsPlayable() {
        val p = Parse.probe(snap("probe_disk.json"))
        assertTrue(p.mediaReady)
    }

    @Test
    fun serversConfigured() {
        assertTrue(Parse.serversConfigured(snap("get_config.json")))
    }

    @Test
    fun serverTestGreeting() {
        val r = Parse.serverTest(snap("server_test.json"))
        assertTrue(r.ok)
        assertEquals("200 mock ready", r.detail)
    }

    @Test
    fun serverSaveOk() {
        assertTrue(Parse.statusOk(snap("server_save.json")))
    }

    @Test
    fun globalPauseResume() {
        assertTrue(Parse.statusOk(snap("pause_all.json")))
        assertTrue(Parse.statusOk(snap("resume_all.json")))
        assertFalse(Parse.statusOk(snap("job_pause_missing.json")))
    }

    @Test
    fun wrongKeyIsStatusFalse() {
        assertFalse(Parse.statusOk(snap("auth_wrong_key.json")))
    }

    @Test
    fun m3uCarriesTokenUrl() {
        val url = Parse.m3uUrl(snap("m3u.txt"))
        assertNotNull(url)
        assertTrue(url!!.contains("/stream/SABnzbd_nzo_nzbfast1?t="))
        assertFalse(url.contains("apikey"))
    }

    // --- playback contract v1 (mode=playback, mode=stream_token) ---

    /** Early in a download: bytes are moving, nothing is playable yet. */
    @Test
    fun playbackPendingIsHonestlyNotReady() {
        val p = Parse.playback(snap("playback_pending.json"))
        assertEquals(1, p.contract)
        assertFalse(p.paused)
        assertEquals(1, p.queue.size)
        assertTrue(p.history.isEmpty())
        val j = p.queue[0]
        assertEquals("Downloading", j.status)
        assertFalse(j.playback.ready)
        assertEquals("pending", j.playback.reason)
        assertNull(j.playback.file)
    }

    /** Mid-download, container parsed: this is the Play affordance. */
    @Test
    fun playbackLiveIsPlayableWhileDownloading() {
        val p = Parse.playback(snap("playback_live.json"))
        val j = p.queue[0]
        assertTrue(j.playback.ready)
        assertEquals("live", j.playback.reason)
        assertEquals("live", j.playback.source)
        assertEquals("movie.mkv", j.playback.file)
        // tail_ok too, so scrubbing will work.
        assertTrue(j.playback.seekable)
        // Numbers arrive as numbers - no string parsing on this call.
        assertEquals(56f, j.percentage, 0.01f)
        assertEquals(2.86, j.mb, 0.01)
        // The play URL carries the job's scoped token, never the key.
        assertTrue(j.stream.contains("?t="))
        assertFalse(j.stream.contains("apikey"))
    }

    /** Finished: the answer moves to disk and stays ready. */
    @Test
    fun playbackDoneReadsFromDisk() {
        val p = Parse.playback(snap("playback_done.json"))
        assertTrue(p.queue.isEmpty())
        val j = p.history[0]
        assertEquals("Completed", j.status)
        assertTrue(j.playback.ready)
        assertEquals("disk", j.playback.reason)
        assertTrue(j.playback.size > 0)
        assertEquals(100.0, j.playback.pct, 0.01)
        // The overlay's telemetry rides the same response.
        assertEquals(3000L, p.stream.runwayWaitMs)
        assertEquals(0L, p.stream.zeroFilledBytes)
    }

    @Test
    fun streamTokenMintsAScopedUrl() {
        val url = Parse.streamToken(snap("stream_token.json"))
        assertNotNull(url)
        assertTrue(url!!.contains("/stream/SABnzbd_nzo_nzbfast1?t="))
        assertFalse(url.contains("apikey"))
        // A job the daemon does not have gets no token at all.
        assertNull(Parse.streamToken(snap("stream_token_unknown.json")))
    }
}
