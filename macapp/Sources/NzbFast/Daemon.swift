import Foundation
// Launcher handshake only (see `isNzbfast`): the engine proves it holds the
// token in runtime.json before this wrapper hands it the stored API key.
import CryptoKit

/// Owns the bundled `nzbfast serve` engine: attach to an already-running
/// daemon on the persisted port, or spawn our own as a managed child.
/// Program/data separation per packaging/INSTALLER-SPEC.md: binaries stay
/// in the bundle, mutable state in ~/Library/Application Support/nzbfast,
/// downloads in "~/Downloads/nzbfast downloads", and ~/Downloads itself
/// is the watch folder - save an .nzb anywhere you normally download and
/// it's queued automatically (only .nzb files are touched; the watcher
/// is non-recursive so the output folder below it is never scanned).
final class Daemon {
    static let shared = Daemon()

    let dataDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("nzbfast")
    /// The user's Downloads folder - watch target and output parent.
    let watchDir = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
    /// Pre-1.0.2 builds downloaded to ~/Downloads/nzbfast - keep using it
    /// when it already exists so an upgrade doesn't split the library.
    let downloadsDir: URL = {
        let dl = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        let legacy = dl.appendingPathComponent("nzbfast")
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: legacy.path, isDirectory: &isDir), isDir.boolValue {
            return legacy
        }
        return dl.appendingPathComponent("nzbfast downloads")
    }()
    var logURL: URL { dataDir.appendingPathComponent("daemon.log") }

    /// The port the dashboard lives on. Persisted so relaunches attach to
    /// the same daemon instead of scanning again.
    private(set) var port: Int = UserDefaults.standard.integer(forKey: "daemonPort")
    private(set) var child: Process?
    /// True when THIS app launched the engine - only then may quit stop it.
    private(set) var spawnedByUs = false
    /// Set before any stop we initiate, so terminationHandler can tell a
    /// crash from a requested exit.
    private var deliberateStop = false
    /// Called on the main queue when the child dies on its own.
    var onUnexpectedExit: ((String) -> Void)?

    var baseURL: URL { URL(string: "http://127.0.0.1:\(port)/")! }

    private var engineURL: URL {
        Bundle.main.resourceURL!.appendingPathComponent("bin/nzbfast")
    }

    /// The daemon's full API key. Two sources, in the daemon's own
    /// precedence order (serve.rs applies settings.json first, and
    /// first_run_apikey then bows out if a key is already set):
    ///   1. a key the user set in the dashboard - settings.json
    ///   2. the one the daemon minted for itself on a first run - the
    ///      `apikey` file next to config.local.json (serve::first_run_apikey
    ///      writes `config.with_file_name("apikey")`, and we pass
    ///      --config dataDir/config.local.json, so that is dataDir/apikey)
    /// An install that is deliberately keyless (NZBFAST_OPEN=1, or a
    /// pre-minting upgrade that never set one) has neither, and nil is the
    /// right answer there. Lets the wrapper authenticate its own
    /// housekeeping calls (shutdown, addfile, version).
    private var apiKey: String? {
        let fromSettings: String? = {
            let settings = dataDir.appendingPathComponent("settings.json")
            guard let data = try? Data(contentsOf: settings),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let key = obj["apikey"] as? String else { return nil }
            let k = key.trimmingCharacters(in: .whitespacesAndNewlines)
            return k.isEmpty ? nil : k
        }()
        if let fromSettings { return fromSettings }
        let keyfile = dataDir.appendingPathComponent("apikey")
        guard let raw = try? String(contentsOf: keyfile, encoding: .utf8) else { return nil }
        let k = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return k.isEmpty ? nil : k
    }

    /// The dashboard port saved in settings.json, if the user has set one.
    /// Read with the same approach as the apikey fallback above.
    ///
    /// The dashboard's Port setting is restart-only: it is persisted here
    /// and the engine's own apply_saved_settings overrides its `--port`
    /// with it at startup. So a saved port is the port the engine WILL
    /// bind whatever we ask for, and the wrapper has to follow it.
    private func savedPort() -> Int? {
        let settings = dataDir.appendingPathComponent("settings.json")
        guard let data = try? Data(contentsOf: settings),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return Daemon.savedPort(inSettings: obj)
    }

    /// Pull a usable port out of a decoded settings.json. Split out so the
    /// rule is testable without a file.
    ///
    /// Matches what the daemon accepts: a JSON number, and the same 1-65535
    /// range the config writer validates. Anything else (absent, null, a
    /// string, out of range) means "no saved port", which is exactly the
    /// case where the engine keeps the `--port` we pass it.
    static func savedPort(inSettings obj: [String: Any]) -> Int? {
        guard let n = obj["port"] as? NSNumber else { return nil }
        // JSON true bridges to NSNumber too and would read as port 1. The
        // daemon's as_u64 rejects a bool, so we reject it as well.
        guard CFGetTypeID(n as CFTypeRef) != CFBooleanGetTypeID() else { return nil }
        let p = n.intValue
        return (1...65535).contains(p) ? p : nil
    }

    /// Percent-encode a query value. The daemon urldecodes every query
    /// value and reads a bare `+` as a space, so a key with punctuation in
    /// it has to arrive encoded; the dashboard's URLSearchParams adoption
    /// hook decodes the same way. `%`-encoding everything outside the
    /// unreserved set keeps both readers honest.
    private func queryEscaped(_ s: String) -> String {
        var unreserved = CharacterSet.alphanumerics
        unreserved.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: unreserved) ?? s
    }

    func apiURL(_ mode: String, _ extra: String = "") -> URL {
        var q = "mode=\(mode)"
        if let k = apiKey { q += "&apikey=\(queryEscaped(k))" }
        if !extra.isEmpty { q += "&\(extra)" }
        return URL(string: "http://127.0.0.1:\(port)/api?\(q)")!
    }

    /// The dashboard URL to load, carrying the API key when we know one.
    /// web/dashboard.html adopts `?apikey=` into localStorage and then
    /// history.replaceState's it out of the address bar, so a fresh install
    /// isn't met by a prompt for a credential the daemon minted seconds
    /// earlier and only ever printed to a log this user never sees. A
    /// keyless install gets the plain baseURL, exactly as before.
    ///
    /// Only ever hand this to a port we have confirmed is nzbfast - i.e.
    /// after start() returns .attached/.spawned, never to a bare port
    /// number.
    var dashboardURL: URL {
        guard let k = apiKey else { return baseURL }
        return URL(string: "http://127.0.0.1:\(port)/?apikey=\(queryEscaped(k))") ?? baseURL
    }

    // MARK: probing

    /// What `runtime.json` says about the engine we expect to find: the
    /// port it bound, and the per-start secret it can prove it holds.
    /// Written by the engine once its listener exists; absent for an
    /// engine older than the handshake, or one started elsewhere.
    private func runtimeToken(forPort port: Int) -> String? {
        guard let data = try? Data(contentsOf: dataDir.appendingPathComponent("runtime.json")),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let filePort = obj["port"] as? Int, filePort == port,
              let token = (obj["token"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !token.isEmpty
        else { return nil }
        return token
    }

    /// sha256("token:nonce") as lowercase hex - the answer the engine
    /// returns for `hs=<nonce>`, computed here to compare with it.
    static func launcherProof(token: String, nonce: String) -> String {
        let digest = SHA256.hash(data: Data("\(token):\(nonce)".utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Does `port` answer /api?mode=version as an nzbfast daemon?
    /// A keyed daemon's refusal counts too: only nzbfast answers in that
    /// shape, and the dashboard is handed the key (or prompts) after attach.
    ///
    /// A reply shape is not identity, though, and a true answer here means
    /// attach-and-then-hand-over-the-API-key. So when `runtime.json` names
    /// THIS port, the listener must also prove it holds that file's token:
    /// any local account can print our JSON, but only this user can read
    /// that file (Application Support is user-only). The token never
    /// travels in either direction - the engine returns
    /// sha256(token:nonce) for a nonce we make up per probe - so probing an
    /// impostor teaches it nothing.
    ///
    /// An engine that answers with no proof while `runtime.json` names
    /// this port is REFUSED (see `provesIdentity`): a token in that file
    /// can only have been written by an engine that also answers the
    /// challenge, so proofless-with-token is a stranger, not an upgrade
    /// case. Only when there is no runtime.json for the port - the actual
    /// pre-handshake engine, or one from another data dir - is the reply
    /// shape alone accepted.
    func isNzbfast(port: Int, timeout: TimeInterval = 1.5) async -> Bool {
        // Probe WITHOUT the key. Nothing has authenticated the far side yet, so
        // any unprivileged local process that binds this port first (6789 is
        // well known and the port is readable from UserDefaults) would receive
        // the full API key in the query string - and that key unlocks
        // get_config/server_secret, i.e. the Usenet provider password in
        // cleartext. The key isn't needed here: the refusal phrases below are
        // signature enough, and only nzbfast answers in that shape.
        // The challenge rides the same keyless probe: a fresh nonce per
        // call, so a recorded answer cannot be replayed at us later.
        let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let q = "mode=version&hs=\(nonce)"
        guard let url = URL(string: "http://127.0.0.1:\(port)/api?\(q)") else { return false }
        var req = URLRequest(url: url)
        req.timeoutInterval = timeout
        guard let (data, _) = try? await URLSession.shared.data(for: req),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return false }
        guard Daemon.isNzbfastReply(obj) else { return false }
        return Daemon.provesIdentity(obj, token: runtimeToken(forPort: port), nonce: nonce)
    }

    /// The identity half of the probe, split out so it is testable without
    /// a socket. See `isNzbfast` for why each arm is what it is.
    static func provesIdentity(_ obj: [String: Any], token: String?, nonce: String) -> Bool {
        guard let token else {
            // Nothing to hold it to: no runtime.json for this port.
            return true
        }
        guard let proof = obj["hs_proof"] as? String else {
            // A token in runtime.json can only have been written by an
            // engine that also answers the challenge - the file write and
            // the proof reply shipped in the same release, and the write
            // is unconditional once the listener exists. So a reply with
            // no proof is NOT an older engine: an older engine leaves no
            // runtime.json and takes the `guard let token` arm above.
            // Refuse - attaching would disclose the stored API key, and
            // with it `mode=server_secret`.
            return false
        }
        let want = launcherProof(token: token, nonce: nonce)
        // Length first, then a full-width compare - no early exit on the
        // first differing byte.
        guard want.utf8.count == proof.utf8.count else { return false }
        return zip(want.utf8, proof.utf8).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    /// Classify a decoded /api?mode=version reply. Split out so the rule is
    /// testable without a socket.
    ///
    /// Since first-run key minting, a keyless probe of a keyed daemon gets
    /// "API Key Required" - serve.rs picks that exact phrase when no key is
    /// presented at all, and "API Key Incorrect" only when a wrong one is
    /// (they're the SAB phrases the *arrs substring-match). Accepting just
    /// the latter made this probe unable to recognise ANY daemon that had a
    /// key, which after minting is every fresh install: attach failed, the
    /// spawn's own daemon was then unrecognisable too, and start() reported
    /// failure while a healthy daemon was running.
    ///
    /// Keep this to those two exact phrases. A true return means "attach to
    /// this and never stop it", so treating any JSON reply as nzbfast would
    /// hand somebody else's server the dashboard - and our API key with it.
    static func isNzbfastReply(_ obj: [String: Any]) -> Bool {
        if obj["nzbfast"] != nil { return true }
        let err = obj["error"] as? String
        return err == "API Key Incorrect" || err == "API Key Required"
    }

    /// TCP-level check: is anything listening on 127.0.0.1:port?
    /// Localhost connects resolve immediately (accept or refuse), so a
    /// plain blocking connect is fine.
    private func portTaken(_ port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return true }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return r == 0
    }

    // MARK: lifecycle

    enum StartResult {
        case attached           // daemon already up on the persisted port
        case spawned            // we launched a child
        case failed(String)     // couldn't start; message + log tail
    }

    /// Shared rule 4: attach to a port one of our engines already answers
    /// on; otherwise scan for a free port from 6789 and spawn.
    /// Never touches daemons on other ports.
    func start() async -> StartResult {
        // Resolve the port FIRST, before the spawn and the scan. A port
        // the user changed in the dashboard is applied by the engine at
        // startup no matter what `--port` says, so the value we
        // remembered in UserDefaults is stale the moment they change it.
        // Following it here is what keeps every later consumer - the
        // spawn argument, the health poll, the dashboard and API URLs,
        // and the shutdown POST - pointed at the one port the engine
        // actually binds. Without it start() reported failure against a
        // perfectly healthy child, and the quit sweep then killed that
        // child by executable path.
        let saved = savedPort()
        // Probe for a LIVE engine before any of that, over every port one
        // of ours could still be answering on: the saved settings.json
        // port first, then the port we last used when it differs.
        //
        // The saved port is restart-only - the engine reads it once at
        // startup - so right after a port change the engine that is still
        // running is on the PREVIOUS port. Attaching to it is the
        // single-engine-preserving choice: spawning on the new port
        // instead would leave two engines sharing config.local.json, the
        // index db and the watch folder. The new port applies on the next
        // restart, through the wrapper's normal stop/start path.
        var candidates: [Int] = []
        for p in [saved ?? 0, port] where p > 0 && !candidates.contains(p) {
            candidates.append(p)
        }
        for candidate in candidates {
            guard await isNzbfast(port: candidate) else { continue }
            // Every consumer follows the port we ACTUALLY attached to.
            port = candidate
            UserDefaults.standard.set(candidate, forKey: "daemonPort")
            spawnedByUs = false
            return .attached
        }
        // Nothing of ours is answering, so we spawn. A saved port wins
        // over the scan below: the engine binds it regardless of the
        // argument we pass, so a scanned port would just be ignored by
        // the child and strand us again. If something unrelated holds
        // that port the child can't bind it and says so in the log,
        // which is the honest outcome - the setting is the user's.
        //
        // Otherwise: free-port scan from 6789 (the shipped launchers'
        // rule). A port with ANY listener - nzbfast or not - is skipped:
        // on first run an existing daemon on 6789 is somebody else's
        // (there is no persisted claim on it), and we must not touch it.
        var chosen = saved ?? 0
        if chosen == 0 {
            for p in 6789..<6889 where !portTaken(p) {
                chosen = p
                break
            }
        }
        guard chosen > 0 else { return .failed("no free port between 6789 and 6889") }
        port = chosen
        UserDefaults.standard.set(chosen, forKey: "daemonPort")
        do {
            try spawn()
        } catch {
            return .failed("couldn't launch the engine: \(error.localizedDescription)")
        }
        if await waitUntilUp(timeout: 15) {
            return .spawned
        }
        return .failed("the engine didn't answer on port \(port) within 15 s")
    }

    private func spawn() throws {
        let fm = FileManager.default
        for dir in [dataDir, downloadsDir] {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        rotateLog()
        if !fm.fileExists(atPath: logURL.path) {
            fm.createFile(atPath: logURL.path, contents: nil)
        }
        let log = try FileHandle(forWritingTo: logURL)
        log.seekToEndOfFile()

        let p = Process()
        p.executableURL = engineURL
        p.arguments = [
            "serve",
            "--port", String(port),
            "--config", dataDir.appendingPathComponent("config.local.json").path,
            "--out", downloadsDir.path,
            "--watch", watchDir.path,
            "--index-db", dataDir.appendingPathComponent("index.db").path,
        ]
        var env = ProcessInfo.processInfo.environment
        env["NZBFAST_BUNDLED"] = "1"   // S3: no self-swap inside the bundle
        p.environment = env
        p.currentDirectoryURL = dataDir
        p.standardOutput = log
        p.standardError = log
        p.terminationHandler = { [weak self] proc in
            try? log.close()
            guard let self else { return }
            DispatchQueue.main.async {
                self.child = nil
                if !self.deliberateStop {
                    self.onUnexpectedExit?(self.logTail())
                }
            }
        }
        deliberateStop = false
        try p.run()
        child = p
        spawnedByUs = true
    }

    /// Poll mode=version every 250 ms until the daemon answers.
    func waitUntilUp(timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await isNzbfast(port: port, timeout: 0.25) { return true }
            // A child that died during startup will never answer.
            if spawnedByUs, let c = child, !c.isRunning { return false }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        return false
    }

    /// Shared rule 6: graceful stop of OUR child - mode=shutdown persists
    /// the queue and exits; ≤5 s later we hard-kill whatever is left.
    /// In-flight downloads survive via the journal.
    ///
    /// Then the orphan sweep, which is what makes the app replaceable:
    /// see `stopBundleOrphans()`.
    func stop() async {
        if !spawnedByUs {
            // Attached, not spawned. If what we attached to is one of our
            // own bundle engines, it is ours to stop - and mode=shutdown
            // is the graceful route (it persists the queue), same as for
            // a child. Only then does the signal sweep below run, and by
            // then it usually has nothing left to do.
            deliberateStop = true
            var req = URLRequest(url: apiURL("shutdown"))
            req.httpMethod = "POST"
            req.timeoutInterval = 2
            if bundleOrphanPIDs().isEmpty == false {
                _ = try? await URLSession.shared.data(for: req)
                for _ in 0..<50 {
                    if bundleOrphanPIDs().isEmpty { break }
                    try? await Task.sleep(nanoseconds: 100_000_000)
                }
            }
        }
        defer { stopBundleOrphans() }
        guard spawnedByUs, let c = child, c.isRunning else { return }
        deliberateStop = true
        var req = URLRequest(url: apiURL("shutdown"))
        req.httpMethod = "POST"
        req.timeoutInterval = 2
        _ = try? await URLSession.shared.data(for: req)
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            if !c.isRunning { return }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        kill(c.processIdentifier, SIGKILL)
    }

    /// Stop any engine still running OUT OF THIS BUNDLE that is not our
    /// own child.
    ///
    /// "Never touch an attached daemon" protects a daemon the USER runs -
    /// from a terminal, from launchd, from their own copy of the binary.
    /// It was keyed on who started the process, which is the wrong test:
    /// an engine running out of `NzbFast.app/Contents/Resources/bin` is
    /// ours whoever started it. Leaving one alive wedges the app, because
    /// a crash or a force-quit orphans the engine, every later launch
    /// ATTACHES to that orphan instead of spawning, and every later quit
    /// then declined to stop it - so the bundle stays busy forever, with
    /// no visible app to quit, and dragging a new NzbFast.app over it
    /// fails with "the item is in use".
    ///
    /// Keyed on the executable path, so a user's own daemon (a different
    /// path) is still never touched - which is the rule this preserves.
    /// The backstop, after the graceful `mode=shutdown` above has had its
    /// turn. The engine installs no SIGTERM handler, so this is an abrupt
    /// exit and the journal is what makes it safe - the same bargain the
    /// existing 5-second SIGKILL fallback already strikes for a child.
    private func stopBundleOrphans() {
        for pid in bundleOrphanPIDs() {
            kill(pid, SIGTERM)
            for _ in 0..<20 {
                if kill(pid, 0) != 0 { break }
                usleep(100_000)
            }
            if kill(pid, 0) == 0 { kill(pid, SIGKILL) }
        }
    }

    /// Engines running out of THIS bundle that are not our own child.
    private func bundleOrphanPIDs() -> [pid_t] {
        let mine = engineURL.resolvingSymlinksInPath().path
        let ours = child?.processIdentifier ?? -1
        return liveProcessIDs().filter { pid in
            guard pid != ours, pid != getpid() else { return false }
            var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            guard proc_pidpath(pid, &buf, UInt32(MAXPATHLEN)) > 0 else { return false }
            return String(cString: buf) == mine
        }
    }

    /// Every live pid, for the orphan sweep. Sized twice: the count can
    /// grow between the sizing call and the fetch.
    private func liveProcessIDs() -> [pid_t] {
        let cap = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        guard cap > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(cap) / MemoryLayout<pid_t>.size + 64)
        let got = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pids,
                                Int32(pids.count * MemoryLayout<pid_t>.size))
        guard got > 0 else { return [] }
        return Array(pids.prefix(Int(got) / MemoryLayout<pid_t>.size)).filter { $0 > 0 }
    }

    /// Restart after an unexpected child death (alert button).
    func restart() async -> StartResult {
        child = nil
        spawnedByUs = false
        return await start()
    }

    // MARK: log handling

    /// Keep daemon.log under ~5 MB; one rotated generation.
    private func rotateLog() {
        let fm = FileManager.default
        let attrs = try? fm.attributesOfItem(atPath: logURL.path)
        let size = (attrs?[.size] as? NSNumber)?.intValue ?? 0
        if size > 5_000_000 {
            let old = dataDir.appendingPathComponent("daemon.log.1")
            try? fm.removeItem(at: old)
            try? fm.moveItem(at: logURL, to: old)
        }
    }

    func logTail(lines: Int = 20) -> String {
        guard let text = try? String(contentsOf: logURL, encoding: .utf8) else {
            return "(no daemon.log)"
        }
        return text.split(separator: "\n").suffix(lines).joined(separator: "\n")
    }

    // MARK: API helpers

    /// Daemon's own release version (for About).
    func daemonVersion() async -> String? {
        var req = URLRequest(url: apiURL("version"))
        req.timeoutInterval = 2
        guard let (data, _) = try? await URLSession.shared.data(for: req),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return obj["nzbfast"] as? String
    }

    /// Multipart POST of an .nzb to mode=addfile. Returns nil on success,
    /// or an error message.
    func addNzb(_ file: URL) async -> String? {
        guard let bytes = try? Data(contentsOf: file) else {
            return "couldn't read \(file.lastPathComponent)"
        }
        let boundary = "nzbfast-\(UUID().uuidString)"
        var req = URLRequest(url: apiURL("addfile"))
        req.httpMethod = "POST"
        req.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"name\"; filename=\"\(file.lastPathComponent)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: application/x-nzb\r\n\r\n".data(using: .utf8)!)
        body.append(bytes)
        body.append("\r\n--\(boundary)--\r\n".data(using: .utf8)!)
        req.httpBody = body
        guard let (data, _) = try? await URLSession.shared.data(for: req),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return "the daemon didn't answer" }
        if (obj["status"] as? Bool) == true { return nil }
        return (obj["error"] as? String) ?? "rejected"
    }

    /// Hand a clicked `nzblnk:` link to mode=addnzblnk. Returns nil on
    /// success, or a message to show.
    ///
    /// The link goes over VERBATIM, percent-encoded as one query value:
    /// `nzbkit::nzblnk` in the daemon is the only parser, and it is the
    /// one that is fuzzed. Nothing here inspects the link.
    ///
    /// Resolving a header can mean a round of searches against the
    /// user's indexers, so this waits longer than the status probes do.
    func addNzblnk(_ link: String) async -> String? {
        var req = URLRequest(url: apiURL("addnzblnk", "output=json&link=\(queryEscaped(link))"))
        req.timeoutInterval = 30
        guard let (data, _) = try? await URLSession.shared.data(for: req),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return "the daemon didn't answer" }
        if (obj["status"] as? Bool) == true { return nil }
        return (obj["error"] as? String) ?? "rejected"
    }
}
