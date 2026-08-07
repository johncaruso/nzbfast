// Session state: server config, the polling loop, and the queue and
// history snapshots every screen reads.
import Foundation
import SwiftUI

@MainActor
final class AppState: ObservableObject {
    @Published var config: ServerConfig?
    @Published var serverVersion: String?
    /// The one mode=playback poll: queue, history, per-file readiness
    /// and the byte-serving telemetry, all in a single response.
    @Published var snapshot: PlaybackSnapshot?
    @Published var lastError: String?
    @Published var offlineSince: Date?
    @Published var selectedTab: MainTab = .home
    @Published var playRequest: PlayerTarget?

    enum MainTab: Hashable { case home, add, server }

    private var client: ApiClient?
    private var pollTask: Task<Void, Never>?
    private static let configKey = "nzbfast.server.config"

    var isConnected: Bool { config != nil }

    init() {
        if let data = UserDefaults.standard.data(forKey: Self.configKey),
           let cfg = try? JSONDecoder().decode(ServerConfig.self, from: data) {
            adopt(cfg, version: nil)
        }
    }

    func api() -> ApiClient? { client }

    /// Validate URL + key against the daemon, then persist and start
    /// polling. mode=version answers without a key, so the key itself
    /// is proven with the call the app lives on: mode=playback needs
    /// the full key and proves the daemon speaks contract v1.
    func connect(urlString: String, apiKey: String) async throws {
        var s = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        if !s.contains("://") { s = "http://" + s }
        while s.hasSuffix("/") { s.removeLast() }
        guard let url = URL(string: s), url.host != nil else { throw ApiError.badURL }
        let cfg = ServerConfig(baseURL: url, apiKey: apiKey.trimmingCharacters(in: .whitespacesAndNewlines))
        let probe = ApiClient(config: cfg)
        let ver = try await probe.version()
        _ = try await probe.playback(limit: 1)
        if let data = try? JSONEncoder().encode(cfg) {
            UserDefaults.standard.set(data, forKey: Self.configKey)
        }
        adopt(cfg, version: ver.nzbfast ?? ver.version)
    }

    private func adopt(_ cfg: ServerConfig, version: String?) {
        config = cfg
        serverVersion = version
        client = ApiClient(config: cfg)
        startPolling()
    }

    func disconnect() {
        pollTask?.cancel()
        pollTask = nil
        UserDefaults.standard.removeObject(forKey: Self.configKey)
        config = nil
        client = nil
        snapshot = nil
        lastError = nil
        offlineSince = nil
    }

    func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    func refresh() async {
        guard let client else { return }
        do {
            // One call for everything: readiness rides the job rows (no
            // per-job probes) and the telemetry feeds the player overlay.
            snapshot = try await client.playback()
            lastError = nil
            offlineSince = nil
        } catch {
            // Keep the last good snapshot on screen; show a banner and
            // keep trying. A fault profile must never wedge the app.
            if offlineSince == nil { offlineSince = Date() }
            lastError = (error as? LocalizedError)?.errorDescription ?? "The server did not answer."
        }
    }

    /// Present the player for a job row. Row 16 already hands over the
    /// tokenized play URL; /m3u is only the fallback for a row that
    /// lacked one. mode=playback is read-only by design; the probe is
    /// what promotes a live job's file index, so fire it once for the
    /// one job the user opened (contract row 13).
    func requestPlay(job: PlaybackJob) async throws {
        guard let client else { throw ApiError.daemon("Not connected.") }
        let url: URL
        if let s = job.stream, let u = URL(string: s) {
            url = u
        } else {
            url = try await client.playURL(for: job.nzoId)
        }
        if job.playback?.source == "live" {
            Task { _ = try? await client.probe(job.nzoId) }
        }
        playRequest = PlayerTarget(jobId: job.nzoId, url: url)
    }

    /// Resolve a tokenized play URL by id (the QA deep-link path).
    func requestPlay(id: String) async throws {
        guard let client else { throw ApiError.daemon("Not connected.") }
        let url = try await client.playURL(for: id)
        playRequest = PlayerTarget(jobId: id, url: url)
    }

    // MARK: link handling

    /// nzblnk links arrive from the OS; the nzbfast scheme carries
    /// DEBUG-only QA hooks so headless Simulator runs can drive the
    /// same code paths the buttons call.
    func handleOpenURL(_ url: URL) {
        if url.scheme == "nzblnk" {
            Task {
                do {
                    guard let client else { throw ApiError.daemon("Not connected.") }
                    let resp = try await client.addNzblnk(url.absoluteString)
                    guard resp.status else {
                        throw ApiError.daemon(resp.error ?? "The server refused that link.")
                    }
                    await refresh()
                } catch {
                    lastError = (error as? LocalizedError)?.errorDescription
                        ?? "Could not add that link."
                }
            }
            return
        }
        // A .nzb shared from another app ("Open in nzbfast" on the
        // share sheet) arrives as a file URL - same upload path the
        // document picker uses, security scope included. Every failure
        // class is surfaced: an OS share that silently does nothing is
        // indistinguishable from success, and the user's NZB just
        // vanishes. Navigation to Home happens only on a real add.
        if url.isFileURL {
            Task {
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                do {
                    guard let client else { throw ApiError.daemon("Not connected.") }
                    let data = try Data(contentsOf: url)
                    let resp = try await client.addFile(data: data, filename: url.lastPathComponent)
                    guard resp.status else {
                        throw ApiError.daemon(resp.error ?? "The server refused that NZB.")
                    }
                    await refresh()
                    selectedTab = .home
                } catch {
                    lastError = (error as? LocalizedError)?.errorDescription
                        ?? "Could not add \(url.lastPathComponent)."
                }
            }
            return
        }
        #if DEBUG
        guard url.scheme == "nzbfast", url.host == "qa" else { return }
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        var query: [String: String] = [:]
        for item in comps?.queryItems ?? [] { query[item.name] = item.value }
        switch url.path {
        case "/connect":
            if let u = query["url"] {
                Task { try? await connect(urlString: u, apiKey: query["key"] ?? "") }
            }
        case "/addurl":
            if let u = query["u"] {
                Task { _ = try? await client?.addUrl(u); await refresh() }
            }
        case "/play":
            if let id = query["id"] {
                Task { try? await requestPlay(id: id) }
            }
        case "/pause":
            if let id = query["id"] {
                Task { try? await client?.pauseJob(id); await refresh() }
            }
        case "/resume":
            if let id = query["id"] {
                Task { try? await client?.resumeJob(id); await refresh() }
            }
        case "/tab":
            switch query["name"] {
            case "add": selectedTab = .add
            case "server": selectedTab = .server
            default: selectedTab = .home
            }
        case "/disconnect":
            disconnect()
        default:
            break
        }
        #endif
    }
}
