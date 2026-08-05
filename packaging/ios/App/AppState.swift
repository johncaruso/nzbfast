// Session state: server config, the polling loop, and the queue and
// history snapshots every screen reads.
import Foundation
import SwiftUI

@MainActor
final class AppState: ObservableObject {
    @Published var config: ServerConfig?
    @Published var serverVersion: String?
    @Published var queue: QueueBody?
    @Published var history: HistoryBody?
    @Published var probes: [String: ProbeResponse] = [:]
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
    /// is proven with an authenticated mode=queue call.
    func connect(urlString: String, apiKey: String) async throws {
        var s = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        if !s.contains("://") { s = "http://" + s }
        while s.hasSuffix("/") { s.removeLast() }
        guard let url = URL(string: s), url.host != nil else { throw ApiError.badURL }
        let cfg = ServerConfig(baseURL: url, apiKey: apiKey.trimmingCharacters(in: .whitespacesAndNewlines))
        let probe = ApiClient(config: cfg)
        let ver = try await probe.version()
        _ = try await probe.queue(limit: 1)
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
        queue = nil
        history = nil
        probes = [:]
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
            let q = try await client.queue()
            let h = try await client.history()
            queue = q
            history = h
            lastError = nil
            offlineSince = nil
            await refreshProbes(for: q.slots)
        } catch {
            // Keep the last good snapshot on screen; show a banner and
            // keep trying. A fault profile must never wedge the app.
            if offlineSince == nil { offlineSince = Date() }
            lastError = (error as? LocalizedError)?.errorDescription ?? "The server did not answer."
        }
    }

    /// Probe playback readiness for jobs that are actively moving.
    private func refreshProbes(for slots: [QueueSlot]) async {
        guard let client else { return }
        for slot in slots.prefix(6) where slot.status == "Downloading" {
            if let p = try? await client.probe(slot.nzoId) {
                probes[slot.nzoId] = p
            }
        }
        let live = Set(slots.map(\.id))
        probes = probes.filter { live.contains($0.key) }
    }

    func probeReady(_ id: String) -> Bool {
        probes[id]?.ready ?? false
    }

    /// Resolve a tokenized play URL and present the player.
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
            Task { _ = try? await client?.addNzblnk(url.absoluteString); await refresh() }
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
