// Thin client for the daemon's SABnzbd-compatible /api plus the
// /stream and /preview endpoints. The endpoint list here is the C1
// contract surface; keep it in sync with research/CONTRACT-MOBILE-API.md.
import Foundation

struct ServerConfig: Codable, Equatable {
    var baseURL: URL
    var apiKey: String
}

enum ApiError: LocalizedError {
    case badURL
    case http(Int)
    case daemon(String)
    case decode(String)

    var errorDescription: String? {
        switch self {
        case .badURL: return "That server URL does not look valid."
        case .http(let code): return "Server answered HTTP \(code)."
        case .daemon(let msg): return msg
        case .decode(let what): return "Unexpected reply while reading \(what)."
        }
    }
}

final class ApiClient {
    let config: ServerConfig
    private let session: URLSession

    init(config: ServerConfig) {
        self.config = config
        let cfg = URLSessionConfiguration.default
        cfg.timeoutIntervalForRequest = 15
        cfg.waitsForConnectivity = false
        self.session = URLSession(configuration: cfg)
    }

    private func apiURL(mode: String, params: [String: String] = [:]) -> URL? {
        guard var comps = URLComponents(url: config.baseURL.appendingPathComponent("api"),
                                        resolvingAgainstBaseURL: false) else { return nil }
        var items = [URLQueryItem(name: "mode", value: mode)]
        for (k, v) in params.sorted(by: { $0.key < $1.key }) {
            items.append(URLQueryItem(name: k, value: v))
        }
        comps.queryItems = items
        return comps.url
    }

    private func request(_ url: URL) -> URLRequest {
        var req = URLRequest(url: url)
        if !config.apiKey.isEmpty {
            req.setValue(config.apiKey, forHTTPHeaderField: "X-Api-Key")
        }
        return req
    }

    private func fetch<T: Decodable>(_ type: T.Type, mode: String,
                                     params: [String: String] = [:],
                                     what: String) async throws -> T {
        guard let url = apiURL(mode: mode, params: params) else { throw ApiError.badURL }
        let (data, resp) = try await session.data(for: request(url))
        guard let http = resp as? HTTPURLResponse else { throw ApiError.decode(what) }
        guard (200..<300).contains(http.statusCode) else { throw ApiError.http(http.statusCode) }
        // Surface daemon-level {"status":false,"error":...} replies.
        if let err = try? JSONDecoder().decode(StatusResponse.self, from: data),
           err.status == false, let msg = err.error {
            throw ApiError.daemon(msg)
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw ApiError.decode(what)
        }
    }

    // MARK: endpoints

    func version() async throws -> VersionResponse {
        try await fetch(VersionResponse.self, mode: "version", what: "version")
    }

    func queue(limit: Int = 60) async throws -> QueueBody {
        try await fetch(QueueResponse.self, mode: "queue",
                        params: ["limit": String(limit)], what: "the queue").queue
    }

    func history(limit: Int = 60) async throws -> HistoryBody {
        try await fetch(HistoryResponse.self, mode: "history",
                        params: ["limit": String(limit)], what: "history").history
    }

    func pauseJob(_ id: String) async throws {
        _ = try await fetch(StatusResponse.self, mode: "queue",
                            params: ["name": "pause", "value": id], what: "pause")
    }

    func resumeJob(_ id: String) async throws {
        _ = try await fetch(StatusResponse.self, mode: "queue",
                            params: ["name": "resume", "value": id], what: "resume")
    }

    func deleteJob(_ id: String, deleteFiles: Bool) async throws {
        var p = ["name": "delete", "value": id]
        if deleteFiles { p["del_files"] = "1" }
        _ = try await fetch(StatusResponse.self, mode: "queue", params: p, what: "delete")
    }

    func deleteHistory(_ id: String, deleteFiles: Bool) async throws {
        var p = ["name": "delete", "value": id]
        if deleteFiles { p["del_files"] = "1" }
        _ = try await fetch(StatusResponse.self, mode: "history", params: p, what: "delete")
    }

    func pauseAll() async throws {
        _ = try await fetch(StatusResponse.self, mode: "pause", what: "pause")
    }

    func resumeAll() async throws {
        _ = try await fetch(StatusResponse.self, mode: "resume", what: "resume")
    }

    func addUrl(_ url: String) async throws -> AddResponse {
        try await fetch(AddResponse.self, mode: "addurl",
                        params: ["name": url], what: "the add reply")
    }

    func addNzblnk(_ link: String) async throws -> AddResponse {
        try await fetch(AddResponse.self, mode: "addnzblnk",
                        params: ["link": link], what: "the add reply")
    }

    func addFile(data: Data, filename: String) async throws -> AddResponse {
        guard let url = apiURL(mode: "addfile") else { throw ApiError.badURL }
        var req = request(url)
        req.httpMethod = "POST"
        let boundary = "nzbfast-\(UUID().uuidString)"
        req.setValue("multipart/form-data; boundary=\(boundary)",
                     forHTTPHeaderField: "Content-Type")
        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"nzbfile\"; filename=\"\(filename)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: application/x-nzb\r\n\r\n".data(using: .utf8)!)
        body.append(data)
        body.append("\r\n--\(boundary)--\r\n".data(using: .utf8)!)
        req.httpBody = body
        let (respData, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse,
              (200..<300).contains(http.statusCode) else {
            throw ApiError.http((resp as? HTTPURLResponse)?.statusCode ?? 0)
        }
        do {
            return try JSONDecoder().decode(AddResponse.self, from: respData)
        } catch {
            throw ApiError.decode("the add reply")
        }
    }

    func probe(_ id: String) async throws -> ProbeResponse {
        let url = config.baseURL
            .appendingPathComponent("preview")
            .appendingPathComponent("probe")
            .appendingPathComponent(id)
        let (data, resp) = try await session.data(for: request(url))
        guard let http = resp as? HTTPURLResponse,
              (200..<300).contains(http.statusCode) else {
            throw ApiError.http((resp as? HTTPURLResponse)?.statusCode ?? 0)
        }
        do {
            return try JSONDecoder().decode(ProbeResponse.self, from: data)
        } catch {
            throw ApiError.decode("the preview probe")
        }
    }

    /// Resolve a tokenized play URL for a job via /m3u. The token
    /// scopes access to this one job so the full API key never rides
    /// in a media URL (the grab-apikey-leak lesson).
    func playURL(for id: String) async throws -> URL {
        guard var comps = URLComponents(url: config.baseURL
            .appendingPathComponent("m3u")
            .appendingPathComponent(id), resolvingAgainstBaseURL: false) else {
            throw ApiError.badURL
        }
        comps.queryItems = [URLQueryItem(name: "apikey", value: config.apiKey)]
        guard let url = comps.url else { throw ApiError.badURL }
        let req = URLRequest(url: url)
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse,
              (200..<300).contains(http.statusCode) else {
            throw ApiError.http((resp as? HTTPURLResponse)?.statusCode ?? 0)
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw ApiError.decode("the play link")
        }
        for line in text.split(whereSeparator: \.isNewline) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.isEmpty || t.hasPrefix("#") { continue }
            if let u = URL(string: t) { return u }
        }
        throw ApiError.decode("the play link")
    }
}
