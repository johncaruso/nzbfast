// API models for the SABnzbd-compatible daemon API. Numeric fields
// arrive as strings in SAB-compat responses, so decoding is lenient.
import Foundation

/// Decodes a value that may arrive as a JSON string or number.
struct Stringly: Codable, Equatable {
    let raw: String

    init(_ raw: String) { self.raw = raw }

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let s = try? c.decode(String.self) {
            raw = s
        } else if let d = try? c.decode(Double.self) {
            raw = String(d)
        } else if let i = try? c.decode(Int.self) {
            raw = String(i)
        } else {
            raw = ""
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(raw)
    }

    var double: Double? { Double(raw) }
}

struct VersionResponse: Codable {
    let version: String?
    let nzbfast: String?
}

struct QueueResponse: Codable {
    let queue: QueueBody
}

struct QueueBody: Codable {
    let paused: Bool?
    let offline: Bool?
    let slots: [QueueSlot]
    let speed: String?
    let kbpersec: Stringly?
    let sizeleft: String?
    let timeleft: String?
    let status: String?
}

struct QueueSlot: Codable, Identifiable {
    let nzoId: String
    let filename: String?
    let status: String?
    let percentage: Stringly?
    let mb: Stringly?
    let mbleft: Stringly?
    let timeleft: String?
    let activity: String?
    let activityDetail: String?
    let media: String?
    let prefetching: Bool?

    var id: String { nzoId }

    enum CodingKeys: String, CodingKey {
        case nzoId = "nzo_id"
        case filename, status, percentage, mb, mbleft, timeleft, activity
        case activityDetail = "activity_detail"
        case media, prefetching
    }

    var name: String { filename ?? nzoId }
    var pct: Double { percentage?.double ?? 0 }
    var isPaused: Bool { (status ?? "") == "Paused" }
    var totalMB: Double { mb?.double ?? 0 }
    var leftMB: Double { mbleft?.double ?? 0 }
}

struct HistoryResponse: Codable {
    let history: HistoryBody
}

struct HistoryBody: Codable {
    let slots: [HistorySlot]
    let noofslots: Int?
}

struct HistorySlot: Codable, Identifiable {
    let nzoId: String
    let name: String?
    let status: String?
    let failMessage: String?
    let size: String?
    let bytes: Stringly?
    let completed: Stringly?
    let storage: String?

    var id: String { nzoId }

    enum CodingKeys: String, CodingKey {
        case nzoId = "nzo_id"
        case name, status, size, bytes, completed, storage
        case failMessage = "fail_message"
    }

    var isCompleted: Bool { (status ?? "") == "Completed" }
    var isFailed: Bool { (status ?? "") == "Failed" }

    /// The daemon serves finished jobs whose media file it can find on
    /// disk; media extensions mirror the daemon's MEDIA_EXTS list.
    var looksPlayable: Bool {
        guard isCompleted else { return false }
        return true
    }
}

struct AddResponse: Codable {
    let status: Bool
    let nzoIds: [String]?
    let stream: String?
    let m3u: String?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case status, stream, m3u, error
        case nzoIds = "nzo_ids"
    }
}

struct StatusResponse: Codable {
    let status: Bool?
    let error: String?
}

struct ProbeCoverage: Codable {
    let headBytes: Stringly?
    let pct: Stringly?
    let tailOk: Bool?

    enum CodingKeys: String, CodingKey {
        case headBytes = "head_bytes"
        case pct
        case tailOk = "tail_ok"
    }
}

struct ProbeMedia: Codable {
    let container: String?
    let complete: Bool?
}

struct ProbeResponse: Codable {
    let nzoId: String?
    let file: String?
    let size: Stringly?
    let coverage: ProbeCoverage?
    let source: String?
    let pending: Bool?
    let media: ProbeMedia?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case nzoId = "nzo_id"
        case file, size, coverage, source, pending, media, error
    }

    /// Playback readiness per the mobile contract: a parsed media
    /// header is the signal; pending means keep polling.
    var ready: Bool {
        error == nil && media != nil
    }
}
