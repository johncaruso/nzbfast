// Home: one playback-first list, fed by the one mode=playback poll.
// Active jobs with live progress and a Play affordance the moment the
// job row's readiness says a media file is reachable, then history.
import SwiftUI

struct HomeView: View {
    @EnvironmentObject var state: AppState
    @State private var actionError: String?

    var body: some View {
        List {
            if let since = state.offlineSince {
                Section {
                    Label {
                        Text("Server unreachable since \(since.formatted(date: .omitted, time: .shortened)). Retrying.")
                    } icon: {
                        Image(systemName: "wifi.exclamationmark")
                    }
                    .foregroundStyle(.orange)
                    .font(.footnote)
                }
            }
            throughputSection
            queueSection
            historySection
        }
        .navigationTitle("nzbfast")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if let snap = state.snapshot {
                    Button {
                        Task {
                            try? await (snap.paused == true
                                        ? state.api()?.resumeAll()
                                        : state.api()?.pauseAll())
                            await state.refresh()
                        }
                    } label: {
                        Image(systemName: snap.paused == true ? "play.fill" : "pause.fill")
                    }
                    .accessibilityLabel(snap.paused == true ? "Resume all" : "Pause all")
                }
            }
        }
        .refreshable { await state.refresh() }
        .alert("Something went wrong", isPresented: .init(
            get: { actionError != nil },
            set: { if !$0 { actionError = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(actionError ?? "")
        }
    }

    // Rolling throughput chart above the queue, anchored the way the
    // web dashboard's is: a known link peak is 100%, drawn as a dashed
    // rule with ~4% of air above it, so working well reads as a band
    // riding the rule and a blip past the peak pokes above it without
    // rescaling the history. No known peak = scale to the window.
    @ViewBuilder private var throughputSection: some View {
        if let snap = state.snapshot, !snap.queue.isEmpty, state.speedHistory.count >= 2 {
            Section {
                ThroughputChart(
                    samples: state.speedHistory,
                    linkPeakMBps: (snap.linkPeak ?? 0) / 1e6,
                    linkPeakSrc: snap.linkPeakSrc ?? ""
                )
            }
        }
    }

    @ViewBuilder private var queueSection: some View {
        Section("Active") {
            if let jobs = state.snapshot?.queue, !jobs.isEmpty {
                ForEach(jobs) { job in
                    QueueRow(job: job, onPlay: { play(job) })
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            run { try await state.api()?.deleteJob(job.id, deleteFiles: true) }
                        } label: { Label("Delete", systemImage: "trash") }
                        if job.isPaused {
                            Button {
                                run { try await state.api()?.resumeJob(job.id) }
                            } label: { Label("Resume", systemImage: "play") }
                            .tint(.green)
                        } else {
                            Button {
                                run { try await state.api()?.pauseJob(job.id) }
                            } label: { Label("Pause", systemImage: "pause") }
                            .tint(.orange)
                        }
                    }
                }
            } else if state.snapshot != nil {
                Text("Nothing downloading. Add an NZB from the Add tab.")
                    .foregroundStyle(.secondary)
                    .font(.footnote)
            } else {
                ProgressView()
            }
        }
    }

    @ViewBuilder private var historySection: some View {
        if let jobs = state.snapshot?.history, !jobs.isEmpty {
            Section("History") {
                ForEach(jobs) { job in
                    HistoryRow(job: job, onPlay: { play(job) })
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button(role: .destructive) {
                                run { try await state.api()?.deleteHistory(job.id, deleteFiles: false) }
                            } label: { Label("Remove", systemImage: "trash") }
                        }
                }
            }
        }
    }

    private func run(_ op: @escaping () async throws -> Void) {
        Task {
            do {
                try await op()
                await state.refresh()
            } catch {
                actionError = (error as? LocalizedError)?.errorDescription
                    ?? "The server refused that."
            }
        }
    }

    private func play(_ job: PlaybackJob) {
        Task {
            do {
                try await state.requestPlay(job: job)
            } catch {
                actionError = (error as? LocalizedError)?.errorDescription
                    ?? "Could not fetch a play link for that job."
            }
        }
    }
}

struct ThroughputChart: View {
    let samples: [Double]
    let linkPeakMBps: Double
    let linkPeakSrc: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(String(format: "%.1f MB/s", samples.last ?? 0))
                    .font(.subheadline.weight(.medium))
                Spacer()
                if linkPeakMBps > 0 {
                    let pct = max((samples.last ?? 0) / linkPeakMBps * 100, 0)
                    Text(String(format: "%.0f%% of %.1f MB/s %@", pct, linkPeakMBps,
                                linkPeakSrc == "line" ? "line speed" : "peak"))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            Canvas { ctx, size in
                guard samples.count >= 2 else { return }
                // The anchor pins the scale's lower bound; the window
                // max can still push past it, so an over-peak blip pokes
                // above the rule instead of squashing the history.
                let floor = linkPeakMBps > 0 ? linkPeakMBps * 1.04 : 0
                let maxV = max(samples.max() ?? 0, floor, 0.001)
                let pad: CGFloat = 2
                let stepX = size.width / CGFloat(samples.count - 1)
                func y(_ v: Double) -> CGFloat {
                    size.height - pad - CGFloat(v / maxV) * (size.height - pad * 2)
                }
                var line = Path()
                for (i, v) in samples.enumerated() {
                    let p = CGPoint(x: CGFloat(i) * stepX, y: y(v))
                    if i == 0 { line.move(to: p) } else { line.addLine(to: p) }
                }
                var area = line
                area.addLine(to: CGPoint(x: size.width, y: size.height))
                area.addLine(to: CGPoint(x: 0, y: size.height))
                area.closeSubpath()
                ctx.fill(area, with: .color(.accentColor.opacity(0.18)))
                ctx.stroke(line, with: .color(.accentColor), lineWidth: 2)
                if linkPeakMBps > 0 {
                    var rule = Path()
                    rule.move(to: CGPoint(x: 0, y: y(linkPeakMBps)))
                    rule.addLine(to: CGPoint(x: size.width, y: y(linkPeakMBps)))
                    ctx.stroke(rule, with: .color(.accentColor.opacity(0.55)),
                               style: StrokeStyle(lineWidth: 1, dash: [6, 4]))
                }
            }
            .frame(height: 56)
        }
        .padding(.vertical, 2)
    }
}

struct QueueRow: View {
    let job: PlaybackJob
    let onPlay: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(job.displayName)
                    .font(.subheadline.weight(.medium))
                    .lineLimit(1)
                ProgressView(value: min(max(job.pct / 100, 0), 1))
                    .tint(job.isPaused ? .orange : .accentColor)
                HStack(spacing: 6) {
                    Text(job.status ?? "")
                    if let mb = job.mb, mb > 0 {
                        Text(String(format: "%.0f%% of %.0f MB", job.pct, mb))
                    }
                    if let tl = job.timeleft, !tl.isEmpty, tl != "0:00:00" {
                        Text(tl)
                    }
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
            // playback.ready on the row replaces the per-job probe:
            // reason "live" (or "disk") means /stream serves it now.
            if job.ready {
                Button(action: onPlay) {
                    Image(systemName: "play.circle.fill")
                        .font(.system(size: 30))
                        .foregroundStyle(.green)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Play test preview")
            }
        }
        .padding(.vertical, 2)
    }
}

struct HistoryRow: View {
    let job: PlaybackJob
    let onPlay: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(job.displayName)
                    .font(.subheadline.weight(.medium))
                    .lineLimit(1)
                HStack(spacing: 6) {
                    if job.isFailed {
                        Label(job.failMessage?.isEmpty == false ? job.failMessage! : "Failed",
                              systemImage: "xmark.circle")
                            .foregroundStyle(.red)
                            .lineLimit(1)
                    } else {
                        Text(job.status ?? "")
                        if let b = job.bytes, b > 0 {
                            Text(String(format: "%.1f MB", Double(b) / 1e6))
                        }
                    }
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            // reason "disk" = the file is really still there; a row
            // whose media has been cleaned away ("no_media") gets no
            // Play.
            if job.ready {
                Button(action: onPlay) {
                    Image(systemName: "play.circle")
                        .font(.system(size: 26))
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Play test preview")
            }
        }
        .padding(.vertical, 2)
    }
}
