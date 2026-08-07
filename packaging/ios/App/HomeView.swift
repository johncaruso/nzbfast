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
