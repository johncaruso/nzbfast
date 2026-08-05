// Home: one playback-first list. Active jobs with live progress and a
// Play affordance the moment the preview probe says a media file is
// reachable, then history.
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
                if let q = state.queue {
                    Button {
                        Task {
                            try? await (q.paused == true
                                        ? state.api()?.resumeAll()
                                        : state.api()?.pauseAll())
                            await state.refresh()
                        }
                    } label: {
                        Image(systemName: q.paused == true ? "play.fill" : "pause.fill")
                    }
                    .accessibilityLabel(q.paused == true ? "Resume all" : "Pause all")
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
            if let slots = state.queue?.slots, !slots.isEmpty {
                ForEach(slots) { slot in
                    QueueRow(slot: slot,
                             ready: state.probeReady(slot.id),
                             onPlay: { play(slot.id) })
                    .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                        Button(role: .destructive) {
                            run { try await state.api()?.deleteJob(slot.id, deleteFiles: true) }
                        } label: { Label("Delete", systemImage: "trash") }
                        if slot.isPaused {
                            Button {
                                run { try await state.api()?.resumeJob(slot.id) }
                            } label: { Label("Resume", systemImage: "play") }
                            .tint(.green)
                        } else {
                            Button {
                                run { try await state.api()?.pauseJob(slot.id) }
                            } label: { Label("Pause", systemImage: "pause") }
                            .tint(.orange)
                        }
                    }
                }
            } else if state.queue != nil {
                Text("Nothing downloading. Add an NZB from the Add tab.")
                    .foregroundStyle(.secondary)
                    .font(.footnote)
            } else {
                ProgressView()
            }
        }
    }

    @ViewBuilder private var historySection: some View {
        if let slots = state.history?.slots, !slots.isEmpty {
            Section("History") {
                ForEach(slots) { slot in
                    HistoryRow(slot: slot, onPlay: { play(slot.id) })
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button(role: .destructive) {
                                run { try await state.api()?.deleteHistory(slot.id, deleteFiles: false) }
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

    private func play(_ id: String) {
        Task {
            do {
                try await state.requestPlay(id: id)
            } catch {
                actionError = (error as? LocalizedError)?.errorDescription
                    ?? "Could not fetch a play link for that job."
            }
        }
    }
}

struct QueueRow: View {
    let slot: QueueSlot
    let ready: Bool
    let onPlay: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(slot.name)
                    .font(.subheadline.weight(.medium))
                    .lineLimit(1)
                ProgressView(value: min(max(slot.pct / 100, 0), 1))
                    .tint(slot.isPaused ? .orange : .accentColor)
                HStack(spacing: 6) {
                    Text(slot.status ?? "")
                    if slot.totalMB > 0 {
                        Text(String(format: "%.0f%% of %.0f MB", slot.pct, slot.totalMB))
                    }
                    if let tl = slot.timeleft, !tl.isEmpty, tl != "0:00:00" {
                        Text(tl)
                    }
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
            if ready {
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
    let slot: HistorySlot
    let onPlay: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(slot.name ?? slot.id)
                    .font(.subheadline.weight(.medium))
                    .lineLimit(1)
                HStack(spacing: 6) {
                    if slot.isFailed {
                        Label(slot.failMessage ?? "Failed", systemImage: "xmark.circle")
                            .foregroundStyle(.red)
                            .lineLimit(1)
                    } else {
                        Text(slot.status ?? "")
                        if let size = slot.size, !size.isEmpty { Text(size) }
                    }
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            if slot.looksPlayable {
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
