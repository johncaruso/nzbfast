// Test-preview player. VLCKit carries playback because most real
// posts are Matroska and AVPlayer refuses the container.
import SwiftUI
import UIKit
#if canImport(VLCKit)
import VLCKit
#elseif canImport(MobileVLCKit)
import MobileVLCKit
#endif

struct PlayerTarget: Identifiable {
    let jobId: String
    let url: URL
    var id: String { jobId }
}

struct PlayerView: View {
    let target: PlayerTarget
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) private var dismiss
    @StateObject private var vm = PlayerModel()
    @State private var controlsVisible = true
    /// First telemetry sample seen by this player: the counters are
    /// cumulative since daemon start, so the overlay reports movement
    /// since the player opened.
    @State private var telemetryBaseline: StreamTelemetry?

    /// Seek discipline: a live job whose tail has not landed answers
    /// playback.seekable=false - scrubbing into unfetched bytes stalls
    /// the player against a hole (or reads zeros mid-recovery).
    /// Finished jobs and ready tails seek freely; no snapshot yet
    /// (remote daemon between polls) errs on the permissive side for
    /// finished files, which is what the row launched from.
    private var seekAllowed: Bool {
        let job = (state.snapshot.map { $0.queue + $0.history } ?? [])
            .first { $0.nzoId == target.jobId }
        guard let p = job?.playback else { return true }
        return p.source != "live" || p.seekable == true
    }

    var body: some View {
        ZStack(alignment: .topLeading) {
            Color.black.ignoresSafeArea()
            VLCVideoSurface(model: vm)
                .ignoresSafeArea()
                .onTapGesture {
                    withAnimation { controlsVisible.toggle() }
                }
            if controlsVisible {
                controls
            }
            healthOverlay
                .padding(.leading, 12)
                .padding(.top, 64)
        }
        .statusBarHidden(true)
        .onAppear {
            UIApplication.shared.isIdleTimerDisabled = true
            vm.load(url: target.url)
        }
        .onDisappear {
            UIApplication.shared.isIdleTimerDisabled = false
            vm.stop()
        }
        .onChange(of: state.snapshot?.stream?.blockedReads) { _ in
            if telemetryBaseline == nil {
                telemetryBaseline = state.snapshot?.stream
            }
        }
    }

    /// Buffer/health overlay: the mode=playback poll keeps running
    /// behind the player, so `stream` telemetry (blocked_reads,
    /// zero_filled_bytes) and the job's own coverage are both live.
    @ViewBuilder private var healthOverlay: some View {
        if let tele = state.snapshot?.stream {
            let base = telemetryBaseline ?? tele
            let waits = max(0, (tele.blockedReads ?? 0) - (base.blockedReads ?? 0))
            let zeroed = max(0, (tele.zeroFilledBytes ?? 0) - (base.zeroFilledBytes ?? 0))
            let job = (state.snapshot.map { $0.queue + $0.history } ?? [])
                .first { $0.nzoId == target.jobId }
            VStack(alignment: .leading, spacing: 2) {
                Text(zeroed > 0
                     ? "Buffer waits \(waits)  ·  gaps \(Self.formatBytes(zeroed))"
                     : "Buffer waits \(waits)")
                    .foregroundStyle(zeroed > 0 ? Color(red: 1, green: 0.76, blue: 0.29) : .white)
                if let job, job.playback?.source == "live" {
                    Text(String(format: "Fetched %.0f%%  ·  %@", job.pct,
                                job.playback?.seekable == true ? "seek ready" : "seek not ready yet"))
                        .foregroundStyle(.white)
                }
            }
            .font(.caption2.monospacedDigit())
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Color.black.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
        }
    }

    private static func formatBytes(_ b: Int64) -> String {
        if b >= 1_000_000 { return String(format: "%.1f MB", Double(b) / 1e6) }
        if b >= 1_000 { return String(format: "%.0f KB", Double(b) / 1e3) }
        return "\(b) B"
    }

    private var controls: some View {
        VStack {
            HStack {
                Button {
                    vm.stop()
                    dismiss()
                } label: {
                    Image(systemName: "xmark")
                        .font(.title3.weight(.semibold))
                        .padding(10)
                        .background(.ultraThinMaterial, in: Circle())
                }
                Spacer()
                Text("Test preview")
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(.ultraThinMaterial, in: Capsule())
            }
            .padding()
            Spacer()
            VStack(spacing: 10) {
                HStack {
                    Text(vm.positionText)
                    Slider(value: $vm.sliderPosition, in: 0...1) { editing in
                        vm.scrub(editing: editing)
                    }
                    .disabled(!seekAllowed)
                    .opacity(seekAllowed ? 1 : 0.4)
                    Text(vm.durationText)
                }
                .font(.caption.monospacedDigit())
                HStack(spacing: 40) {
                    Button { vm.skip(by: -15) } label: {
                        Image(systemName: "gobackward.15").font(.title2)
                    }
                    .disabled(!seekAllowed)
                    .opacity(seekAllowed ? 1 : 0.4)
                    Button { vm.togglePlay() } label: {
                        Image(systemName: vm.isPlaying ? "pause.fill" : "play.fill")
                            .font(.system(size: 40))
                    }
                    Button { vm.skip(by: 15) } label: {
                        Image(systemName: "goforward.15").font(.title2)
                    }
                    .disabled(!seekAllowed)
                    .opacity(seekAllowed ? 1 : 0.4)
                }
                if let note = vm.statusNote {
                    Text(note)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .padding()
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
            .padding()
        }
        .foregroundStyle(.white)
        .transition(.opacity)
    }
}

@MainActor
final class PlayerModel: NSObject, ObservableObject {
    @Published var isPlaying = false
    @Published var sliderPosition: Double = 0
    @Published var positionText = "0:00"
    @Published var durationText = "--:--"
    @Published var statusNote: String? = "Opening"

    let player = VLCMediaPlayer()
    private var scrubbing = false

    func load(url: URL) {
        player.delegate = self
        player.media = VLCMedia(url: url)
        player.play()
        isPlaying = true
    }

    func stop() {
        player.stop()
        isPlaying = false
    }

    func togglePlay() {
        if player.isPlaying {
            player.pause()
            isPlaying = false
        } else {
            player.play()
            isPlaying = true
        }
    }

    func skip(by seconds: Int) {
        if seconds >= 0 {
            player.jumpForward(Int32(seconds))
        } else {
            player.jumpBackward(Int32(-seconds))
        }
    }

    func scrub(editing: Bool) {
        scrubbing = editing
        if !editing {
            player.position = Float(sliderPosition)
        }
    }

    fileprivate func syncFromPlayer() {
        isPlaying = player.isPlaying
        if !scrubbing {
            sliderPosition = Double(player.position)
        }
        positionText = Self.format(ms: player.time.intValue)
        if let len = player.media?.length.intValue, len > 0 {
            durationText = Self.format(ms: len)
        }
        switch player.state {
        case .buffering:
            statusNote = "Buffering"
        case .error:
            statusNote = "Playback failed. The file may not be ready yet."
        case .ended:
            statusNote = "Finished"
            isPlaying = false
        default:
            statusNote = nil
        }
    }

    private static func format(ms: Int32) -> String {
        let total = Int(ms) / 1000
        let h = total / 3600, m = (total % 3600) / 60, s = total % 60
        if h > 0 { return String(format: "%d:%02d:%02d", h, m, s) }
        return String(format: "%d:%02d", m, s)
    }
}

extension PlayerModel: VLCMediaPlayerDelegate {
    nonisolated func mediaPlayerStateChanged(_ aNotification: Notification) {
        Task { @MainActor in self.syncFromPlayer() }
    }

    nonisolated func mediaPlayerTimeChanged(_ aNotification: Notification) {
        Task { @MainActor in self.syncFromPlayer() }
    }
}

struct VLCVideoSurface: UIViewRepresentable {
    let model: PlayerModel

    func makeUIView(context: Context) -> UIView {
        let view = UIView()
        view.backgroundColor = .black
        model.player.drawable = view
        return view
    }

    func updateUIView(_ uiView: UIView, context: Context) {}
}
