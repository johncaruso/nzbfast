// Throwaway Simulator harness for the A3 spike: link the nzbfast engine
// staticlib, start it in-process, and show the dashboard it serves on
// 127.0.0.1 in a WKWebView. Start/Stop buttons exercise the FFI cycle.
// NOT a product app - the C1 SwiftUI shell is that; this exists to
// prove the engine runs inside an iOS process (no exec on iOS).
//
// The Simulator shares the host Mac's loopback, so the port must dodge
// real daemons on the machine (:6789 is live) - build-harness.sh bakes
// NZBFAST_HARNESS_PORT in via -D; default set there, not here.

import SwiftUI
import WebKit

// The staticlib's C ABI (crates/nzbfast-ffi/include/nzbfast.h), bound
// directly - three functions do not earn a bridging header.
@_silgen_name("nzbfast_start")
func nzbfast_start(
    _ configDir: UnsafePointer<CChar>, _ port: UInt16, _ apikey: UnsafePointer<CChar>?
) -> Int32
@_silgen_name("nzbfast_stop")
func nzbfast_stop() -> Int32
@_silgen_name("nzbfast_is_up")
func nzbfast_is_up() -> Int32

let harnessPort: UInt16 = 8724
// Explicit key: a NULL apikey makes the engine's first run MINT one
// (secure-by-default), and the dashboard then wants it typed in. The
// product app must do the same (or read the minted key back).
let harnessKey = "spike-harness"

@main
struct HarnessApp: App {
    var body: some Scene {
        WindowGroup { HarnessView() }
    }
}

struct HarnessView: View {
    @State private var status = "engine: not started"
    @State private var webKey = 0

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Button("Start") { start() }
                Button("Stop") { status = "stop -> \(nzbfast_stop())" }
                Button("Reload") { webKey += 1 }
                Text(status).font(.footnote).lineLimit(2)
            }
            .padding(8)
            DashboardView(port: harnessPort).id(webKey)
        }
        .onAppear { start() }
    }

    func start() {
        let dir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        )[0].appendingPathComponent("nzbfast", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let rc = dir.path.withCString { d in
            harnessKey.withCString { k in nzbfast_start(d, harnessPort, k) }
        }
        status = "start -> \(rc), up=\(nzbfast_is_up()), port \(harnessPort)"
        // Give the listener a beat, then load the dashboard.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { webKey += 1 }
    }
}

struct DashboardView: UIViewRepresentable {
    let port: UInt16
    func makeUIView(context: Context) -> WKWebView {
        let v = WKWebView()
        v.load(URLRequest(url: URL(string: "http://127.0.0.1:\(port)/?apikey=\(harnessKey)")!))
        return v
    }
    func updateUIView(_ v: WKWebView, context: Context) {}
}
