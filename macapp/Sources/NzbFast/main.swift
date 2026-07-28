import AppKit

// SwiftPM executable entry: no storyboard, the delegate builds everything.
// app.run() only returns at quit, so the locals live for the app's life.
MainActor.assumeIsolated {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.setActivationPolicy(.regular)
    app.run()
}
