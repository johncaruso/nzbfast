import AppKit
import ServiceManagement
import UniformTypeIdentifiers

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuItemValidation {
    private let daemon = Daemon.shared
    private var windowController: DashboardWindowController!
    /// .nzb files that arrived (open-with) before the daemon was up.
    private var pendingNzbs: [URL] = []
    private var stackReady = false
    private var quitting = false

    // MARK: lifecycle

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenus()
        windowController = DashboardWindowController()
        windowController.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)

        daemon.onUnexpectedExit = { [weak self] tail in
            Task { @MainActor in self?.childDied(tail) }
        }
        Task { await startStack() }
    }

    private func startStack() async {
        windowController.setOverlay(visible: true)
        switch await daemon.start() {
        case .attached, .spawned:
            stackReady = true
            // dashboardURL, not baseURL: only now is the port confirmed to
            // be an nzbfast, and the page needs the key handed to it or a
            // fresh install lands on a prompt for a credential it has never
            // been shown.
            windowController.showDashboard(daemon.dashboardURL)
            let files = pendingNzbs
            pendingNzbs = []
            for f in files { await postNzb(f) }
        case .failed(let why):
            windowController.setOverlay(visible: true, text: "nzbfast couldn't start")
            let alert = NSAlert()
            alert.messageText = "nzbfast couldn't start"
            alert.informativeText = "\(why)\n\nLast log lines:\n\(daemon.logTail())"
            alert.addButton(withTitle: "Try Again")
            alert.addButton(withTitle: "Quit")
            if alert.runModal() == .alertFirstButtonReturn {
                Task { await startStack() }
            } else {
                NSApp.terminate(nil)
            }
        }
    }

    private func childDied(_ tail: String) {
        guard !quitting else { return }
        stackReady = false
        windowController.setOverlay(visible: true, text: "nzbfast stopped")
        let alert = NSAlert()
        alert.messageText = "nzbfast stopped unexpectedly"
        alert.informativeText = "Last log lines:\n\(tail)"
        alert.addButton(withTitle: "Restart")
        alert.addButton(withTitle: "Quit")
        if alert.runModal() == .alertFirstButtonReturn {
            Task {
                if case .failed(let why) = await daemon.restart() {
                    self.windowController.setOverlay(visible: true, text: why)
                } else {
                    self.stackReady = true
                    self.windowController.showDashboard(self.daemon.dashboardURL)
                }
            }
        } else {
            NSApp.terminate(nil)
        }
    }

    /// Graceful quit (shared rule 6): stop OUR child cleanly, then go.
    /// An attached daemon is never touched.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if quitting { return .terminateNow }
        quitting = true
        Task {
            await daemon.stop()
            DispatchQueue.main.async {
                NSApp.reply(toApplicationShouldTerminate: true)
            }
        }
        return .terminateLater
    }

    /// Dock-icon click with the window closed: bring it back.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !hasVisibleWindows {
            windowController.showWindow(nil)
        }
        return true
    }

    // MARK: .nzb open-with

    func application(_ application: NSApplication, open urls: [URL]) {
        let nzbs = urls.filter { $0.pathExtension.lowercased() == "nzb" }
        guard !nzbs.isEmpty else { return }
        if stackReady {
            Task { for f in nzbs { await postNzb(f) } }
        } else {
            // Cold start: the stack is coming up; post once it answers.
            pendingNzbs.append(contentsOf: nzbs)
        }
    }

    private func postNzb(_ file: URL) async {
        if let err = await daemon.addNzb(file) {
            let alert = NSAlert()
            alert.messageText = "Couldn't add \(file.lastPathComponent)"
            alert.informativeText = err
            alert.runModal()
        }
    }

    // MARK: menus

    private func buildMenus() {
        let main = NSMenu()

        // App menu
        let appItem = main.addItem(withTitle: "nzbfast", action: nil, keyEquivalent: "")
        let appMenu = NSMenu()
        appItem.submenu = appMenu
        appMenu.addItem(withTitle: "About nzbfast", action: #selector(showAbout), keyEquivalent: "")
        appMenu.addItem(.separator())
        let login = appMenu.addItem(
            withTitle: "Start at Login", action: #selector(toggleLogin), keyEquivalent: "")
        login.target = self
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide nzbfast", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(withTitle: "Quit nzbfast", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        // File
        let fileItem = main.addItem(withTitle: "File", action: nil, keyEquivalent: "")
        let fileMenu = NSMenu(title: "File")
        fileItem.submenu = fileMenu
        fileMenu.addItem(withTitle: "Open .nzb…", action: #selector(openNzbPanel), keyEquivalent: "o")
        fileMenu.addItem(.separator())
        fileMenu.addItem(withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")

        // Edit - standard actions so the dashboard's text fields get
        // cut/copy/paste/select-all keyboard shortcuts.
        let editItem = main.addItem(withTitle: "Edit", action: nil, keyEquivalent: "")
        let editMenu = NSMenu(title: "Edit")
        editItem.submenu = editMenu
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")

        // View
        let viewItem = main.addItem(withTitle: "View", action: nil, keyEquivalent: "")
        let viewMenu = NSMenu(title: "View")
        viewItem.submenu = viewMenu
        viewMenu.addItem(withTitle: "Open in Browser", action: #selector(openInBrowser), keyEquivalent: "b")
        viewMenu.addItem(withTitle: "Open Downloads Folder", action: #selector(openDownloads), keyEquivalent: "d")

        // Window
        let winItem = main.addItem(withTitle: "Window", action: nil, keyEquivalent: "")
        let winMenu = NSMenu(title: "Window")
        winItem.submenu = winMenu
        winMenu.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        winMenu.addItem(withTitle: "Zoom", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        NSApp.windowsMenu = winMenu

        // Help
        let helpItem = main.addItem(withTitle: "Help", action: nil, keyEquivalent: "")
        let helpMenu = NSMenu(title: "Help")
        helpItem.submenu = helpMenu
        helpMenu.addItem(withTitle: "nzbfast User Manual", action: #selector(openManual), keyEquivalent: "?")
        NSApp.helpMenu = helpMenu

        NSApp.mainMenu = main
    }

    /// Keep the Start at Login checkmark honest.
    func validateMenuItem(_ item: NSMenuItem) -> Bool {
        if item.action == #selector(toggleLogin) {
            item.state = SMAppService.mainApp.status == .enabled ? .on : .off
        }
        // Nothing to open in a browser - and no confirmed port to hand the
        // API key to - until the daemon has answered.
        if item.action == #selector(openInBrowser) { return stackReady }
        return true
    }

    // MARK: menu actions

    @objc private func showAbout() {
        let bundleVer = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        Task {
            let dv = await daemon.daemonVersion()
            let alert = NSAlert()
            alert.messageText = "nzbfast"
            var info = "App v\(bundleVer)"
            if let dv { info += " · engine v\(dv)" }
            info += "\nThe fast Usenet downloader.\nGPL-3.0 - https://github.com/nzbfast/nzbfast"
            alert.informativeText = info
            alert.runModal()
        }
    }

    @objc private func toggleLogin() {
        do {
            if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
        } catch {
            let alert = NSAlert()
            alert.messageText = "Couldn't change Start at Login"
            alert.informativeText = error.localizedDescription
            alert.runModal()
        }
    }

    @objc private func openNzbPanel() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        if let nzb = UTType(filenameExtension: "nzb") {
            panel.allowedContentTypes = [nzb]
        }
        panel.begin { [weak self] resp in
            guard resp == .OK, let self else { return }
            self.application(NSApp, open: panel.urls)
        }
    }

    /// Hand the system browser the same keyed URL the embedded webview gets,
    /// or it lands on a prompt for a credential the user has never been
    /// shown. dashboardURL returns the plain baseURL on a keyless install,
    /// so that case is unchanged.
    ///
    /// Gated on stackReady, which is dashboardURL's own contract: the key
    /// may only go to a port start() has confirmed is nzbfast. Before that,
    /// `port` is just a number remembered from a previous run and anything
    /// could be listening on it. validateMenuItem greys the item out until
    /// then, so this guard is the belt to that item's braces.
    @objc private func openInBrowser() {
        guard stackReady else { return }
        NSWorkspace.shared.open(daemon.dashboardURL)
    }

    @objc private func openDownloads() {
        try? FileManager.default.createDirectory(at: daemon.downloadsDir, withIntermediateDirectories: true)
        NSWorkspace.shared.open(daemon.downloadsDir)
    }

    @objc private func openManual() {
        NSWorkspace.shared.open(daemon.baseURL.appendingPathComponent("manual"))
    }
}
