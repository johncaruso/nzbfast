// nzbfast mobile shell (workstream C1). Remote mode only in this
// phase: the app is a client for the user's own nzbfast daemon.
import SwiftUI

@main
struct NzbfastMobileApp: App {
    @StateObject private var state = AppState()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(state)
                .preferredColorScheme(.dark)
        }
    }
}

struct RootView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        Group {
            if state.isConnected {
                MainTabView()
            } else {
                ConnectView()
            }
        }
        .onOpenURL { url in
            state.handleOpenURL(url)
        }
        .onAppear {
            // Headless QA path: simctl launch arguments land in the
            // arguments domain of UserDefaults, so a driver can route
            // one deep link per launch without the OS open dialog.
            #if DEBUG
            if let s = UserDefaults.standard.string(forKey: "qaurl"),
               let u = URL(string: s) {
                state.handleOpenURL(u)
            }
            #endif
        }
    }
}

struct MainTabView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        TabView(selection: $state.selectedTab) {
            NavigationStack { HomeView() }
                .tabItem { Label("Home", systemImage: "play.rectangle.on.rectangle") }
                .tag(AppState.MainTab.home)
            NavigationStack { AddView() }
                .tabItem { Label("Add", systemImage: "plus.circle") }
                .tag(AppState.MainTab.add)
            NavigationStack { SettingsView() }
                .tabItem { Label("Server", systemImage: "server.rack") }
                .tag(AppState.MainTab.server)
        }
        .fullScreenCover(item: $state.playRequest) { target in
            PlayerView(target: target)
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        List {
            Section("Server") {
                LabeledContent("URL", value: state.config?.baseURL.absoluteString ?? "")
                LabeledContent("Version", value: state.serverVersion ?? "unknown")
            }
            Section {
                Button("Disconnect", role: .destructive) {
                    state.disconnect()
                }
            }
        }
        .navigationTitle("Server")
    }
}
