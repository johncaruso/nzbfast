// First-run screen: "my server" mode only in this phase. On-device
// mode arrives with workstream A3.
import SwiftUI

struct ConnectView: View {
    @EnvironmentObject var state: AppState
    @State private var urlString = ""
    @State private var apiKey = ""
    @State private var busy = false
    @State private var errorText: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Point the app at your own nzbfast server. You can copy the URL and API key from the server's dashboard settings.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Section("Your server") {
                    TextField("http://192.168.1.10:6789", text: $urlString)
                        .keyboardType(.URL)
                        .textContentType(.URL)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    SecureField("API key", text: $apiKey)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }
                if let errorText {
                    Section {
                        Label(errorText, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                }
                Section {
                    Button {
                        Task { await connect() }
                    } label: {
                        if busy {
                            ProgressView()
                                .frame(maxWidth: .infinity)
                        } else {
                            Text("Connect")
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(busy || urlString.isEmpty)
                }
            }
            .navigationTitle("nzbfast")
        }
    }

    private func connect() async {
        busy = true
        errorText = nil
        do {
            try await state.connect(urlString: urlString, apiKey: apiKey)
        } catch {
            errorText = (error as? LocalizedError)?.errorDescription
                ?? "Could not reach that server."
        }
        busy = false
    }
}
