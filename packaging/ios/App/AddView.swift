// Add: paste an NZB URL or nzblnk, or pick a .nzb with the document
// picker. Share-sheet registration is a P2 item (see the handoff note).
import SwiftUI
import UniformTypeIdentifiers

struct AddView: View {
    @EnvironmentObject var state: AppState
    @State private var pasted = ""
    @State private var busy = false
    @State private var showPicker = false
    @State private var resultText: String?
    @State private var resultIsError = false

    var body: some View {
        Form {
            Section("Link") {
                TextField("Paste an NZB URL or nzblnk", text: $pasted, axis: .vertical)
                    .lineLimit(2...4)
                    .keyboardType(.URL)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                Button("Add link") {
                    Task { await addLink() }
                }
                .disabled(busy || pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            Section("File") {
                Button {
                    showPicker = true
                } label: {
                    Label("Choose an NZB file", systemImage: "doc.badge.plus")
                }
                .disabled(busy)
            }
            if let resultText {
                Section {
                    Label(resultText,
                          systemImage: resultIsError ? "exclamationmark.triangle" : "checkmark.circle")
                        .foregroundStyle(resultIsError ? .orange : .green)
                }
            }
        }
        .navigationTitle("Add")
        .fileImporter(isPresented: $showPicker,
                      allowedContentTypes: nzbTypes,
                      allowsMultipleSelection: false) { result in
            Task { await addPicked(result) }
        }
    }

    private var nzbTypes: [UTType] {
        var types: [UTType] = [.xml, .data]
        if let nzb = UTType(filenameExtension: "nzb") {
            types.insert(nzb, at: 0)
        }
        return types
    }

    private func addLink() async {
        let link = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
        busy = true
        do {
            let resp: AddResponse
            if link.lowercased().hasPrefix("nzblnk") {
                resp = try await requireApi().addNzblnk(link)
            } else {
                resp = try await requireApi().addUrl(link)
            }
            finish(added: resp)
            pasted = ""
        } catch {
            fail(error)
        }
        busy = false
    }

    private func addPicked(_ result: Result<[URL], Error>) async {
        busy = true
        do {
            guard let url = try result.get().first else { busy = false; return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let data = try readBoundedNzb(at: url)
            let resp = try await requireApi().addFile(data: data, filename: url.lastPathComponent)
            finish(added: resp)
        } catch {
            fail(error)
        }
        busy = false
    }

    private func requireApi() throws -> ApiClient {
        guard let api = state.api() else { throw ApiError.daemon("Not connected.") }
        return api
    }

    private func finish(added resp: AddResponse) {
        if resp.status {
            let n = resp.nzoIds?.count ?? 1
            resultText = n == 1 ? "Added. It will appear on Home." : "Added \(n) jobs."
            resultIsError = false
            Task { await state.refresh() }
        } else {
            resultText = resp.error ?? "The server refused that."
            resultIsError = true
        }
    }

    private func fail(_ error: Error) {
        resultText = (error as? LocalizedError)?.errorDescription ?? "That did not work."
        resultIsError = true
    }
}
