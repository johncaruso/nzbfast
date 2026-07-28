// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NzbFast",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "NzbFast",
            path: "Sources/NzbFast",
            // The wrapper is small, single-window AppKit; v5 semantics
            // keep it free of Swift-6 strict-concurrency ceremony.
            swiftSettings: [.swiftLanguageMode(.v5)]
        )
    ]
)
