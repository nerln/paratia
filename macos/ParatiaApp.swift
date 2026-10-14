import SwiftUI
import AppKit
import Darwin

struct ParatiaApp: App {
    @StateObject private var model = AppModel()

    init() {
        let arguments = CommandLine.arguments
        if arguments.contains("--launch-check") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 4) { NSApplication.shared.terminate(nil) }
        }
        if let indice = arguments.firstIndex(of: "--render-fixtures"), indice + 1 < arguments.count {
            var lingua = "it"
            if let posizione = arguments.firstIndex(of: "--lang"), posizione + 1 < arguments.count {
                lingua = arguments[posizione + 1]
            }
            do { try FixtureRenderer.render(to: URL(fileURLWithPath: arguments[indice + 1], isDirectory: true), lingua: lingua); exit(0) }
            catch { fputs("Fixture rendering failed.\n", stderr); exit(1) }
        }
    }

    var body: some Scene {
        WindowGroup("Paratia") { ContentView(model: model) }
            .defaultSize(width: 1180, height: 800)
            .commands {
                CommandGroup(after: .appInfo) {
                    Button(tr("Aggiorna lo stato")) { model.refreshAction() }.keyboardShortcut("r")
                }
                CommandGroup(replacing: .appSettings) {
                    Button(tr("Impostazioni…")) { model.section = .settings }.keyboardShortcut(",", modifiers: .command)
                }
            }
    }
}

// The native entry point handles the daemon mode before creating any SwiftUI
// objects or connecting to WindowServer. Both modes retain this app's identity.
@MainActor
@_cdecl("ParatiaRunGUI")
func paratiaRunGUI() {
    ParatiaApp.main()
}

@MainActor
enum FixtureRenderer {
    static func render(to directory: URL, lingua: String) throws {
        Localizzazione.usa(lingua)
        NSApplication.shared.setActivationPolicy(.prohibited)
        let previousAppearance = NSApplication.shared.appearance
        let appearance = NSAppearance(named: .aqua)
        NSApplication.shared.appearance = appearance
        defer { NSApplication.shared.appearance = previousAppearance }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for (index, section) in Section.allCases.enumerated() {
            let model = AppModel(fixtures: true)
            model.section = section
            let view = NSHostingView(rootView: ContentView(model: model)
                .environment(\.colorScheme, .light)
                .background(Color.white))
            view.appearance = appearance
            view.wantsLayer = true
            view.layer?.backgroundColor = NSColor.white.cgColor
            let bounds = NSRect(x: 0, y: 0, width: 1240, height: 860)
            let window = NSWindow(contentRect: bounds, styleMask: [.borderless], backing: .buffered, defer: false)
            window.appearance = appearance
            window.isOpaque = true
            window.backgroundColor = .white
            window.contentView = view
            view.frame = bounds
            window.layoutIfNeeded()
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.2))
            view.layoutSubtreeIfNeeded()
            guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
                throw AppError(message: tr("Rendering non disponibile."))
            }
            view.cacheDisplay(in: view.bounds, to: bitmap)
            guard let png = bitmap.representation(using: .png, properties: [:]) else {
                throw AppError(message: tr("Rendering non disponibile."))
            }
            let name = String(format: "%02d", index + 1) + "-" + ["cartelle", "registro", "etichette", "banco", "impostazioni"][index] + ".png"
            try png.write(to: directory.appendingPathComponent(name), options: .atomic)
            window.contentView = nil
        }
    }
}
