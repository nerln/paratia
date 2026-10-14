import Foundation
import CoreFoundation
import Darwin

enum NativeInstall {
    static let bootstrapBundlePath = "/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app"
    static let preparationCommand = """
    sudo /bin/sh -c 'set -eu
    [ ! -L "/Library/Application Support/ParatiaBootstrap.noindex" ]
    [ -d "/Applications/Paratia.app" ]
    [ ! -L "/Applications/Paratia.app" ]
    /usr/bin/install -d -m 755 -o root -g wheel "/Library/Application Support/ParatiaBootstrap.noindex"
    /bin/chmod -N "/Library/Application Support/ParatiaBootstrap.noindex"
    paratia_bootstrap_stage=$(/usr/bin/mktemp -d "/Library/Application Support/ParatiaBootstrap.noindex/.prepara.XXXXXX")
    /usr/bin/ditto --noacl "/Applications/Paratia.app" "$paratia_bootstrap_stage/Paratia.app"
    /usr/bin/find "$paratia_bootstrap_stage/Paratia.app" ! -type d ! -type f -print > "$paratia_bootstrap_stage/percorsi-non-ordinari"
    [ ! -s "$paratia_bootstrap_stage/percorsi-non-ordinari" ]
    /usr/sbin/chown -R root:wheel "$paratia_bootstrap_stage/Paratia.app"
    /bin/chmod -R go-w "$paratia_bootstrap_stage/Paratia.app"
    /usr/bin/codesign --verify --deep --strict "$paratia_bootstrap_stage/Paratia.app"
    [ ! -L "/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app" ]
    if [ -e "/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app" ]; then
        /bin/mv "/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app" "$paratia_bootstrap_stage/precedente.app"
    fi
    /bin/mv "$paratia_bootstrap_stage/Paratia.app" "/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app"
    /usr/bin/codesign --verify --deep --strict "/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app"
    /usr/bin/find "/Library/Application Support/ParatiaBootstrap.noindex" -mindepth 1 -maxdepth 1 -type d -user root -name ".prepara.*" -exec /bin/rm -rf -- {} +
    if [ -e "/Library/Application Support/ParatiaBootstrap" ]; then
        [ ! -L "/Library/Application Support/ParatiaBootstrap" ]
        [ -d "/Library/Application Support/ParatiaBootstrap" ]
        [ "$(/usr/bin/stat -f %u "/Library/Application Support/ParatiaBootstrap")" = "0" ]
        paratia_legacy_mode=$(/usr/bin/stat -f %Lp "/Library/Application Support/ParatiaBootstrap")
        [ $((0$paratia_legacy_mode & 022)) -eq 0 ]
        [ ! -L "/Library/Application Support/ParatiaBootstrap/Paratia.app" ]
        if [ -e "/Library/Application Support/ParatiaBootstrap/Paratia.app" ]; then
            [ -d "/Library/Application Support/ParatiaBootstrap/Paratia.app" ]
            [ "$(/usr/bin/stat -f %u "/Library/Application Support/ParatiaBootstrap/Paratia.app")" = "0" ]
            /bin/rm -rf -- "/Library/Application Support/ParatiaBootstrap/Paratia.app"
        fi
        /usr/bin/find "/Library/Application Support/ParatiaBootstrap" -mindepth 1 -maxdepth 1 -type d -user root -name ".prepara.*" -exec /bin/rm -rf -- {} +
    fi'
    """
    // The bootstrap imports catena before installing these fixed daemon assets.
    // The complete bundle is checked too: the installer reads it while copying.
    private static let bootstrapFiles = [
        "Contents/Info.plist", "Contents/MacOS/Paratia", "Contents/_CodeSignature/CodeResources",
        "Contents/Resources/python/registro_installa.py", "Contents/Resources/python/catena.py",
        "Contents/Resources/python/registro.py", "Contents/Resources/python/registro_daemon.py"
    ]

    private static func protectionError(_ path: String) -> AppError {
        AppError(message: "Installazione amministratore bloccata: apri la copia bootstrap protetta, distinta dall'app normale e dal servizio (\(path)). Chiudi Paratia ed esegui tu questo unico comando nel Terminale:\n\n\(preparationCommand)\n\nSe il comando termina senza errori, apri \(bootstrapBundlePath) dal Finder e usa Installa il registro. Il comando non modifica /Applications: l'app normale e la voce Accesso completo al disco restano /Applications/Paratia.app. Dopo aver verificato la nuova copia, elimina il vecchio bootstrap indicizzabile e le directory .prepara root del bootstrap. Se la nuova copia o un suo antenato non è protetto da root, oppure un ACL concede scrittura, il dialogo resta bloccato: non vengono applicate eccezioni ai controlli.")
    }

    private static func requireProtected(_ path: URL) throws {
        guard path.path.withCString({ ParatiaRootProtectedAncestors($0) }) == 1 else {
            throw protectionError(path.path)
        }
    }

    static func validateBootstrap(bundle: URL) throws {
        guard bundle.path == bootstrapBundlePath else { throw protectionError(bundle.path) }
        try requireProtected(bundle)
        for relative in bootstrapFiles {
            let file = bundle.appendingPathComponent(relative)
            try requireProtected(file)
            let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
            guard attributes[.type] as? FileAttributeType == .typeRegular else { throw protectionError(file.path) }
        }
        var readFailure: URL?
        guard let entries = FileManager.default.enumerator(at: bundle, includingPropertiesForKeys: [], options: [], errorHandler: { path, _ in
            readFailure = path
            return false
        }) else { throw protectionError(bundle.path) }
        var count = 0
        while let file = entries.nextObject() as? URL {
            count += 1
            guard count <= 10_000, file.path.hasPrefix(bundle.path + "/") else { throw protectionError(file.path) }
            try requireProtected(file)
        }
        if let path = readFailure { throw protectionError(path.path) }
        // Verify the sealed resources before any bundle Python executes as root.
        // Verification uses no signing identity and never accesses a keychain.
        let verifier = Process()
        verifier.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        verifier.arguments = ["--verify", "--deep", "--strict", bundle.path]
        verifier.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        verifier.standardInput = FileHandle.nullDevice
        verifier.standardOutput = FileHandle.nullDevice
        verifier.standardError = FileHandle.nullDevice
        do { try verifier.run(); verifier.waitUntilExit() } catch {
            throw AppError(message: "La firma di Paratia non può essere verificata. Chiedi al supervisore di ricostruire e reinstallare l'app prima di autorizzare il registro.")
        }
        guard verifier.terminationReason == .exit, verifier.terminationStatus == 0 else {
            throw AppError(message: "La firma o le risorse di Paratia non sono integre. Chiedi al supervisore di ricostruire e reinstallare l'app prima di autorizzare il registro.")
        }
    }

    static func validate(plan: Record) throws -> [String] {
        let bundle = URL(fileURLWithPath: Bundle.main.bundlePath, isDirectory: true)
        try validateBootstrap(bundle: bundle)
        let resource = bundle.appendingPathComponent("Contents/Resources/python", isDirectory: true)
        guard
              let argv = plan["argv"] as? [String], argv.count == 9,
              argv[1] == "-I", argv[2] == "-S",
              argv[3] == resource.appendingPathComponent("registro_installa.py").path,
              argv[4] == "--install", argv[5] == "--uid", argv[6] == String(getuid()),
              argv[7] == "--source", argv[8] == resource.path else {
            throw AppError(message: "Il piano di installazione non corrisponde ai componenti di questa app.")
        }
        let runtime = URL(fileURLWithPath: argv[0]).resolvingSymlinksInPath()
        let allowed = "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/"
        guard runtime.path == argv[0], runtime.path.hasPrefix(allowed),
              runtime.lastPathComponent.hasPrefix("python"), runtime.deletingLastPathComponent().lastPathComponent == "bin" else {
            throw AppError(message: "L'installazione richiede il Python Apple protetto dei Command Line Tools.")
        }
        var current = runtime
        while true {
            guard current.path.withCString({ ParatiaRootProtected($0) }) == 1 else {
                throw AppError(message: "Il runtime Apple è modificabile senza root. Ripristina i Command Line Tools prima di installare.")
            }
            if current.path == "/" { break }
            current.deleteLastPathComponent()
        }
        return argv
    }

    static func decodeInstallationResponse(_ response: Data) throws -> Record {
        guard !response.isEmpty, response.count <= 1_048_576,
              let result = try? JSONSerialization.jsonObject(with: response) as? Record else {
            throw AppError(message: "L'installatore non ha restituito un JSON valido. Aggiorna lo stato e riprova dalle Impostazioni.")
        }
        guard let installed = result["installed"] as? NSNumber,
              CFGetTypeID(installed) == CFBooleanGetTypeID() else {
            throw AppError(message: "La risposta dell'installatore non contiene un esito booleano valido. Aggiorna lo stato e riprova.")
        }
        guard installed.boolValue else {
            let message = result["message"] as? String ?? "L'installazione del registro non è riuscita."
            let code = result["error_code"] as? String ?? "install_failed"
            throw AppError(message: String(message.prefix(2048)) + "\nCodice: " + String(code.prefix(96)))
        }
        return result
    }

    static func execute(plan: Record) async throws -> Record {
        let argv = try validate(plan: plan)
        return try await Task.detached(priority: .userInitiated) {
            // Recheck in the execution task immediately before the admin dialog.
            try validateBootstrap(bundle: URL(fileURLWithPath: Bundle.main.bundlePath, isDirectory: true))
            var pointers = argv.dropFirst().map { strdup($0) }
            defer { pointers.forEach { free($0) } }
            pointers.append(nil)
            var stream: UnsafeMutablePointer<FILE>?
            let status = argv[0].withCString { executable in
                pointers.withUnsafeMutableBufferPointer { ParatiaAuthorizedInstall(executable, $0.baseAddress, &stream) }
            }
            guard status == 0, let output = stream else {
                throw AppError(message: status == -60006 ? "Autorizzazione annullata. Nessuna installazione confermata." : "macOS non ha autorizzato l'installazione. Riprova dalle Impostazioni.")
            }
            defer { fclose(output) }
            var response = Data(), buffer = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = fread(&buffer, 1, buffer.count, output)
                if count == 0 { break }
                if response.count + count > 1_048_576 { throw AppError(message: "Il servizio non ha restituito una conferma valida. Aggiorna lo stato.") }
                response.append(contentsOf: buffer.prefix(count))
            }
            return try decodeInstallationResponse(response)
        }.value
    }
}
