import Foundation
import Darwin

enum NativeInstall {
    static func validate(plan: Record) throws -> [String] {
        guard let resource = Bundle.main.resourceURL?.appendingPathComponent("python"),
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

    static func execute(plan: Record) async throws -> Record {
        let argv = try validate(plan: plan)
        return try await Task.detached(priority: .userInitiated) {
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
            guard let result = try? JSONSerialization.jsonObject(with: response) as? Record, result.flag("installed") else {
                throw AppError(message: "Il servizio non ha confermato l'installazione. Aggiorna lo stato e riprova dalle Impostazioni.")
            }
            return result
        }.value
    }
}
