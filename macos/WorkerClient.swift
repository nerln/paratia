import Foundation

struct AppError: LocalizedError {
    let message: String
    var code: String = "failed"
    var errorDescription: String? { message }
}

actor WorkerClient {
    private let resources: URL
    private let python: URL

    init(resources: URL? = nil) {
        self.resources = resources ?? Bundle.main.resourceURL!.appendingPathComponent("python")
        let apple = URL(fileURLWithPath: "/Library/Developer/CommandLineTools/usr/bin/python3")
        python = FileManager.default.isExecutableFile(atPath: apple.path) ? apple : URL(fileURLWithPath: "/usr/bin/python3")
    }

    func request(_ action: String, parameters: Record = [:], key: Data = Data()) async throws -> Any {
        let worker = resources.appendingPathComponent("gui_worker.py")
        guard FileManager.default.fileExists(atPath: worker.path) else {
            throw AppError(message: tr("I componenti dell'app non sono disponibili. Ricostruisci o reinstalla Paratia."))
        }
        let metadata = try JSONSerialization.data(withJSONObject: parameters, options: [.sortedKeys])
        guard metadata.count <= 1_048_576, key.count <= 4096 else {
            throw AppError(message: tr("La richiesta è troppo grande. Riduci i filtri o la lunghezza della chiave."))
        }
        var payload = Data()
        for part in [metadata, key] {
            var length = UInt32(part.count).bigEndian
            withUnsafeBytes(of: &length) { payload.append(contentsOf: $0) }
            payload.append(part)
        }
        defer { payload.resetBytes(in: 0..<payload.count) }
        let process = Process()
        process.executableURL = python
        process.arguments = ["-I", "-S", worker.path, action]
        // Il worker eredita l'ambiente della GUI e riceve in più la lingua scelta in PARATIA_LANG.
        var ambiente = ProcessInfo.processInfo.environment
        ambiente["PARATIA_LANG"] = Localizzazione.codice
        process.environment = ambiente
        // No passphrase is ever placed in the environment or process arguments.
        let input = Pipe(), output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch {
            throw AppError(message: tr("Impossibile avviare i componenti Python. Installa i Command Line Tools Apple e riapri l'app."))
        }
        do {
            try input.fileHandleForWriting.write(contentsOf: payload)
            try input.fileHandleForWriting.close()
        } catch {
            input.fileHandleForWriting.closeFile()
            // Do not terminate a migration: its backend must finish or preserve recovery state.
            throw AppError(message: tr("La comunicazione con l'operazione è stata interrotta. Aggiorna lo stato delle cartelle."))
        }
        let response = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard response.count <= 32 * 1024 * 1024,
              let envelope = try? JSONSerialization.jsonObject(with: response) as? Record else {
            throw AppError(message: tr("L'operazione non ha restituito uno stato valido. Aggiorna e controlla eventuali migrazioni incomplete."))
        }
        guard envelope.flag("ok") else {
            let message = envelope.text("message", fallback: tr("Operazione non riuscita."))
            throw AppError(message: message, code: envelope.text("code", fallback: "failed"))
        }
        return envelope["result"] ?? NSNull()
    }
}
