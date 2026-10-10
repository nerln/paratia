import SwiftUI
import AppKit
import UniformTypeIdentifiers

@MainActor
final class AppModel: ObservableObject {
    @Published var section: Section? = .folders
    @Published var folders: [FolderItem] = []
    @Published var watchedFolders: [Record] = []
    @Published var events: [EventItem] = []
    @Published var files: [FileItem] = []
    @Published var labels: [Record] = []
    @Published var labelPlan: Record = [:]
    @Published var registry: Record = [:]
    @Published var hooks: Record = [:]
    @Published var bank: Record = [:]
    @Published var bankPreview: Record = [:]
    @Published var integrity: Record = [:]
    @Published var browsePath = ""
    @Published var browseParent: String?
    @Published var busy: String?
    @Published var error: String?
    @Published var notice: String?
    @Published var warning: String?
    @Published var keyRequest: KeyRequest?
    @Published var detail: EventItem?
    @Published var eventTotal = 0
    @Published var eventsTruncated = false
    @Published var eventsKernelActive: Bool?
    @Published var eventsKernelMessage = "La raccolta kernel non è ancora verificata per questa ricerca."
    @Published var selectedFolder = ""
    @Published var fileFilter = ""
    @Published var processFilter = ""
    @Published var agentFilter = ""
    @Published var useDates = false
    @Published var since = Calendar.current.date(byAdding: .day, value: -1, to: Date())!
    @Published var until = Date()
    @Published var showHidden = false
    @Published var minutes = 15
    @Published var bankDestination = ""
    @Published var realAgents = false
    let fixtures: Bool
    private let worker = WorkerClient()

    init(fixtures: Bool = false) {
        self.fixtures = fixtures
        if fixtures { loadFixtures() }
    }

    var filters: Record {
        var f: Record = [:]
        if !selectedFolder.isEmpty { f["folder"] = selectedFolder }
        if !fileFilter.isEmpty { f["file"] = fileFilter }
        if !processFilter.isEmpty { f["process"] = processFilter }
        if !agentFilter.isEmpty { f["agent"] = agentFilter }
        if useDates {
            let formatter = ISO8601DateFormatter()
            f["since"] = formatter.string(from: since)
            f["until"] = formatter.string(from: until)
        }
        return f
    }

    var registryFolders: [FolderItem] {
        let encryptedIDs = Set(folders.map { $0.id })
        return folders + watchedFolders.filter { !encryptedIDs.contains($0.text("id")) }.map { FolderItem(data: $0) }
    }

    func watchStatus(_ record: Record) -> String {
        if !record.flag("esiste") { return "Configurata · cartella non presente" }
        let kernelIDs = registry["watched_ids"] as? [String] ?? []
        if registry.flag("running"), registry.flag("healthy"), kernelIDs.contains(record.text("id")) {
            return "Configurata e confermata dal registro kernel"
        }
        return "Configurata · raccolta kernel non confermata"
    }

    func perform(_ title: String, _ operation: @escaping () async throws -> Void) {
        guard !fixtures, busy == nil else { return }
        busy = title; error = nil; notice = nil; warning = nil
        Task {
            defer { busy = nil }
            do { try await operation() } catch {
                let original = error.localizedDescription
                try? await self.refresh()
                self.error = original
            }
        }
    }

    func refresh() async throws {
        guard !fixtures else { return }
        let f = try await worker.request("cartelle.elenco") as? [Record] ?? []
        folders = f.map { FolderItem(data: $0) }
        watchedFolders = try await worker.request("registro.elenco_sorveglianza") as? [Record] ?? []
        registry = try await worker.request("registro.stato") as? Record ?? [:]
        hooks = try await optionalStatus("hooks.stato")
        bank = try await optionalStatus("banco.storico")
    }

    private func optionalStatus(_ action: String) async throws -> Record {
        do { return try await worker.request(action) as? Record ?? [:] }
        catch let failure as AppError where failure.code == "pending" {
            return ["pending": true, "message": failure.message]
        }
    }

    func refreshAction() { perform("Aggiornamento dello stato…") { try await self.refresh() } }

    func chooseDirectory(title: String) -> String? {
        let panel = NSOpenPanel()
        panel.title = title
        panel.canChooseFiles = false; panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false; panel.canCreateDirectories = false
        return panel.runModal() == .OK ? panel.url?.resolvingSymlinksInPath().path : nil
    }

    func protectFolder() {
        guard !fixtures, busy == nil else { return }
        guard let source = chooseDirectory(title: "Scegli la cartella da proteggere"),
              let destination = chooseDirectory(title: "Scegli la destinazione sul disco esterno") else { return }
        perform("Controllo della cartella e del disco…") {
            _ = try await self.worker.request("cartelle.prepara_protezione", parameters: ["origine": source, "dove": destination, "minutes": self.minutes])
            self.keyRequest = KeyRequest(action: "cartelle.proteggi", title: "Proteggi \(URL(fileURLWithPath: source).lastPathComponent)",
                                        parameters: ["origine": source, "dove": destination, "minutes": self.minutes], confirm: true)
        }
    }

    func askKey(_ folder: FolderItem, recovery: Bool = false) {
        guard !fixtures, busy == nil else { return }
        if recovery {
            keyRequest = KeyRequest(action: "cartelle.recupera", title: "Recupera \(folder.name)",
                                    parameters: ["id": folder.id], confirm: false)
            return
        }
        perform("Controllo dello stato della cartella…") {
            let ready = try await self.worker.request("cartelle.prepara_apertura", parameters: ["id": folder.id, "minutes": self.minutes]) as? Record ?? [:]
            if ready.flag("gia_aperta") {
                self.notice = ready.text("messaggio", fallback: "La cartella è già aperta. Nessuna chiave necessaria; il timer esistente resta invariato.")
                try await self.refresh()
                return
            }
            guard ready.flag("pronto") else { throw AppError(message: "La cartella non è pronta per l'apertura. Aggiorna lo stato e riprova.") }
            self.keyRequest = KeyRequest(action: "cartelle.apri", title: "Apri \(folder.name)",
                                        parameters: ["id": folder.id, "minutes": self.minutes], confirm: false)
        }
    }

    func submitKey(_ request: KeyRequest, key: Data) {
        keyRequest = nil
        perform(request.action == "cartelle.proteggi" ? "Migrazione e verifica in corso…" : "Operazione in corso…") {
            var sensitive = key
            defer { sensitive.resetBytes(in: 0..<sensitive.count) }
            let result = try await self.worker.request(request.action, parameters: request.parameters, key: sensitive)
            self.captureWarnings(result)
            if self.warning == nil { self.notice = request.action == "banco.run" ? "Prova terminata. Consulta gli esiti e le eventuali fasi in attesa." : "Operazione completata." }
            try await self.refresh()
        }
    }

    func close(_ folder: FolderItem) {
        perform("Chiusura di \(folder.name)…") {
            let result = try await self.worker.request("cartelle.chiudi", parameters: ["id": folder.id])
            self.captureWarnings(result); try await self.refresh()
        }
    }

    func forceClose(_ folder: FolderItem) {
        guard !fixtures, busy == nil else { return }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Forzare la chiusura di \(folder.name)?"
        alert.informativeText = "La cartella può essere in uso da un'app o da un terminale aperto dentro. Chiudili e prova prima Chiudi. La chiusura forzata può perdere modifiche non salvate."
        alert.addButton(withTitle: "Annulla")
        alert.addButton(withTitle: "Chiudi forzatamente")
        guard alert.runModal() == .alertSecondButtonReturn else { return }
        perform("Chiusura forzata di \(folder.name)…") {
            let result = try await self.worker.request("cartelle.chiudi", parameters: ["id": folder.id, "force": true])
            self.captureWarnings(result)
            try await self.refresh()
            if folder.isIncomplete {
                let recoveryNotice = "Montaggi chiusi. La migrazione resta incompleta: usa Recupera la fonte o Annulla migrazione. La copia in chiaro può essere ancora presente."
                self.warning = self.warning.map { $0 + "\n" + recoveryNotice } ?? recoveryNotice
            } else {
                self.notice = "Chiusura forzata completata. Controlla eventuali documenti con modifiche non salvate."
            }
        }
    }

    func closeAll() {
        perform("Chiusura di tutte le cartelle…") {
            let results = try await self.worker.request("cartelle.chiudi_tutte") as? [Record] ?? []
            self.captureWarnings(results)
            try await self.refresh()
            if let failure = results.first(where: { $0["errore"] != nil }) { throw AppError(message: failure.text("errore")) }
        }
    }

    func cancelMigration(_ folder: FolderItem) {
        let alert = NSAlert()
        alert.messageText = "Annullare la migrazione di \(folder.name)?"
        alert.informativeText = "La fonte deve essere ancora integra. L'immagine cifrata viene conservata."
        alert.addButton(withTitle: "Annulla la migrazione"); alert.addButton(withTitle: "Torna indietro")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        perform("Controllo della fonte…") {
            let result = try await self.worker.request("cartelle.annulla", parameters: ["id": folder.id])
            self.captureWarnings(result); try await self.refresh()
        }
    }

    func loadEvents() {
        perform("Ricerca nel registro…") {
            try await self.refreshEvents()
        }
    }

    private func refreshEvents() async throws {
        let result = try await worker.request("registro.query", parameters: ["filters": filters]) as? Record ?? [:]
        let rows = result["rows"] as? [Record] ?? []
        events = rows.enumerated().map { EventItem(id: "\($0.offset)-\($0.element.text("precedente"))", data: $0.element) }
        eventTotal = result.number("total"); eventsTruncated = result.flag("truncated")
        eventsKernelActive = result["kernel_active"] as? Bool
        let collection = result["kernel_collection"] as? Record ?? [:]
        eventsKernelMessage = collection.text("message", fallback: "La raccolta kernel non è ancora verificata per questa ricerca.")
    }

    func watchFolder() {
        guard !fixtures, busy == nil, let path = chooseDirectory(title: "Sorveglia una cartella") else { return }
        let identifier = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        perform("Configurazione della sorveglianza…") {
            let result = try await self.worker.request("registro.sorveglia", parameters: ["id": identifier, "percorso": path]) as? Record ?? [:]
            try await self.refresh()
            self.notice = result.text("messaggio", fallback: "Cartella configurata.") + " La raccolta è confermata solo quando il registro kernel è attivo e riconosce il suo ID."
        }
    }

    func removeWatch(_ record: Record) {
        perform("Rimozione della sorveglianza…") {
            _ = try await self.worker.request("registro.rimuovi_sorveglianza", parameters: ["id": record.text("id")])
            if self.selectedFolder == record.text("id") { self.selectedFolder = "" }
            try await self.refresh()
            try await self.refreshEvents()
            self.notice = "Sorveglianza rimossa dalla configurazione. Gli eventi già raccolti restano nel registro."
        }
    }

    func showWatchEvents(_ record: Record) {
        selectedFolder = record.text("id"); fileFilter = ""; processFilter = ""; agentFilter = ""; useDates = false
        section = .logs
        loadEvents()
    }

    func export(_ action: String, title: String, extension ext: String, parameters: Record = [:]) {
        let panel = NSSavePanel()
        panel.title = title; panel.nameFieldStringValue = "paratia-\(section?.id ?? "registro").\(ext)"
        panel.allowedContentTypes = [UTType(filenameExtension: ext) ?? .data]
        guard panel.runModal() == .OK, let path = panel.url?.path else { return }
        perform("Esportazione…") {
            var params = parameters; params["path"] = path
            let result = try await self.worker.request(action, parameters: params) as? Record ?? [:]
            self.notice = "Esportazione salvata in \(path)."
            if action == "registro.export_csv" {
                self.eventsKernelActive = result["kernel_active"] as? Bool
                let collection = result["kernel_collection"] as? Record ?? [:]
                self.eventsKernelMessage = collection.text("message", fallback: "La raccolta kernel non è ancora verificata per questa esportazione.")
            }
        }
    }

    func browse(_ path: String? = nil) {
        let target = path ?? (browsePath.isEmpty ? FileManager.default.homeDirectoryForCurrentUser.path : browsePath)
        perform("Elenco della cartella…") {
            try await self.refreshBrowser(target)
        }
    }

    private func refreshBrowser(_ target: String) async throws {
        let r = try await worker.request("etichette.sfoglia", parameters: ["radice": target, "mostra_nascosti": showHidden]) as? Record ?? [:]
        browsePath = r.text("radice"); browseParent = r["genitore"] as? String
        files = (r["figli"] as? [Record] ?? []).map { FileItem(data: $0) }
        labels = try await worker.request("etichette.elenco") as? [Record] ?? []
        labelPlan = try await worker.request("etichette.piano") as? Record ?? [:]
    }

    func mark(_ file: FileItem, label: String, note: String = "") {
        perform("Aggiornamento dell'etichetta…") {
            _ = try await self.worker.request("etichette.segna", parameters: ["percorso": file.id, "etichetta": label, "nota": note])
            try await self.refreshBrowser(self.browsePath)
        }
    }

    func removeLabel(_ file: FileItem) {
        perform("Rimozione dell'etichetta…") {
            _ = try await self.worker.request("etichette.togli", parameters: ["percorso": file.id])
            try await self.refreshBrowser(self.browsePath)
        }
    }

    func prepareBank() {
        guard !bankDestination.isEmpty else { error = "Scegli prima la destinazione sul disco esterno."; return }
        perform("Controllo delle condizioni per il banco…") {
            self.bankPreview = try await self.worker.request("banco.anteprima", parameters: ["dove": self.bankDestination]) as? Record ?? [:]
        }
    }

    func runBank() {
        guard !fixtures, busy == nil else { return }
        guard registry.flag("running"), registry.flag("healthy") else {
            error = "Il banco richiede un registro kernel attivo e sano. Completa prima le autorizzazioni nelle Impostazioni."; return
        }
        guard !bankDestination.isEmpty else { error = "Scegli una destinazione sul disco esterno."; return }
        perform("Controllo del disco e delle condizioni del banco…") {
            self.bankPreview = try await self.worker.request("banco.anteprima", parameters: ["dove": self.bankDestination]) as? Record ?? [:]
            guard !self.bankPreview.flag("richiede_autorizzazione") else {
                throw AppError(message: "Completa le autorizzazioni del registro e del Desktop prima di inserire la chiave.")
            }
            self.keyRequest = KeyRequest(action: "banco.run", title: "Avvia il banco di prova",
                                        parameters: ["dove": self.bankDestination, "minutes": self.minutes, "agenti_reali": self.realAgents], confirm: true)
        }
    }

    func installHooks() {
        perform("Preparazione degli hook…") {
            let plan = try await self.worker.request("hooks.install_plan") as? Record ?? [:]
            let alert = NSAlert()
            alert.messageText = "Collegare Paratia alle sessioni agente?"
            let changes = plan["changes"] as? [Record] ?? []
            let paths = changes.map { "• " + $0.text("path") }.joined(separator: "\n")
            alert.informativeText = "Verranno conservate le configurazioni esistenti e creati backup prima delle modifiche.\n\n" + paths + "\n\nIn Codex la fiducia negli hook deve essere approvata da te tramite /hooks. Le sessioni esistenti devono essere riavviate."
            alert.addButton(withTitle: "Applica il piano"); alert.addButton(withTitle: "Annulla")
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            let result = try await self.worker.request("hooks.applica") as? Record ?? [:]
            let backups = (result["backups"] as? [String]) ?? []
            self.warning = result.text("message", fallback: "Hook configurati. Riavvia le sessioni e verifica la fiducia in Codex.")
                + (backups.isEmpty ? "" : "\nBackup: " + backups.joined(separator: "\n"))
            try await self.refresh()
        }
    }

    func restoreHooks() {
        let panel = NSOpenPanel()
        panel.title = "Scegli un backup degli hook di Paratia"
        panel.canChooseFiles = true; panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false; panel.showsHiddenFiles = true
        panel.allowedContentTypes = [.json]
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".claude")
        guard panel.runModal() == .OK, let path = panel.url?.path else { return }
        let alert = NSAlert()
        alert.messageText = "Ripristinare la configurazione degli hook?"
        alert.informativeText = "Paratia ripristina il backup soltanto se la configurazione corrisponde ancora a quella installata. Le modifiche successive vengono conservate. Prima del ripristino viene creato un nuovo backup."
        alert.addButton(withTitle: "Ripristina"); alert.addButton(withTitle: "Annulla")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        perform("Ripristino della configurazione degli hook…") {
            let result = try await self.worker.request("hooks.ripristina", parameters: ["path": path]) as? Record ?? [:]
            try await self.refresh()
            self.warning = "Configurazione ripristinata. Riavvia le sessioni e verifica gli hook nell'harness.\nNuovo backup: " + result.text("backup")
        }
    }

    func installRegistry() {
        perform("Preparazione dell'installazione…") {
            try NativeInstall.validateBootstrap(bundle: URL(fileURLWithPath: Bundle.main.bundlePath, isDirectory: true))
            let plan = try await self.worker.request("registro.install_plan") as? Record ?? [:]
            let alert = NSAlert()
            alert.messageText = "Installare il registro degli accessi?"
            alert.informativeText = "L'installazione parte da questa copia di bootstrap protetta e crea una copia separata per il servizio Paratia. macOS gestisce la password amministratore. Dopo l'installazione chiudi questa copia e riapri /Applications/Paratia.app. Abilita quell'app in Accesso completo al disco; dopo ogni nuova build ad hoc rimuovi e aggiungi di nuovo la voce. Python non va autorizzato."
            alert.addButton(withTitle: "Autorizza con macOS"); alert.addButton(withTitle: "Annulla")
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            let result = try await NativeInstall.execute(plan: plan)
            guard result.flag("installed") else { throw AppError(message: "L'installazione non è stata confermata. Riprova dalle Impostazioni.") }
            self.warning = "Registro installato. Chiudi la copia di bootstrap e riapri /Applications/Paratia.app. In Accesso completo al disco abilita quell'app; dopo questa nuova build rimuovi e aggiungi di nuovo la voce. Python non va autorizzato. Premi Aggiorna nell'app normale per verificare il servizio."
            try await self.refresh()
        }
    }

    func verifyRegistry() {
        perform("Verifica delle catene del registro…") {
            self.integrity = try await self.worker.request("registro.verifica") as? Record ?? [:]
        }
    }

    private func captureWarnings(_ result: Any) {
        let records = (result as? [Record]) ?? ((result as? Record).map { [$0] } ?? [])
        let warnings = records.compactMap { $0["avviso_registro"] as? String }
        if !warnings.isEmpty { warning = warnings.joined(separator: "\n") }
    }

    private func loadFixtures() {
        watchedFolders = [["id": "synthetic-watch", "nome": "Progetto di esempio", "origine": "/Cartelle sintetiche/Progetto", "tipo": "sorveglianza", "esiste": true]]
        folders = [FolderItem(data: ["id": "synthetic-1", "nome": "Contratti di esempio", "origine": "/Cartelle sintetiche/Contratti", "bundle": "/Disco di esempio/Contratti.sparsebundle", "stato": "chiusa", "file": 24, "byte": 12_582_912, "minutes": 15]),
                   FolderItem(data: ["id": "synthetic-2", "nome": "Documenti di esempio", "origine": "/Cartelle sintetiche/Documenti", "bundle": "/Disco di esempio/Documenti.sparsebundle", "stato": "aperta", "file": 9, "byte": 5_242_880, "minutes": 15])]
        registry = ["installed": false, "running": false, "healthy": false, "needs_root": true, "message": "Il registro kernel attende le autorizzazioni. Questi dati sono sintetici."]
        hooks = ["pending": true, "message": "Collega gli hook e conferma la fiducia nell'harness."]
        events = [EventItem(id: "example", data: ["quando": "08/10/2026 09:41:05", "evento": "cartella-chiusa", "percorso": "/Cartelle sintetiche/Documenti", "processo": "Paratia", "pid": 1234, "utente": "utente di esempio", "source": "paratia", "agente": NSNull(), "esito": "riuscito"])]
        eventTotal = events.count
        browsePath = "/Cartelle sintetiche"
        files = [FileItem(data: ["nome": "Contratti", "percorso": "/Cartelle sintetiche/Contratti", "cartella": true, "etichetta": "riservato", "ereditata": false]),
                 FileItem(data: ["nome": "Materiale pubblico", "percorso": "/Cartelle sintetiche/Materiale pubblico", "cartella": true, "etichetta": "pubblico", "ereditata": false])]
        bankPreview = ["stato": "sintetica", "percorso": "/Desktop sintetico/folder-test", "file": 4,
                       "byte": 8_396_800, "messaggio": "Anteprima sintetica: nessun accesso al Desktop reale."]
        let phases: [Record] = ["prima", "chiusa", "riaperta", "richiusa"].map { name in
            let closed = name == "chiusa" || name == "richiusa"
            let probes: [Record] = ["shell", "mdls", "codex", "claude"].map { actor in
                ["attore": actor, "misurato": actor == "shell", "riuscito": actor == "shell" ? !closed : NSNull(),
                 "errno": closed && actor == "shell" ? 2 : NSNull(), "rc": actor == "shell" ? 0 : NSNull(),
                 "copertura_verificata": false, "riscontri_kernel": [],
                 "messaggio": "Esito sintetico per verificare la schermata; nessuna prova reale."]
            }
            return ["nome": name, "iniziata": "2026-10-08T09:41:05+02:00", "conclusa": "2026-10-08T09:41:07+02:00",
                    "atteso": closed ? "rifiuto" : "accesso", "stato_cartella": closed ? "chiusa" : "aperta",
                    "file_visibili": closed ? 0 : 4, "byte_visibili": closed ? 0 : 8_396_800, "prove": probes, "ok": false]
        }
        let run: Record = ["id": "fixture-bank", "stato": "incompleto", "file": 4, "byte": 8_396_800,
                           "iniziata": "2026-10-08T09:41:05+02:00", "conclusa": "2026-10-08T09:41:07+02:00",
                           "messaggio": "Storico sintetico. Le prove reali attendono le autorizzazioni.", "fasi": phases,
                           "percorso": "/Desktop sintetico/folder-test", "stato_finale": "chiusa"]
        bank = run; bank["prove"] = [run]
    }
}
