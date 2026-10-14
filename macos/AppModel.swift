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
    @Published var eventsKernelMessage = tr("La raccolta kernel non è ancora verificata per questa ricerca.")
    @Published var eventsKernelCollection: Record = [:]
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
    @Published var language: String = UserDefaults.standard.string(forKey: Localizzazione.chiaveImpostazione) ?? "sistema"
    let fixtures: Bool
    private let worker = WorkerClient()

    func setLanguage(_ preferenza: String) {
        language = preferenza
        Localizzazione.imposta(preferenza)
        // Worker messages already on screen were written in the old language.
        if !fixtures && busy == nil { refreshAction() }
    }

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
        let statuses = registry["watch_status"] as? [Record] ?? []
        let token = record.text("configuration_token", fallback: "")
        let status = statuses.first {
            $0.text("id") == record.text("id") &&
            (token.isEmpty || $0.text("configuration_token", fallback: "") == token)
        }
        let refused = status.map { $0.text("status") == "rejected" }
            ?? (record.text("raccolta", fallback: "") == "rifiutata")
        if refused {
            let message = status?.text("message", fallback: tr("La cartella non può essere sorvegliata."))
                ?? record.text("message", fallback: tr("La cartella non può essere sorvegliata."))
            return tr("Rifiutata dal raccoglitore: ") + message
        }
        let warning = status?.text("warning_message", fallback: "")
            ?? record.text("warning_message", fallback: "")
        if registry.flag("running"), !(warning.isEmpty) {
            return tr("Confermata dal raccoglitore · ") + warning
        }
        if record["esiste"] as? Bool == false { return tr("Configurata · cartella non presente") }
        let kernelIDs = registry["watched_ids"] as? [String] ?? []
        let confirmed = status.map { $0.text("status") == "confirmed" }
            ?? (record.text("raccolta", fallback: "") == "confermata" || kernelIDs.contains(record.text("id")))
        if registry.flag("running"), confirmed {
            return tr("Confermata dal raccoglitore")
        }
        return tr("Configurata · raccolta kernel non confermata")
    }

    func healthReasons(_ record: Record) -> [Record] {
        (record["health_reasons"] as? [Record] ?? []).filter {
            !($0["message"] as? String ?? "").isEmpty
        }
    }

    func collectionMetrics(_ record: Record) -> String {
        func measurement(_ key: String, unit: String) -> String? {
            guard let value = record[key] as? Double, value.isFinite, value >= 0 else { return nil }
            return String(format: "%.1f", locale: Localizzazione.locale, value) + unit
        }
        let lag = measurement("event_lag_seconds", unit: " s") ?? tr("non misurato")
        let rate = measurement("lines_per_second", unit: tr(" righe/s")) ?? tr("non misurato")
        return tr("Latenza degli eventi: ") + lag + tr(" · Flusso ricevuto: ") + rate
    }

    func lastEventAge(_ record: Record) -> String {
        guard let seconds = record["last_event_age_seconds"] as? Double, seconds.isFinite, seconds >= 0 else {
            return tr("Nessun evento ricevuto misurato.")
        }
        return tr("Ultimo evento ricevuto ") + String(format: "%.1f", locale: Localizzazione.locale, seconds)
            + tr(" s fa. Il silenzio non prova un ritardo del raccoglitore.")
    }

    var registryUpdateSteps: [String] { registry["update_steps"] as? [String] ?? [] }

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
        eventsKernelActive = nil
        eventsKernelMessage = tr("Stato della ricerca precedente da verificare: ripeti la ricerca.")
        eventsKernelCollection = [:]
        hooks = try await optionalStatus("hooks.stato")
        bank = try await optionalStatus("banco.storico")
    }

    private func optionalStatus(_ action: String) async throws -> Record {
        do { return try await worker.request(action) as? Record ?? [:] }
        catch let failure as AppError where failure.code == "pending" {
            return ["pending": true, "message": failure.message]
        }
    }

    func refreshAction() { perform(tr("Aggiornamento dello stato…")) { try await self.refresh() } }

    func chooseDirectory(title: String, message: String? = nil, startAt: String? = nil, canCreate: Bool = false) -> String? {
        let panel = NSOpenPanel()
        panel.title = title
        if let message { panel.message = message }
        if let startAt { panel.directoryURL = URL(fileURLWithPath: startAt, isDirectory: true) }
        panel.canChooseFiles = false; panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false; panel.canCreateDirectories = canCreate
        return panel.runModal() == .OK ? panel.url?.resolvingSymlinksInPath().path : nil
    }

    func protectFolder() {
        guard !fixtures, busy == nil else { return }
        guard let source = chooseDirectory(title: tr("Scegli la cartella da proteggere"),
                                           message: tr("Passo 1 di 2: la cartella da cifrare. Dopo la verifica il suo contenuto passa nell'immagine cifrata.")),
              let destination = chooseDirectory(title: tr("Scegli la destinazione sul disco esterno"),
                                                message: tr("Passo 2 di 2: dove salvare l'immagine cifrata. Serve una cartella su un disco esterno fisico, diversa dalla cartella da proteggere e fuori da essa."),
                                                startAt: "/Volumes", canCreate: true) else { return }
        perform(tr("Controllo della cartella e del disco…")) {
            _ = try await self.worker.request("cartelle.prepara_protezione", parameters: ["origine": source, "dove": destination, "minutes": self.minutes])
            self.keyRequest = KeyRequest(action: "cartelle.proteggi", title: tr("Proteggi %@", "\(URL(fileURLWithPath: source).lastPathComponent)"),
                                        parameters: ["origine": source, "dove": destination, "minutes": self.minutes], confirm: true)
        }
    }

    func askKey(_ folder: FolderItem, recovery: Bool = false) {
        guard !fixtures, busy == nil else { return }
        if recovery {
            keyRequest = KeyRequest(action: "cartelle.recupera", title: tr("Recupera %@", "\(folder.name)"),
                                    parameters: ["id": folder.id], confirm: false)
            return
        }
        perform(tr("Controllo dello stato della cartella…")) {
            let ready = try await self.worker.request("cartelle.prepara_apertura", parameters: ["id": folder.id, "minutes": self.minutes]) as? Record ?? [:]
            if ready.flag("gia_aperta") {
                self.notice = ready.text("messaggio", fallback: tr("La cartella è già aperta. Nessuna chiave necessaria; il timer esistente resta invariato."))
                try await self.refresh()
                return
            }
            guard ready.flag("pronto") else { throw AppError(message: tr("La cartella non è pronta per l'apertura. Aggiorna lo stato e riprova.")) }
            self.keyRequest = KeyRequest(action: "cartelle.apri", title: tr("Apri %@", "\(folder.name)"),
                                        parameters: ["id": folder.id, "minutes": self.minutes], confirm: false)
        }
    }

    func submitKey(_ request: KeyRequest, key: Data) {
        keyRequest = nil
        perform(request.action == "cartelle.proteggi" ? tr("Migrazione e verifica in corso…") : tr("Operazione in corso…")) {
            var sensitive = key
            defer { sensitive.resetBytes(in: 0..<sensitive.count) }
            let result = try await self.worker.request(request.action, parameters: request.parameters, key: sensitive)
            self.captureWarnings(result)
            if self.warning == nil { self.notice = request.action == "banco.run" ? tr("Prova terminata. Consulta gli esiti e le eventuali fasi in attesa.") : tr("Operazione completata.") }
            try await self.refresh()
        }
    }

    func close(_ folder: FolderItem) {
        perform(tr("Chiusura di %@…", "\(folder.name)")) {
            let result = try await self.worker.request("cartelle.chiudi", parameters: ["id": folder.id])
            self.captureWarnings(result); try await self.refresh()
        }
    }

    func forceClose(_ folder: FolderItem) {
        guard !fixtures, busy == nil else { return }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = tr("Forzare la chiusura di %@?", "\(folder.name)")
        alert.informativeText = tr("La cartella può essere in uso da un'app o da un terminale aperto dentro. Chiudili e prova prima Chiudi. La chiusura forzata può perdere modifiche non salvate.")
        alert.addButton(withTitle: tr("Annulla"))
        alert.addButton(withTitle: tr("Chiudi forzatamente"))
        guard alert.runModal() == .alertSecondButtonReturn else { return }
        perform(tr("Chiusura forzata di %@…", "\(folder.name)")) {
            let result = try await self.worker.request("cartelle.chiudi", parameters: ["id": folder.id, "force": true])
            self.captureWarnings(result)
            try await self.refresh()
            if folder.isIncomplete {
                let recoveryNotice = tr("Montaggi chiusi. La migrazione resta incompleta: usa Recupera la fonte o Annulla migrazione. La copia in chiaro può essere ancora presente.")
                self.warning = self.warning.map { $0 + "\n" + recoveryNotice } ?? recoveryNotice
            } else {
                self.notice = tr("Chiusura forzata completata. Controlla eventuali documenti con modifiche non salvate.")
            }
        }
    }

    func closeAll() {
        perform(tr("Chiusura di tutte le cartelle…")) {
            let results = try await self.worker.request("cartelle.chiudi_tutte") as? [Record] ?? []
            self.captureWarnings(results)
            try await self.refresh()
            if let failure = results.first(where: { $0["errore"] != nil }) { throw AppError(message: failure.text("errore")) }
        }
    }

    func cancelMigration(_ folder: FolderItem) {
        let alert = NSAlert()
        alert.messageText = tr("Annullare la migrazione di %@?", "\(folder.name)")
        alert.informativeText = tr("La fonte deve essere ancora integra. L'immagine cifrata viene conservata.")
        alert.addButton(withTitle: tr("Annulla la migrazione")); alert.addButton(withTitle: tr("Torna indietro"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        perform(tr("Controllo della fonte…")) {
            let result = try await self.worker.request("cartelle.annulla", parameters: ["id": folder.id])
            self.captureWarnings(result); try await self.refresh()
        }
    }

    func loadEvents() {
        perform(tr("Ricerca nel registro…")) {
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
        eventsKernelCollection = collection
        eventsKernelMessage = collection.text("message", fallback: tr("La raccolta kernel non è ancora verificata per questa ricerca."))
    }

    func watchFolder() {
        guard !fixtures, busy == nil, let path = chooseDirectory(title: tr("Sorveglia una cartella")) else { return }
        let identifier = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        perform(tr("Configurazione della sorveglianza…")) {
            let result = try await self.worker.request("registro.sorveglia", parameters: ["id": identifier, "percorso": path]) as? Record ?? [:]
            try await self.refresh()
            self.notice = result.text("messaggio", fallback: tr("Cartella configurata.")) + tr(" La raccolta è confermata solo quando il registro kernel è attivo e riconosce il suo ID.")
        }
    }

    func removeWatch(_ record: Record) {
        perform(tr("Rimozione della sorveglianza…")) {
            _ = try await self.worker.request("registro.rimuovi_sorveglianza", parameters: ["id": record.text("id")])
            if self.selectedFolder == record.text("id") { self.selectedFolder = "" }
            try await self.refresh()
            try await self.refreshEvents()
            self.notice = tr("Sorveglianza rimossa dalla configurazione. Gli eventi già raccolti restano nel registro.")
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
        perform(tr("Esportazione…")) {
            var params = parameters; params["path"] = path
            let result = try await self.worker.request(action, parameters: params) as? Record ?? [:]
            self.notice = tr("Esportazione salvata in %@.", "\(path)")
            if action == "registro.export_csv" {
                self.eventsKernelActive = result["kernel_active"] as? Bool
                let collection = result["kernel_collection"] as? Record ?? [:]
                self.eventsKernelCollection = collection
                self.eventsKernelMessage = collection.text("message", fallback: tr("La raccolta kernel non è ancora verificata per questa esportazione."))
            }
        }
    }

    func browse(_ path: String? = nil) {
        let target = path ?? (browsePath.isEmpty ? FileManager.default.homeDirectoryForCurrentUser.path : browsePath)
        perform(tr("Elenco della cartella…")) {
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
        perform(tr("Aggiornamento dell'etichetta…")) {
            _ = try await self.worker.request("etichette.segna", parameters: ["percorso": file.id, "etichetta": label, "nota": note])
            try await self.refreshBrowser(self.browsePath)
        }
    }

    func removeLabel(_ file: FileItem) {
        perform(tr("Rimozione dell'etichetta…")) {
            _ = try await self.worker.request("etichette.togli", parameters: ["percorso": file.id])
            try await self.refreshBrowser(self.browsePath)
        }
    }

    func prepareBank() {
        guard !bankDestination.isEmpty else { error = tr("Scegli prima la destinazione sul disco esterno."); return }
        perform(tr("Controllo delle condizioni per il banco…")) {
            self.bankPreview = try await self.worker.request("banco.anteprima", parameters: ["dove": self.bankDestination]) as? Record ?? [:]
        }
    }

    func runBank() {
        guard !fixtures, busy == nil else { return }
        guard registry.flag("running"), registry.flag("healthy") else {
            error = tr("Il banco richiede un registro kernel attivo e sano. Completa prima le autorizzazioni nelle Impostazioni."); return
        }
        guard !bankDestination.isEmpty else { error = tr("Scegli una destinazione sul disco esterno."); return }
        perform(tr("Controllo del disco e delle condizioni del banco…")) {
            self.bankPreview = try await self.worker.request("banco.anteprima", parameters: ["dove": self.bankDestination]) as? Record ?? [:]
            guard !self.bankPreview.flag("richiede_autorizzazione") else {
                throw AppError(message: tr("Completa le autorizzazioni del registro e del Desktop prima di inserire la chiave."))
            }
            self.keyRequest = KeyRequest(action: "banco.run", title: tr("Avvia il banco di prova"),
                                        parameters: ["dove": self.bankDestination, "minutes": self.minutes, "agenti_reali": self.realAgents], confirm: true)
        }
    }

    func installHooks() {
        perform(tr("Preparazione degli hook…")) {
            let plan = try await self.worker.request("hooks.install_plan") as? Record ?? [:]
            let alert = NSAlert()
            alert.messageText = tr("Collegare Paratia alle sessioni agente?")
            let changes = plan["changes"] as? [Record] ?? []
            let paths = changes.map { "• " + $0.text("path") }.joined(separator: "\n")
            alert.informativeText = tr("Verranno conservate le configurazioni esistenti e creati backup prima delle modifiche.\n\n") + paths + tr("\n\nIn Codex la fiducia negli hook deve essere approvata da te tramite /hooks. Le sessioni esistenti devono essere riavviate.")
            alert.addButton(withTitle: tr("Applica il piano")); alert.addButton(withTitle: tr("Annulla"))
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            let result = try await self.worker.request("hooks.applica") as? Record ?? [:]
            let backups = (result["backups"] as? [String]) ?? []
            self.warning = result.text("message", fallback: tr("Hook configurati. Riavvia le sessioni e verifica la fiducia in Codex."))
                + (backups.isEmpty ? "" : "\n" + tr("Backup: ") + backups.joined(separator: "\n"))
            try await self.refresh()
        }
    }

    func restoreHooks() {
        let panel = NSOpenPanel()
        panel.title = tr("Scegli un backup degli hook di Paratia")
        panel.canChooseFiles = true; panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false; panel.showsHiddenFiles = true
        panel.allowedContentTypes = [.json]
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".claude")
        guard panel.runModal() == .OK, let path = panel.url?.path else { return }
        let alert = NSAlert()
        alert.messageText = tr("Ripristinare la configurazione degli hook?")
        alert.informativeText = tr("Paratia ripristina il backup soltanto se la configurazione corrisponde ancora a quella installata. Le modifiche successive vengono conservate. Prima del ripristino viene creato un nuovo backup.")
        alert.addButton(withTitle: tr("Ripristina")); alert.addButton(withTitle: tr("Annulla"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        perform(tr("Ripristino della configurazione degli hook…")) {
            let result = try await self.worker.request("hooks.ripristina", parameters: ["path": path]) as? Record ?? [:]
            try await self.refresh()
            self.warning = tr("Configurazione ripristinata. Riavvia le sessioni e verifica gli hook nell'harness.\nNuovo backup: ") + result.text("backup")
        }
    }

    func installRegistry() {
        perform(tr("Preparazione dell'installazione…")) {
            try NativeInstall.validateBootstrap(bundle: URL(fileURLWithPath: Bundle.main.bundlePath, isDirectory: true))
            let plan = try await self.worker.request("registro.install_plan") as? Record ?? [:]
            let alert = NSAlert()
            alert.messageText = tr("Installare il registro degli accessi?")
            // Il testo del piano dice se il permesso va rifatto (firma ad hoc) o resta valido (firma stabile).
            alert.informativeText = tr("L'installazione parte da questa copia di bootstrap protetta e crea una copia separata per il servizio Paratia. macOS gestisce la password amministratore. Dopo l'installazione chiudi questa copia e riapri /Applications/Paratia.app. Python non va autorizzato.") + "\n\n" + plan.text("message", fallback: "")
            alert.addButton(withTitle: tr("Autorizza con macOS")); alert.addButton(withTitle: tr("Annulla"))
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            let result = try await NativeInstall.execute(plan: plan)
            guard result.flag("installed") else { throw AppError(message: tr("L'installazione non è stata confermata. Riprova dalle Impostazioni.")) }
            // Con firma ad hoc il permesso va rifatto a ogni build; con firma stabile resta valido.
            let regrant = (result["fda_regrant_after_build"] as? Bool) ?? true
            self.warning = regrant
                ? tr("Registro installato. Chiudi la copia di bootstrap e riapri /Applications/Paratia.app. In Accesso completo al disco abilita quell'app; dopo questa nuova build rimuovi e aggiungi di nuovo la voce. Python non va autorizzato. Premi Aggiorna nell'app normale per verificare il servizio.")
                : tr("Registro installato. Chiudi la copia di bootstrap e riapri /Applications/Paratia.app. In Accesso completo al disco abilita quell'app: con la stessa firma il permesso resta valido. Python non va autorizzato. Premi Aggiorna nell'app normale per verificare il servizio.")
            try await self.refresh()
        }
    }

    func verifyRegistry() {
        perform(tr("Verifica delle catene del registro…")) {
            self.integrity = try await self.worker.request("registro.verifica") as? Record ?? [:]
        }
    }

    private func captureWarnings(_ result: Any) {
        let records = (result as? [Record]) ?? ((result as? Record).map { [$0] } ?? [])
        let warnings = records.compactMap { $0["avviso_registro"] as? String }
        if !warnings.isEmpty { warning = warnings.joined(separator: "\n") }
    }

    private func loadFixtures() {
        // I percorsi di anteprima passano da tr(): ogni lingua mostra il suo nome di cartella.
        watchedFolders = [["id": "synthetic-watch", "nome": tr("Progetto di esempio"), "origine": tr("/Esempio/3"), "tipo": "sorveglianza", "esiste": true,
                           "raccolta": "rifiutata", "reason_code": "folder_unavailable", "message": tr("Cartella non disponibile. Esito sintetico.")]]
        folders = [FolderItem(data: ["id": "synthetic-1", "nome": tr("Contratti di esempio"), "origine": tr("/Esempio/1"), "bundle": tr("/Esempio/disco/1.sparsebundle"), "stato": "chiusa", "file": 24, "byte": 12_582_912, "minutes": 15]),
                   FolderItem(data: ["id": "synthetic-2", "nome": tr("Documenti di esempio"), "origine": tr("/Esempio/2"), "bundle": tr("/Esempio/disco/2.sparsebundle"), "stato": "aperta", "file": 9, "byte": 5_242_880, "minutes": 15])]
        registry = ["installed": true, "running": false, "healthy": false, "needs_root": false,
                    "needs_update": true, "event_lag_seconds": 3.2, "lines_per_second": 28_400.0, "last_event_age_seconds": 12.0,
                    "update_message": tr("Il servizio sintetico usa una build diversa dall'app. Nessuna misura reale."),
                    "message": tr("Stato sintetico: servizio da aggiornare e cartella rifiutata. Nessuna misura reale."),
                    "health_reasons": [["code": "event_lag", "message": tr("Gli eventi arrivano in ritardo. Esito sintetico.")],
                                       ["code": "rejected_folders", "message": tr("Una cartella è rifiutata dal raccoglitore. Esito sintetico.")]],
                    "watch_status": [["id": "synthetic-watch", "status": "rejected", "reason_code": "folder_unavailable", "message": tr("Cartella non disponibile. Esito sintetico.")]],
                    "update_steps": [tr("Chiudi Paratia."), tr("Prepara il bootstrap usando il comando riportato sotto."),
                                     tr("Apri la copia di bootstrap e premi Installa il registro, autorizzando con macOS."),
                                     tr("Chiudi la copia di bootstrap."), tr("In Accesso completo al disco controlla che /Applications/Paratia.app sia abilitata. Se la firma è cambiata, rimuovi e aggiungi di nuovo la voce. Non autorizzare Python."),
                                     tr("Riapri /Applications/Paratia.app e premi Aggiorna; verifica la conferma delle cartelle e un evento kernel.")]]
        hooks = ["pending": true, "message": tr("Collega gli hook e conferma la fiducia nell'harness.")]
        events = [EventItem(id: "example", data: ["quando": "2026-10-08 09:41:05", "evento": "cartella-chiusa", "percorso": tr("/Esempio/2"), "processo": "Paratia", "pid": 1234, "utente": tr("utente di esempio"), "source": "paratia", "agente": NSNull(), "esito": "riuscito"])]
        eventTotal = events.count
        browsePath = tr("/Esempio")
        files = [FileItem(data: ["nome": tr("Contratti"), "percorso": tr("/Esempio/1"), "cartella": true, "etichetta": "riservato", "ereditata": false]),
                 FileItem(data: ["nome": tr("Materiale pubblico"), "percorso": tr("/Esempio/3"), "cartella": true, "etichetta": "pubblico", "ereditata": false])]
        bankPreview = ["stato": "sintetica", "percorso": tr("/Esempio/Desktop/folder-test"), "file": 4,
                       "byte": 8_396_800, "messaggio": tr("Anteprima sintetica: nessun accesso al Desktop reale.")]
        let phases: [Record] = ["prima", "chiusa", "riaperta", "richiusa"].map { name in
            let closed = name == "chiusa" || name == "richiusa"
            let probes: [Record] = ["shell", "mdls", "codex", "claude"].map { actor in
                ["attore": actor, "misurato": actor == "shell", "riuscito": actor == "shell" ? !closed : NSNull(),
                 "errno": closed && actor == "shell" ? 2 : NSNull(), "rc": actor == "shell" ? 0 : NSNull(),
                 "copertura_verificata": false, "riscontri_kernel": [],
                 "messaggio": tr("Esito sintetico per verificare la schermata; nessuna prova reale.")]
            }
            return ["nome": name, "iniziata": "2026-10-08T09:41:05+02:00", "conclusa": "2026-10-08T09:41:07+02:00",
                    "atteso": closed ? "rifiuto" : "accesso", "stato_cartella": closed ? "chiusa" : "aperta",
                    "file_visibili": closed ? 0 : 4, "byte_visibili": closed ? 0 : 8_396_800, "prove": probes, "ok": false]
        }
        let run: Record = ["id": "fixture-bank", "stato": "incompleto", "file": 4, "byte": 8_396_800,
                           "iniziata": "2026-10-08T09:41:05+02:00", "conclusa": "2026-10-08T09:41:07+02:00",
                           "messaggio": tr("Storico sintetico. Le prove reali attendono le autorizzazioni."), "fasi": phases,
                           "percorso": tr("/Esempio/Desktop/folder-test"), "stato_finale": "chiusa"]
        bank = run; bank["prove"] = [run]
    }
}
