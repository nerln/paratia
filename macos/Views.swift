import SwiftUI
import AppKit

struct ContentView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        NavigationSplitView {
            List(Section.allCases, selection: $model.section) { section in
                Label(section.rawValue, systemImage: section.icon)
                    .foregroundStyle(model.section == section ? Color.white : Color.primary).tag(section)
            }
            .navigationSplitViewColumnWidth(min: 175, ideal: 190, max: 240)
            .safeAreaInset(edge: .bottom) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("PARATIA").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    Text(model.fixtures ? "Anteprima · dati sintetici" : "Cartelle cifrate. Decisioni umane.")
                        .font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(16)
            }
        } detail: {
            VStack(spacing: 0) {
                if model.fixtures {
                    Banner(text: "Anteprima con dati sintetici. Nessuna operazione reale eseguita.", icon: "photo", color: .blue)
                }
                switch model.section ?? .folders {
                case .folders: FoldersView(model: model)
                case .logs: RegistryView(model: model)
                case .labels: LabelsView(model: model)
                case .bank: BankView(model: model)
                case .settings: SettingsView(model: model)
                }
                if let notice = model.notice { Banner(text: notice, icon: "checkmark.circle", color: .green) }
                if let warning = model.warning { Banner(text: warning, icon: "exclamationmark.triangle", color: .orange) }
                if let busy = model.busy {
                    HStack { ProgressView().controlSize(.small); Text(busy); Spacer(); Text("Lascia terminare l'operazione.").foregroundStyle(.secondary) }
                        .font(.callout).padding(12).background(.regularMaterial)
                }
            }.navigationTitle((model.section ?? .folders).rawValue)
        }
        .toolbar {
            ToolbarItem { Button { model.refreshAction() } label: { Label("Aggiorna", systemImage: "arrow.clockwise") }.disabled(model.busy != nil || model.fixtures) }
        }
        .sheet(item: $model.keyRequest) { request in KeySheet(model: model, request: request) }
        .sheet(item: $model.detail) { event in EventDetail(event: event) }
        .alert("Operazione non riuscita", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("Ho capito") { model.error = nil }
        } message: { Text(model.error ?? "") }
        .task { if !model.fixtures { model.refreshAction() } }
        .frame(minWidth: 980, minHeight: 650)
    }
}

struct Banner: View {
    let text: String
    let icon: String
    let color: Color
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).foregroundStyle(color)
            Text(text).font(.callout).frame(maxWidth: .infinity, alignment: .leading)
        }.padding(12).background(color.opacity(0.08))
    }
}

struct PageHeading: View {
    let title: String
    let subtitle: String
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.largeTitle.weight(.semibold))
            Text(subtitle).font(.body).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(.bottom, 20)
    }
}

struct FoldersView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PageHeading(title: "Le tue cartelle protette", subtitle: "Da chiuse, i file restano nell'immagine cifrata anche quando il disco esterno è sbloccato.")
                HStack {
                    Button { model.protectFolder() } label: { Label("Proteggi una cartella", systemImage: "plus") }.buttonStyle(.borderedProminent)
                    Button { model.closeAll() } label: { Label("Chiudi tutte", systemImage: "lock.fill") }.disabled(!model.folders.contains(where: { $0.state == "aperta" || $0.isIncomplete }))
                    Spacer()
                    Stepper("Chiusura dopo \(model.minutes) min", value: $model.minutes, in: 1...1440).frame(width: 235)
                }.disabled(model.busy != nil || model.fixtures)
                if model.folders.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "lock.rectangle.stack").font(.system(size: 44)).foregroundStyle(.secondary)
                        Text("Nessuna cartella protetta").font(.title2.weight(.medium))
                        Text("Scegli una cartella e una destinazione sul disco esterno. La chiave la scegli tu.").foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity).padding(50)
                }
                ForEach(model.folders) { folder in
                    FolderCard(model: model, folder: folder)
                }
                GroupBox {
                    VStack(alignment: .leading, spacing: 7) {
                        Label("Prima di migrare", systemImage: "info.circle").font(.headline)
                        Text("Chiudi i documenti e le app che possono modificare la fonte. Paratia verifica la copia, chiude e riapre il compartimento, poi rimuove l'originale.")
                        Text("Backup, snapshot e copie già sincronizzate possono contenere versioni precedenti.").foregroundStyle(.secondary)
                    }.font(.callout).frame(maxWidth: .infinity, alignment: .leading).padding(8)
                }
            }.padding(28)
        }
    }
}

struct FolderCard: View {
    @ObservedObject var model: AppModel
    let folder: FolderItem
    private var color: Color { folder.isIncomplete ? .red : folder.state == "aperta" ? .orange : .green }
    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 13) {
                HStack(alignment: .top, spacing: 14) {
                    Image(systemName: folder.isIncomplete ? "exclamationmark.triangle.fill" : folder.state == "aperta" ? "lock.open.fill" : "lock.fill")
                        .font(.title).foregroundStyle(color).frame(width: 34)
                    VStack(alignment: .leading, spacing: 5) {
                        Text(folder.name).font(.title3.weight(.semibold))
                        Text(folder.source).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                    Spacer()
                    Text(folder.isIncomplete ? "Da recuperare" : folder.state == "aperta" ? "Aperta" : "Chiusa")
                        .font(.callout.weight(.medium)).foregroundStyle(color)
                }
                HStack {
                    Label("\(folder.data.number("file")) file · \(byteCount(folder.data.number("byte")))", systemImage: "doc.on.doc")
                    Spacer()
                    if folder.isIncomplete {
                        Button("Recupera la fonte") { model.askKey(folder, recovery: true) }
                        Button("Annulla migrazione") { model.cancelMigration(folder) }
                        if !folder.data.text("montaggio_temporaneo", fallback: "").isEmpty {
                            Button("Chiudi montaggi") { model.close(folder) }
                            Button("Forza chiusura…", role: .destructive) { model.forceClose(folder) }
                        }
                    } else if folder.state == "aperta" {
                        Button("Mostra nel Finder") { NSWorkspace.shared.open(URL(fileURLWithPath: folder.source)) }
                        Button("Chiudi") { model.close(folder) }.buttonStyle(.borderedProminent)
                        Button("Forza chiusura…", role: .destructive) { model.forceClose(folder) }
                    } else {
                        Button("Apri…") { model.askKey(folder) }.buttonStyle(.borderedProminent)
                    }
                }.font(.callout).disabled(model.busy != nil || model.fixtures)
                if folder.isIncomplete {
                    Text("La protezione non è completa. Le copie residue vengono conservate per il recupero.").font(.callout).foregroundStyle(.red)
                    ForEach(["plaintext_residuo", "recupero_temporaneo"], id: \.self) { field in
                        if let path = folder.data[field] as? String {
                            Text(path).font(.caption.monospaced()).textSelection(.enabled)
                        }
                    }
                } else if folder.state == "aperta" {
                    Text("I processi dell'utente possono leggere i file. Chiusura richiesta dopo \(folder.data.number("minutes")) minuti; se occupata, Paratia ritenta senza forzare.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text("Registro: " + model.watchStatus(folder.data)).font(.caption).foregroundStyle(.secondary)
                Text("Immagine: \(folder.data.text("bundle"))").font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            }.padding(12)
        }
    }
}

struct KeySheet: View {
    @ObservedObject var model: AppModel
    let request: KeyRequest
    @Environment(\.dismiss) var dismiss
    @State private var key = ""
    @State private var confirmation = ""
    private var valid: Bool { key.utf8.count >= 12 && (!request.confirm || key == confirmation) }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label(request.title, systemImage: "key.fill").font(.title2.weight(.semibold))
            Text(request.confirm ? "Usa una chiave propria del compartimento, diversa da quella del disco. Conservane una copia in un luogo che controlli." : "Inserisci la chiave di questo compartimento.")
            SecureField("Chiave del compartimento", text: $key).textFieldStyle(.roundedBorder)
            if request.confirm { SecureField("Ripeti la chiave", text: $confirmation).textFieldStyle(.roundedBorder) }
            Text("Almeno 12 byte. La chiave non viene salvata nel portachiavi, nei file o nel registro.").font(.caption).foregroundStyle(.secondary)
            if request.confirm && !confirmation.isEmpty && key != confirmation { Text("Le chiavi non coincidono.").font(.callout).foregroundStyle(.red) }
            HStack {
                Spacer()
                Button("Annulla") { key = ""; confirmation = ""; dismiss() }.keyboardShortcut(.cancelAction)
                Button("Continua") {
                    let data = Data(key.utf8)
                    key = ""; confirmation = ""
                    model.submitKey(request, key: data)
                    dismiss()
                }.keyboardShortcut(.defaultAction).disabled(!valid)
            }
        }.padding(28).frame(width: 520).onDisappear { key = ""; confirmation = "" }
    }
}

struct RegistryView: View {
    @ObservedObject var model: AppModel
    @State private var selection: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            PageHeading(title: "Chi ha aperto cosa", subtitle: "Metadati delle operazioni dell'app e degli eventi kernel osservati. I contenuti dei file restano fuori dal registro.")
            GroupBox("Cartelle sorvegliate") {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("Puoi sorvegliare anche una cartella senza cifrarla.").font(.callout).foregroundStyle(.secondary)
                        Spacer()
                        Button("Sorveglia una cartella…") { model.watchFolder() }.buttonStyle(.borderedProminent)
                    }
                    if model.watchedFolders.isEmpty { Text("Nessuna cartella sorvegliata configurata.").font(.caption).foregroundStyle(.secondary) }
                    else {
                        ScrollView {
                            VStack(alignment: .leading, spacing: 12) {
                                ForEach(Array(model.watchedFolders.enumerated()), id: \.offset) { _, folder in
                                    HStack(alignment: .top) {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Label(folder.text("nome"), systemImage: "folder").font(.callout.weight(.semibold))
                                            Text(folder.text("origine")).font(.caption).textSelection(.enabled)
                                            Text(model.watchStatus(folder)).font(.caption).foregroundStyle(.secondary)
                                        }
                                        Spacer()
                                        Button("Apri registro") { model.showWatchEvents(folder) }
                                        Button("Rimuovi") { model.removeWatch(folder) }
                                    }
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }.frame(maxHeight: 150)
                    }
                }.padding(8).disabled(model.busy != nil || model.fixtures)
            }
            HStack {
                Picker("Cartella", selection: $model.selectedFolder) {
                    Text("Tutte le cartelle").tag("")
                    ForEach(model.registryFolders) { Text($0.name).tag($0.id) }
                }.frame(width: 220)
                TextField("File o percorso", text: $model.fileFilter)
                TextField("Processo o PID", text: $model.processFilter)
                Picker("Agente", selection: $model.agentFilter) {
                    Text("Tutti").tag(""); Text("Agente riconosciuto").tag("true")
                    Text("Non agente").tag("false"); Text("Sconosciuto").tag("unknown")
                    Text("Codex").tag("Codex"); Text("Claude Code").tag("Claude Code")
                    Text("ChatGPT").tag("ChatGPT"); Text("agentbridge").tag("agentbridge")
                }.frame(width: 175)
            }.textFieldStyle(.roundedBorder)
            HStack {
                Toggle("Intervallo", isOn: $model.useDates)
                if model.useDates {
                    DatePicker("Da", selection: $model.since); DatePicker("A", selection: $model.until)
                }
                Spacer()
                Button("Cerca") { model.loadEvents() }.buttonStyle(.borderedProminent)
                Button("Esporta CSV…") { model.export("registro.export_csv", title: "Esporta il registro filtrato", extension: "csv", parameters: ["filters": model.filters]) }
            }.disabled(model.busy != nil || model.fixtures)
            if !model.registry.flag("running") || !model.registry.flag("healthy") {
                Banner(text: model.registry.text("message", fallback: "Il registro kernel non è ancora verificato. Completa le autorizzazioni nelle Impostazioni."), icon: "exclamationmark.circle", color: .orange)
            }
            if model.registry.flag("needs_update") {
                HStack {
                    Label(model.registry.text("update_message", fallback: "Aggiorna il registro e verifica la build installata."), systemImage: "arrow.triangle.2.circlepath").font(.callout)
                    Spacer()
                    Button("Passi per aggiornare…") { model.section = .settings }
                }
            }
            RegistryHealthDetails(model: model, record: model.registry)
            Table(model.events, selection: $selection) {
                TableColumn("Ora", value: \.date).width(min: 145, ideal: 170)
                TableColumn("Evento", value: \.event).width(min: 100, ideal: 120)
                TableColumn("Percorso", value: \.path)
                TableColumn("Processo", value: \.process)
                TableColumn("Agente", value: \.agent).width(min: 85, ideal: 110)
            }.contextMenu { Button("Apri dettaglio") { openDetail() }.disabled(selection == nil) }
            HStack {
                Text("\(model.eventTotal) eventi\(model.eventsTruncated ? " · visualizzazione limitata: restringi i filtri o esporta il CSV completo" : "")").font(.caption).foregroundStyle(.secondary)
                Label(model.eventsKernelActive == true ? "Raccolta kernel attiva" : model.eventsKernelActive == false ? "Raccolta kernel inattiva" : "Raccolta kernel da verificare", systemImage: model.eventsKernelActive == true ? "checkmark.circle" : "exclamationmark.circle")
                    .font(.caption).foregroundStyle(model.eventsKernelActive == true ? Color.green : .orange)
                Spacer()
                Button("Apri dettaglio") { openDetail() }.disabled(selection == nil)
            }
            Text(model.eventsKernelMessage).font(.caption).foregroundStyle(.secondary)
            if !model.eventsKernelCollection.isEmpty {
                RegistryHealthDetails(model: model, record: model.eventsKernelCollection)
            }
            Text("Un'apertura per lettura non prova una lettura dei byte. Gli eventi mancanti e la discendenza sconosciuta vengono indicati, non ricostruiti.")
                .font(.caption).foregroundStyle(.secondary)
        }.padding(28).onAppear { if model.events.isEmpty { model.loadEvents() } }
    }
    private func openDetail() { model.detail = model.events.first { $0.id == selection } }
}

struct RegistryHealthDetails: View {
    @ObservedObject var model: AppModel
    let record: Record
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(model.collectionMetrics(record)).font(.caption).foregroundStyle(.secondary)
            Text(model.lastEventAge(record)).font(.caption).foregroundStyle(.secondary)
            ForEach(Array(model.healthReasons(record).enumerated()), id: \.offset) { _, reason in
                Label(reason.text("message"), systemImage: "exclamationmark.circle")
                    .font(.caption).foregroundStyle(.orange)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct RegistryUpdateSteps: View {
    @ObservedObject var model: AppModel
    var body: some View {
        if model.registry.flag("needs_update") {
            GroupBox("Aggiorna il registro") {
                VStack(alignment: .leading, spacing: 10) {
                    Text(model.registry.text("update_message", fallback: "Aggiorna il registro e verifica la build installata.")).font(.callout)
                    Text("Segui questi passi nell'ordine indicato.").font(.callout)
                    ForEach(Array(model.registryUpdateSteps.enumerated()), id: \.offset) { index, step in
                        Text("\(index + 1). \(step)").font(.callout).textSelection(.enabled)
                    }
                    Text("Il comando per preparare il bootstrap è riportato qui sotto in Prepara la copia per installare il registro.")
                        .font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
            }
        }
    }
}

struct EventDetail: View {
    let event: EventItem
    @Environment(\.dismiss) var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(event.event).font(.title2.weight(.semibold))
            Text(event.path).font(.callout.monospaced()).textSelection(.enabled)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(event.data.keys.sorted(), id: \.self) { key in
                        HStack(alignment: .top) {
                            Text(detailLabel(key)).foregroundStyle(.secondary).frame(width: 170, alignment: .leading)
                            Text(detailValue(event.data[key])).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                        }.font(.callout)
                    }
                }
            }
            HStack { Spacer(); Button("Chiudi") { dismiss() }.keyboardShortcut(.defaultAction) }
        }.padding(28).frame(width: 720, height: 560)
    }
    private func detailValue(_ value: Any?) -> String {
        guard let value = value, !(value is NSNull) else { return "Non disponibile" }
        if value is [Any] || value is Record { return prettyJSON(value) }
        return String(describing: value)
    }
    private func detailLabel(_ key: String) -> String {
        ["quando": "Data e ora", "evento": "Operazione", "percorso": "Percorso", "processo": "Processo",
         "pid": "PID", "ppid": "PID padre", "utente": "Utente", "agente": "Discendenza agente",
         "nome_agente": "Agente riconosciuto", "source": "Fonte", "esito": "Esito", "errore": "Errore",
         "cartella": "Compartimento", "chain_ok": "Catena verificata", "catena_ok": "Catena verificata",
         "precedente": "Hash precedente", "hash": "Hash", "fread": "Aperto per lettura", "fwrite": "Aperto per scrittura"][key] ?? key
    }
}

struct LabelsView: View {
    @ObservedObject var model: AppModel
    @State private var zoneTarget: FileItem?
    @State private var zoneName = "lavoro"
    @State private var selection: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            PageHeading(title: "Decidi cosa proteggere", subtitle: "Un'etichetta registra una decisione. La cifratura inizia quando proteggi la cartella.")
            HStack {
                Button { if let p = model.browseParent { model.browse(p) } } label: { Image(systemName: "arrow.up") }.disabled(model.browseParent == nil)
                TextField("Percorso della cartella", text: $model.browsePath).onSubmit { model.browse() }
                Button("Scegli…") { if let p = model.chooseDirectory(title: "Sfoglia una cartella") { model.browse(p) } }
                Toggle("Nascosti", isOn: $model.showHidden).onChange(of: model.showHidden) { _ in model.browse() }
                Button("Vai") { model.browse() }
            }.textFieldStyle(.roundedBorder).disabled(model.busy != nil || model.fixtures)
            Table(model.files, selection: $selection) {
                TableColumn("Nome") { file in Label(file.name, systemImage: file.isDirectory ? "folder" : "doc") }
                TableColumn("Etichetta") { file in
                    Text(file.data.text("etichetta", fallback: "Da esaminare") + (file.data.flag("ereditata") ? " · ereditata" : ""))
                        .foregroundStyle(file.data.text("etichetta") == "riservato" ? Color.red : .secondary)
                }
                TableColumn("Dimensione") { file in Text(file.isDirectory ? "—" : byteCount(file.data.number("peso"))) }
            }
            if let file = model.files.first(where: { $0.id == selection }) {
                HStack {
                    if file.isDirectory { Button("Entra") { model.browse(file.id) } }
                    Button("Riservato") { model.mark(file, label: "riservato") }
                    Button("Zona…") { zoneTarget = file }
                    Button("Pubblico") { model.mark(file, label: "pubblico") }
                    Button("Togli etichetta") { model.removeLabel(file) }.disabled(file.data.flag("ereditata"))
                    Spacer()
                    Button("Aggiorna elenco") { model.browse() }
                }.disabled(model.busy != nil || model.fixtures)
                if file.data.flag("ereditata") { Text("Etichetta ereditata da \(file.data.text("da")). Puoi assegnarne una specifica a questo elemento.").font(.caption).foregroundStyle(.secondary) }
            }
            DisclosureGroup("Il piano delle etichette") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("\(model.labels.count) etichette · \(byteCount(model.labelPlan.number("byte_totali"))) nel piano")
                    ForEach(Array(((model.labelPlan["mosse"] as? [Record]) ?? []).enumerated()), id: \.offset) { _, item in
                        Text(item.text("percorso") + " · " + item.text("etichetta")).font(.caption).textSelection(.enabled)
                    }
                    ForEach(Array(((model.labelPlan["problemi"] as? [Record]) ?? []).enumerated()), id: \.offset) { _, problem in
                        Text(problem.text("percorso") + ": " + (problem.text("perche") == "the path is gone" ? "Il percorso non esiste più." : problem.text("perche"))).font(.caption).foregroundStyle(.orange)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            Text("Il browser elenca nomi, dimensioni ed etichette. Non mostra anteprime o contenuti dei file.").font(.caption).foregroundStyle(.secondary)
        }.padding(28).onAppear { if model.files.isEmpty { model.browse() } }
        .sheet(item: $zoneTarget) { file in
            VStack(alignment: .leading, spacing: 16) {
                Text("Assegna a una zona").font(.title2)
                TextField("Nome della zona", text: $zoneName).textFieldStyle(.roundedBorder)
                Text("La zona rimane leggibile dalla sessione che ci lavora. L'etichetta non crea la zona.").font(.callout).foregroundStyle(.secondary)
                HStack { Spacer(); Button("Annulla") { zoneTarget = nil }; Button("Segna") { model.mark(file, label: "zona:" + zoneName.trimmingCharacters(in: .whitespaces)); zoneTarget = nil }.disabled(zoneName.isEmpty) }
            }.padding(24).frame(width: 430)
        }
    }
}

struct BankView: View {
    @ObservedObject var model: AppModel
    private var history: [Record] { model.bank["prove"] as? [Record] ?? [] }
    private var phases: [Record] { model.bank["fasi"] as? [Record] ?? [] }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                PageHeading(title: "Prima, chiusa, aperta, richiusa", subtitle: "Il banco usa la cartella di prova sul Desktop e conserva gli esiti reali di ogni fase.")
                Banner(text: "I tuoi file vengono esaminati solo attraverso metadati. I file sintetici vengono creati soltanto se la cartella di prova è vuota.", icon: "doc.text", color: .blue)
                HStack {
                    Text(model.bankDestination.isEmpty ? "Destinazione sul disco esterno da scegliere" : model.bankDestination).font(.callout).textSelection(.enabled)
                    Spacer()
                    Button("Scegli destinazione…") { if let p = model.chooseDirectory(title: "Scegli la destinazione del banco sul disco esterno") { model.bankDestination = p } }
                }
                Toggle("Autorizzo le CLI reali, incluse eventuali richieste del portachiavi", isOn: $model.realAgents)
                Text("Codex e Claude Code avviano processi figli per la prova, senza chiamare un modello. Le CLI possono chiedere autenticazione o accesso al portachiavi: decidi nei dialoghi di macOS. Un rifiuto degli hook resta un esito reale.").font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("Controlla le condizioni") { model.prepareBank() }
                    Button("Esegui la sequenza…") { model.runBank() }.buttonStyle(.borderedProminent)
                    Spacer()
                    Button("Esporta JSON…") { model.export("banco.export_json", title: "Esporta lo storico del banco", extension: "json") }
                    Button("Esporta CSV…") { model.export("banco.export_csv", title: "Esporta lo storico del banco", extension: "csv") }
                }.disabled(model.busy != nil || model.fixtures)
                if !model.bankPreview.isEmpty {
                    GroupBox("Condizioni del banco") {
                        VStack(alignment: .leading, spacing: 10) {
                            Label(bankState(model.bankPreview.text("stato")), systemImage: model.bankPreview.flag("richiede_autorizzazione") ? "exclamationmark.circle" : "info.circle").font(.headline)
                            Text(model.bankPreview.text("messaggio", fallback: "Controlla le condizioni prima di avviare il banco."))
                            Text(model.bankPreview.text("percorso")).font(.callout).textSelection(.enabled)
                            Text(inventory(model.bankPreview)).font(.caption).foregroundStyle(.secondary)
                            if model.bankPreview.flag("richiede_autorizzazione") { Text("Autorizzazioni necessarie prima della prova.").font(.caption).foregroundStyle(.orange) }
                            DisclosureGroup("Dati della verifica") { Text(prettyJSON(model.bankPreview)).font(.caption.monospaced()).textSelection(.enabled) }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                    }
                }
                GroupBox("Ultima prova") {
                    VStack(alignment: .leading, spacing: 12) {
                        if model.bank.isEmpty || model.bank.flag("pending") || history.isEmpty {
                            Label("Nessuna prova reale confermata", systemImage: "clock").font(.headline)
                            Text(model.bank.text("messaggio", fallback: model.bank.text("message", fallback: "Completa le autorizzazioni del registro e controlla le condizioni prima di avviare il banco.")))
                        } else {
                            HStack {
                                Label(bankState(model.bank.text("stato")), systemImage: model.bank.text("stato") == "completo" ? "checkmark.circle" : "exclamationmark.circle").font(.headline)
                                Spacer()
                                Text("\(history.count) prove nello storico").font(.caption).foregroundStyle(.secondary)
                            }
                            Text(model.bank.text("messaggio", fallback: "Consulta gli esiti delle singole fasi."))
                            Text(model.bank.text("percorso")).font(.callout).textSelection(.enabled)
                            Text(inventory(model.bank)).font(.callout)
                            Text("Avviata: " + model.bank.text("iniziata") + " · Conclusa: " + model.bank.text("conclusa", fallback: "in attesa")).font(.caption).foregroundStyle(.secondary)
                            if let finalState = model.bank["stato_finale"] as? String {
                                Text("Chiusura finale: " + bankState(finalState)).font(.callout)
                            }
                            if let migration = model.bank["verifica_migrazione"] as? Record {
                                Text("Migrazione: \(migration.number("file_prima")) file, \(byteCount(migration.number("byte_prima"))) prima → \(migration.number("file_dopo")) file, \(byteCount(migration.number("byte_dopo"))) dopo. " + (migration.flag("verificato") ? "Copia verificata." : "Verifica mancante."))
                                    .font(.callout).foregroundStyle(migration.flag("verificato") ? Color.primary : .orange)
                            }
                            if let warning = model.bank["avviso_registro"] as? String { Banner(text: warning, icon: "exclamationmark.triangle", color: .orange) }
                            ForEach(Array(phases.enumerated()), id: \.offset) { _, phase in BankPhaseCard(phase: phase) }
                            if history.count > 1 {
                                DisclosureGroup("Prove precedenti (\(history.count - 1))") {
                                    VStack(alignment: .leading, spacing: 12) {
                                        ForEach(Array(history.dropLast().reversed().enumerated()), id: \.offset) { _, previous in
                                            VStack(alignment: .leading, spacing: 5) {
                                                Text(previous.text("iniziata") + " · " + bankState(previous.text("stato"))).font(.headline)
                                                Text(previous.text("messaggio", fallback: "Esiti conservati nello storico."))
                                                Text(previous.text("percorso")).font(.caption).textSelection(.enabled)
                                                ForEach(Array(((previous["fasi"] as? [Record]) ?? []).enumerated()), id: \.offset) { _, phase in BankPhaseCard(phase: phase) }
                                            }.padding(.vertical, 6)
                                        }
                                    }
                                }
                            }
                        }
                        if !model.bank.isEmpty { DisclosureGroup("Dettagli dello storico") { Text(prettyJSON(model.bank)).font(.caption.monospaced()).textSelection(.enabled) } }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
            }.padding(28)
        }
    }
    private func inventory(_ record: Record) -> String {
        guard record["file"] is NSNumber, record["byte"] is NSNumber else { return "Conteggio e dimensione non ancora disponibili." }
        return "\(record.number("file")) file · \(byteCount(record.number("byte")))"
    }
    private func bankState(_ state: String) -> String {
        ["non-eseguito": "Prova da eseguire", "vuota": "Cartella vuota", "contiene-file": "La cartella contiene dati",
         "permesso-desktop": "Accesso al Desktop da autorizzare", "aperta": "Cartella aperta", "chiusa": "Cartella chiusa",
         "completo": "Sequenza verificata", "incompleto": "Sequenza con riscontri mancanti", "in-corso": "Prova in corso",
         "fallito": "Prova non completata", "migrazione-incompleta": "Migrazione da recuperare"][state] ?? state
    }
}

struct BankPhaseCard: View {
    let phase: Record
    private var probes: [Record] { phase["prove"] as? [Record] ?? [] }
    private var title: String {
        ["prima": "Prima della protezione", "chiusa": "Compartimento chiuso", "riaperta": "Compartimento riaperto", "richiusa": "Compartimento richiuso"][phase.text("nome")] ?? phase.text("nome")
    }
    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(title).font(.headline)
                    Spacer()
                    Text(phase.flag("ok") ? "Verificata" : phase["conclusa"] == nil ? "In corso" : "Riscontri mancanti").font(.caption).foregroundStyle(phase.flag("ok") ? Color.green : .orange)
                }
                Text("Esito atteso: " + (phase.text("atteso") == "rifiuto" ? "accesso rifiutato" : "accesso consentito") + " · \(phase.number("file_visibili")) file visibili · \(byteCount(phase.number("byte_visibili")))").font(.caption)
                Text("Avvio: " + phase.text("iniziata") + " · Fine: " + phase.text("conclusa", fallback: "in attesa")).font(.caption).foregroundStyle(.secondary)
                ForEach(Array(probes.enumerated()), id: \.offset) { _, probe in
                    let informational = probe["obbligatoria"] as? Bool == false
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text(actorName(probe.text("attore"))).font(.callout.weight(.semibold)).frame(width: 105, alignment: .leading)
                            Text(outcome(probe)).font(.callout)
                            Spacer()
                            Text(informational ? "Informativa" : probe.flag("esito_atteso") ? "Atteso confermato" : "Atteso non confermato").font(.caption).foregroundStyle(informational ? Color.gray : probe.flag("esito_atteso") ? Color.green : Color.orange)
                        }
                        HStack(spacing: 16) {
                            Text("errno: " + probe.text("errno", fallback: "—") + " · codice uscita: " + probe.text("rc", fallback: "—"))
                            let matches = (probe["riscontri_kernel"] as? [Record])?.count ?? 0
                            Text("\(matches) riscontri kernel · " + (informational ? "sonda informativa" : probe.flag("copertura_verificata") ? (matches > 0 ? "riscontro kernel confermato" : "misura locale confermata") : "evidenza richiesta mancante"))
                        }.font(.caption).foregroundStyle(.secondary)
                        if let message = probe["messaggio"] as? String { Text(message).font(.caption).foregroundStyle(.orange) }
                        if let note = probe["nota"] as? String { Text(note).font(.caption).foregroundStyle(.secondary) }
                    }.padding(.vertical, 5)
                }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }
    private func actorName(_ actor: String) -> String { ["shell": "Shell", "mdls": "Spotlight", "codex": "Codex", "claude": "Claude Code"][actor] ?? actor }
    private func outcome(_ probe: Record) -> String {
        guard probe.flag("misurato"), let success = probe["riuscito"] as? Bool else { return "Non misurato" }
        return success ? "Accesso riuscito" : "Accesso fallito o rifiutato"
    }
}

struct SettingsView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PageHeading(title: "Autorizzazioni e controlli", subtitle: "Le password amministratore e le autorizzazioni privacy restano nei dialoghi di macOS.")
                RegistryUpdateSteps(model: model)
                GroupBox("Registro kernel") {
                    VStack(alignment: .leading, spacing: 12) {
                        Label(model.registry.flag("running") && model.registry.flag("healthy") ? "Registro attivo" : "Autorizzazione o verifica necessaria", systemImage: model.registry.flag("healthy") ? "checkmark.circle" : "exclamationmark.circle")
                        Text(model.registry.text("message", fallback: "Installa il servizio del registro e autorizza /Applications/Paratia.app."))
                        RegistryHealthDetails(model: model, record: model.registry)
                        DisclosureGroup("Prepara la copia per installare il registro") {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("Chiudi Paratia. Esegui tu questo singolo comando nel Terminale; quando termina senza errori, apri la copia indicata sotto dal Finder e premi Installa il registro. L'app quotidiana e la voce Accesso completo al disco restano /Applications/Paratia.app.")
                                Text(NativeInstall.preparationCommand).font(.caption.monospaced()).textSelection(.enabled)
                                Text(NativeInstall.bootstrapBundlePath).font(.caption.monospaced()).textSelection(.enabled)
                                Text("Dopo una nuova build, prepara di nuovo la copia in ParatiaBootstrap.noindex. Il comando verifica la nuova firma, poi elimina il vecchio bootstrap e le cartelle .prepara. Dopo l'installazione chiudi il bootstrap e riapri l'app normale.").font(.caption).foregroundStyle(.secondary)
                            }.padding(.top, 8)
                        }
                        HStack {
                            Button("Installa il registro…") { model.installRegistry() }.buttonStyle(.borderedProminent)
                            Button("Apri Accesso completo al disco") {
                                if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") { NSWorkspace.shared.open(url) }
                            }
                        }.disabled(model.busy != nil || model.fixtures)
                        Text(model.registry.text("fda_message", fallback: "Aggiungi e abilita /Applications/Paratia.app. Con firma ad hoc, dopo ogni nuova build rimuovi e aggiungi di nuovo l'app. Non autorizzare Python."))
                            .font(.callout).foregroundStyle(.secondary)
                        if model.registry["needs_fda"] is NSNull || model.registry["needs_fda"] == nil { Text("Accesso completo al disco: non ancora verificato.").font(.caption).foregroundStyle(.orange) }
                        if model.registry["needs_update"] is NSNull || model.registry["needs_update"] == nil {
                            Text("Versione del servizio: non ancora verificata.").font(.caption).foregroundStyle(.secondary)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
                GroupBox("Chiusura all'avvio di una sessione agente") {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(model.hooks.text("message", fallback: "Il gate deve essere collegato agli harness che usi. La fiducia va confermata anche dentro Codex."))
                        HStack {
                            Button("Rivedi e collega gli hook…") { model.installHooks() }
                            Button("Ripristina un backup…") { model.restoreHooks() }
                        }.disabled(model.busy != nil || model.fixtures)
                        DisclosureGroup("Dettagli della configurazione") { Text(prettyJSON(model.hooks)).font(.caption.monospaced()).textSelection(.enabled) }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
                GroupBox("Limiti del registro") {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach((model.registry["limits"] as? [String]) ?? ["Le aperture per lettura non provano la lettura dei byte.", "I tentativi falliti non sono tutti osservabili dal kernel.", "Una catena di hash locale non prova da sola che la coda non sia stata troncata."], id: \.self) { Text("• " + $0) }
                    }.font(.callout).frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
                GroupBox("Integrità delle catene") {
                    VStack(alignment: .leading, spacing: 10) {
                        Button("Verifica il registro") { model.verifyRegistry() }.disabled(model.busy != nil || model.fixtures)
                        Text("La verifica controlla gli eventi presenti. Non prova da sola la copertura continua o l'assenza di una coda eliminata.").font(.caption).foregroundStyle(.secondary)
                        if !model.integrity.isEmpty {
                            Label(model.integrity.flag("ok") ? "Eventi presenti integri" : "Verifica non superata", systemImage: model.integrity.flag("ok") ? "checkmark.circle" : "exclamationmark.triangle")
                                .foregroundStyle(model.integrity.flag("ok") ? Color.green : .orange)
                            ForEach(Array(((model.integrity["catene"] as? [Record]) ?? []).enumerated()), id: \.offset) { _, chain in
                                VStack(alignment: .leading, spacing: 5) {
                                    Text((chain.text("source") == "eslogger" ? "Registro kernel" : "Operazioni di Paratia") + ": " + (chain.flag("ok") ? "integra" : "errore") + " · \(chain.number("voci")) eventi").font(.callout.weight(.medium))
                                    if let message = chain["errore"] as? String { Text(message).font(.caption).foregroundStyle(.orange) }
                                }
                            }
                            DisclosureGroup("Dati della verifica") { Text(prettyJSON(model.integrity)).font(.caption.monospaced()).textSelection(.enabled) }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
            }.padding(28)
        }
    }
}
