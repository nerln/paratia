import SwiftUI
import AppKit

struct ContentView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        NavigationSplitView {
            List(Section.allCases, selection: $model.section) { section in
                Label(section.title, systemImage: section.icon)
                    .foregroundStyle(model.section == section ? Color.white : Color.primary).tag(section)
            }
            .navigationSplitViewColumnWidth(min: 175, ideal: 190, max: 240)
            .safeAreaInset(edge: .bottom) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("PARATIA").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    Text(model.fixtures ? tr("Anteprima · dati sintetici") : tr("Cartelle cifrate. Decisioni umane."))
                        .font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(16)
            }
        } detail: {
            VStack(spacing: 0) {
                if model.fixtures {
                    Banner(text: tr("Anteprima con dati sintetici. Nessuna operazione reale eseguita."), icon: "photo", color: .blue)
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
                    HStack { ProgressView().controlSize(.small); Text(busy); Spacer(); Text(tr("Lascia terminare l'operazione.")).foregroundStyle(.secondary) }
                        .font(.callout).padding(12).background(.regularMaterial)
                }
            }.navigationTitle((model.section ?? .folders).title)
        }
        .toolbar {
            ToolbarItem { Button { model.refreshAction() } label: { Label(tr("Aggiorna"), systemImage: "arrow.clockwise") }.disabled(model.busy != nil || model.fixtures) }
        }
        .sheet(item: $model.keyRequest) { request in KeySheet(model: model, request: request) }
        .sheet(item: $model.detail) { event in EventDetail(event: event) }
        .alert(tr("Operazione non riuscita"), isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button(tr("Ho capito")) { model.error = nil }
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
                PageHeading(title: tr("Le tue cartelle protette"), subtitle: tr("Da chiuse, i file restano nell'immagine cifrata anche quando il disco è sbloccato: nessun programma, nessun agente li legge."))
                HStack {
                    Button { model.protectFolder() } label: { Label(tr("Proteggi una cartella"), systemImage: "plus") }.buttonStyle(.borderedProminent)
                    Button { model.closeAll() } label: { Label(tr("Chiudi tutte"), systemImage: "lock.fill") }.disabled(!model.folders.contains(where: { $0.state == "aperta" || $0.isIncomplete }))
                    Spacer()
                    Stepper(tr("Chiusura dopo %@ min", "\(model.minutes)"), value: $model.minutes, in: 1...1440).frame(width: 235)
                }.disabled(model.busy != nil || model.fixtures)
                if model.folders.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "lock.rectangle.stack").font(.system(size: 44)).foregroundStyle(.secondary)
                        Text(tr("Nessuna cartella protetta")).font(.title2.weight(.medium))
                        Text(tr("Scegli una cartella: resta dov'è, e il suo contenuto viene cifrato sullo stesso disco. La chiave la scegli tu.")).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity).padding(50)
                }
                ForEach(model.folders) { folder in
                    FolderCard(model: model, folder: folder)
                }
                GroupBox {
                    VStack(alignment: .leading, spacing: 7) {
                        Label(tr("Prima di migrare"), systemImage: "info.circle").font(.headline)
                        Text(tr("Chiudi i documenti e le app che possono modificare la fonte. Paratia verifica la copia, chiude e riapre il compartimento, poi rimuove l'originale."))
                        Text(tr("Backup, snapshot e copie già sincronizzate possono contenere versioni precedenti.")).foregroundStyle(.secondary)
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
                    Text(folder.isIncomplete ? tr("Da recuperare") : folder.state == "aperta" ? tr("Aperta") : tr("Chiusa"))
                        .font(.callout.weight(.medium)).foregroundStyle(color)
                }
                HStack {
                    Label(conteggioFile(folder.data.number("file"), byteCount(folder.data.number("byte"))), systemImage: "doc.on.doc")
                    Spacer()
                    if folder.isIncomplete {
                        // Recovery reads a verified image; an unverified attempt is simply cancelled.
                        if folder.data.flag("verificato") { Button(tr("Recupera la fonte")) { model.askKey(folder, recovery: true) } }
                        Button(tr("Annulla migrazione")) { model.cancelMigration(folder) }
                        if !folder.data.text("montaggio_temporaneo", fallback: "").isEmpty {
                            Button(tr("Chiudi montaggi")) { model.close(folder) }
                            Button(tr("Forza chiusura…"), role: .destructive) { model.forceClose(folder) }
                        }
                    } else if folder.state == "aperta" {
                        Button(tr("Mostra nel Finder")) { NSWorkspace.shared.open(URL(fileURLWithPath: folder.openPath)) }
                        Button(tr("Chiudi")) { model.close(folder) }.buttonStyle(.borderedProminent)
                        Button(tr("Forza chiusura…"), role: .destructive) { model.forceClose(folder) }
                    } else {
                        Button(tr("Togli la protezione…")) { model.removeProtection(folder) }
                        Button(tr("Apri…")) { model.askKey(folder) }.buttonStyle(.borderedProminent)
                    }
                }.font(.callout).disabled(model.busy != nil || model.fixtures)
                if folder.isIncomplete {
                    Text(folder.data.flag("verificato") ? tr("La protezione non è completa. Le copie residue vengono conservate per il recupero.") : tr("La protezione non è riuscita e la tua cartella non è stata toccata: premi Annulla migrazione e potrai usarla come prima.")).font(.callout).foregroundStyle(.red)
                    if let reason = folder.data["errore"] as? String, !reason.isEmpty {
                        Text(tr("Cosa è andato storto: %@", reason)).font(.callout).textSelection(.enabled)
                    }
                    ForEach(["plaintext_residuo", "recupero_temporaneo"], id: \.self) { field in
                        if let path = folder.data[field] as? String {
                            Text(path).font(.caption).textSelection(.enabled)
                        }
                    }
                } else if folder.state != "aperta" {
                    Text(tr("Chiusa: nel Finder la vedi vuota e in sola lettura, e nessun programma legge i file. Per lavorarci aprila con la chiave; quello che aggiungi da aperta viene cifrato alla chiusura.")).font(.caption).foregroundStyle(.secondary)
                } else if folder.state == "aperta" {
                    if let capacity = folder.data["capacita"] as? NSNumber, capacity.int64Value > 0 {
                        Text(tr("Spazio dentro: fino a %@, lasciando sempre 1 GB libero sul disco. Si adatta da solo a ogni apertura.", ByteCountFormatter.string(fromByteCount: capacity.int64Value, countStyle: .file)))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if folder.openPath != folder.source {
                        Text(tr("Questo disco non permette di aprirla al suo posto: i file sono in %@ (Mostra nel Finder). La cartella sul disco resta vuota e in sola lettura.", folder.openPath))
                            .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                    Text(tr("Aperta: tu e qualsiasi programma, agenti compresi, potete leggere i file. Si chiude dopo %@ minuti; se un'app la sta usando, Paratia riprova senza forzare.", "\(folder.data.number("minutes"))"))
                        .font(.caption).foregroundStyle(.secondary)
                }
                Text(tr("Registro: ") + model.watchStatus(folder.data)).font(.caption).foregroundStyle(.secondary)
                Text(tr("Immagine: %@", "\(folder.data.text("bundle"))")).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
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
            Text(request.confirm ? tr("Usa una chiave propria del compartimento, diversa da quella del disco. Conservane una copia in un luogo che controlli.") : tr("Inserisci la chiave di questo compartimento."))
            SecureField(tr("Chiave del compartimento"), text: $key).textFieldStyle(.roundedBorder)
            if request.confirm { SecureField(tr("Ripeti la chiave"), text: $confirmation).textFieldStyle(.roundedBorder) }
            Text(tr("Almeno 12 byte. La chiave non viene salvata nel portachiavi, nei file o nel registro.")).font(.caption).foregroundStyle(.secondary)
            if request.confirm && !confirmation.isEmpty && key != confirmation { Text(tr("Le chiavi non coincidono.")).font(.callout).foregroundStyle(.red) }
            HStack {
                Spacer()
                Button(tr("Annulla")) { key = ""; confirmation = ""; dismiss() }.keyboardShortcut(.cancelAction)
                Button(tr("Continua")) {
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
            PageHeading(title: tr("Chi ha aperto cosa"), subtitle: tr("Metadati delle operazioni dell'app e degli eventi kernel osservati. I contenuti dei file restano fuori dal registro."))
            GroupBox(tr("Cartelle sorvegliate")) {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text(tr("Puoi sorvegliare anche una cartella senza cifrarla.")).font(.callout).foregroundStyle(.secondary)
                        Spacer()
                        Button(tr("Sorveglia una cartella…")) { model.watchFolder() }.buttonStyle(.borderedProminent)
                    }
                    if model.watchedFolders.isEmpty { Text(tr("Nessuna cartella sorvegliata configurata.")).font(.caption).foregroundStyle(.secondary) }
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
                                        Button(tr("Apri registro")) { model.showWatchEvents(folder) }
                                        Button(tr("Rimuovi")) { model.removeWatch(folder) }
                                    }
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }.frame(maxHeight: 150)
                    }
                }.padding(8).disabled(model.busy != nil || model.fixtures)
            }
            HStack {
                Picker(tr("Cartella"), selection: $model.selectedFolder) {
                    Text(tr("Tutte le cartelle")).tag("")
                    ForEach(model.registryFolders) { Text($0.name).tag($0.id) }
                }.frame(width: 220)
                TextField(tr("File o percorso"), text: $model.fileFilter)
                TextField(tr("Processo o PID"), text: $model.processFilter)
                Picker(tr("Agente"), selection: $model.agentFilter) {
                    Text(tr("Tutti")).tag(""); Text(tr("Agente riconosciuto")).tag("true")
                    Text(tr("Non agente")).tag("false"); Text(tr("Sconosciuto")).tag("unknown")
                    Text("Codex").tag("Codex"); Text("Claude Code").tag("Claude Code")
                    Text("ChatGPT").tag("ChatGPT"); Text("agentbridge").tag("agentbridge")
                }.frame(width: 175)
            }.textFieldStyle(.roundedBorder)
            HStack {
                Toggle(tr("Intervallo"), isOn: $model.useDates)
                if model.useDates {
                    DatePicker(tr("Da"), selection: $model.since); DatePicker(tr("A"), selection: $model.until)
                }
                Spacer()
                Button(tr("Cerca")) { model.loadEvents() }.buttonStyle(.borderedProminent)
                Button(tr("Esporta CSV…")) { model.export("registro.export_csv", title: tr("Esporta il registro filtrato"), extension: "csv", parameters: ["filters": model.filters]) }
            }.disabled(model.busy != nil || model.fixtures)
            if !model.registry.flag("running") || !model.registry.flag("healthy") {
                Banner(text: model.registry.text("message", fallback: tr("Il registro kernel non è ancora verificato. Completa le autorizzazioni nelle Impostazioni.")), icon: "exclamationmark.circle", color: .orange)
            }
            if model.registry.flag("needs_update") {
                HStack {
                    Label(model.registry.text("update_message", fallback: tr("Aggiorna il registro e verifica la build installata.")), systemImage: "arrow.triangle.2.circlepath").font(.callout).foregroundStyle(.secondary)
                    Spacer()
                    Button(tr("Come aggiornarlo…")) { model.section = .settings }
                }
            }
            RegistryHealthDetails(model: model, record: model.registry)
            Table(model.events, selection: $selection) {
                TableColumn(tr("Ora"), value: \.date).width(min: 145, ideal: 170)
                TableColumn(tr("Evento"), value: \.event).width(min: 100, ideal: 120)
                TableColumn(tr("Percorso"), value: \.path)
                TableColumn(tr("Processo"), value: \.process)
                TableColumn(tr("Agente"), value: \.agent).width(min: 85, ideal: 110)
            }.contextMenu { Button(tr("Apri dettaglio")) { openDetail() }.disabled(selection == nil) }
            HStack {
                Text(plurale(model.eventTotal, uno: "%@ evento", molti: "%@ eventi") + (model.eventsTruncated ? tr(" · visualizzazione limitata: restringi i filtri o esporta il CSV completo") : "")).font(.caption).foregroundStyle(.secondary)
                Label(model.eventsKernelActive == true ? tr("Raccolta kernel attiva") : model.eventsKernelActive == false ? tr("Raccolta kernel inattiva") : tr("Raccolta kernel da verificare"), systemImage: model.eventsKernelActive == true ? "checkmark.circle" : "exclamationmark.circle")
                    .font(.caption).foregroundStyle(model.eventsKernelActive == true ? Color.green : .orange)
                Spacer()
                Button(tr("Apri dettaglio")) { openDetail() }.disabled(selection == nil)
            }
            Text(model.eventsKernelMessage).font(.caption).foregroundStyle(.secondary)
            if !model.eventsKernelCollection.isEmpty {
                RegistryHealthDetails(model: model, record: model.eventsKernelCollection)
            }
            Text(tr("Un'apertura per lettura non prova una lettura dei byte. Gli eventi mancanti e la discendenza sconosciuta vengono indicati, non ricostruiti."))
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
            ForEach(Array(model.notices(record).enumerated()), id: \.offset) { _, notice in
                Label(notice.text("message"), systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct RegistryUpdateSteps: View {
    @ObservedObject var model: AppModel
    var body: some View {
        if model.registry.flag("needs_update") {
            GroupBox(tr("Aggiornamento facoltativo del registro")) {
                VStack(alignment: .leading, spacing: 10) {
                    Text(model.registry.text("update_message", fallback: tr("Aggiorna il registro e verifica la build installata."))).font(.callout)
                    Text(tr("Non è urgente: il registro funziona anche così. Quando vuoi, segui questi passi nell'ordine indicato.")).font(.callout)
                    ForEach(Array(model.registryUpdateSteps.enumerated()), id: \.offset) { index, step in
                        Text("\(index + 1). \(step)").font(.callout).textSelection(.enabled)
                    }
                    Text(tr("Il comando per preparare il bootstrap è riportato qui sotto in Prepara la copia per installare il registro."))
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
            Text(event.path).font(.callout).textSelection(.enabled)
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
            HStack { Spacer(); Button(tr("Chiudi")) { dismiss() }.keyboardShortcut(.defaultAction) }
        }.padding(28).frame(width: 720, height: 560)
    }
    private func detailValue(_ value: Any?) -> String {
        guard let value = value, !(value is NSNull) else { return tr("Non disponibile") }
        if value is [Any] || value is Record { return prettyJSON(value) }
        return String(describing: value)
    }
    private func detailLabel(_ key: String) -> String {
        ["quando": tr("Data e ora"), "evento": tr("Operazione"), "percorso": tr("Percorso"), "processo": tr("Processo"),
         "pid": tr("PID"), "ppid": tr("PID padre"), "utente": tr("Utente"), "agente": tr("Discendenza agente"),
         "nome_agente": tr("Agente riconosciuto"), "source": tr("Fonte"), "esito": tr("Esito"), "errore": tr("Errore"),
         "cartella": tr("Compartimento"), "chain_ok": tr("Catena verificata"), "catena_ok": tr("Catena verificata"),
         "precedente": tr("Hash precedente"), "hash": tr("Hash"), "fread": tr("Aperto per lettura"), "fwrite": tr("Aperto per scrittura")][key] ?? key
    }
}

struct LabelsView: View {
    @ObservedObject var model: AppModel
    @State private var zoneTarget: FileItem?
    @State private var zoneName = tr("lavoro")
    @State private var selection: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            PageHeading(title: tr("Decidi cosa proteggere"), subtitle: tr("Un'etichetta registra una decisione. La cifratura inizia quando proteggi la cartella."))
            HStack {
                Button { if let p = model.browseParent { model.browse(p) } } label: { Image(systemName: "arrow.up") }.disabled(model.browseParent == nil)
                TextField(tr("Percorso della cartella"), text: $model.browsePath).onSubmit { model.browse() }
                Button(tr("Scegli…")) { if let p = model.chooseDirectory(title: tr("Sfoglia una cartella")) { model.browse(p) } }
                Toggle(tr("Nascosti"), isOn: $model.showHidden).onChange(of: model.showHidden) { _ in model.browse() }
                Button(tr("Vai")) { model.browse() }
            }.textFieldStyle(.roundedBorder).disabled(model.busy != nil || model.fixtures)
            Table(model.files, selection: $selection) {
                TableColumn(tr("Nome")) { file in Label(file.name, systemImage: file.isDirectory ? "folder" : "doc") }
                TableColumn(tr("Etichetta")) { file in
                    let etichetta = etichettaTesto(file.data.text("etichetta", fallback: tr("Da esaminare")))
                    Text(file.data.flag("ereditata") ? tr("%@ · ereditata", etichetta) : etichetta)
                        .foregroundStyle(file.data.text("etichetta") == "riservato" ? Color.red : .secondary)
                }
                TableColumn(tr("Dimensione")) { file in Text(file.isDirectory ? "—" : byteCount(file.data.number("peso"))) }
            }
            if let file = model.files.first(where: { $0.id == selection }) {
                HStack {
                    if file.isDirectory { Button(tr("Entra")) { model.browse(file.id) } }
                    Button(tr("Riservato")) { model.mark(file, label: "riservato") }
                    Button(tr("Zona…")) { zoneTarget = file }
                    Button(tr("Pubblico")) { model.mark(file, label: "pubblico") }
                    Button(tr("Togli etichetta")) { model.removeLabel(file) }.disabled(file.data.flag("ereditata"))
                    Spacer()
                    Button(tr("Aggiorna elenco")) { model.browse() }
                }.disabled(model.busy != nil || model.fixtures)
                if file.data.flag("ereditata") { Text(tr("Etichetta ereditata da %@. Puoi assegnarne una specifica a questo elemento.", "\(file.data.text("da"))")).font(.caption).foregroundStyle(.secondary) }
            }
            DisclosureGroup(tr("Il piano delle etichette")) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(tr("%@ etichette · %@ nel piano", "\(model.labels.count)", "\(byteCount(model.labelPlan.number("byte_totali")))"))
                    ForEach(Array(((model.labelPlan["mosse"] as? [Record]) ?? []).enumerated()), id: \.offset) { _, item in
                        Text(item.text("percorso") + " · " + etichettaTesto(item.text("etichetta"))).font(.caption).textSelection(.enabled)
                    }
                    ForEach(Array(((model.labelPlan["problemi"] as? [Record]) ?? []).enumerated()), id: \.offset) { _, problem in
                        Text(problem.text("percorso") + ": " + (problem.text("perche") == "the path is gone" ? tr("Il percorso non esiste più.") : problem.text("perche"))).font(.caption).foregroundStyle(.orange)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            Text(tr("Il browser elenca nomi, dimensioni ed etichette. Non mostra anteprime o contenuti dei file.")).font(.caption).foregroundStyle(.secondary)
        }.padding(28).onAppear { if model.files.isEmpty { model.browse() } }
        .sheet(item: $zoneTarget) { file in
            VStack(alignment: .leading, spacing: 16) {
                Text(tr("Assegna a una zona")).font(.title2)
                TextField(tr("Nome della zona"), text: $zoneName).textFieldStyle(.roundedBorder)
                Text(tr("La zona rimane leggibile dalla sessione che ci lavora. L'etichetta non crea la zona.")).font(.callout).foregroundStyle(.secondary)
                HStack { Spacer(); Button(tr("Annulla")) { zoneTarget = nil }; Button(tr("Segna")) { model.mark(file, label: "zona:" + zoneName.trimmingCharacters(in: .whitespaces)); zoneTarget = nil }.disabled(zoneName.isEmpty) }
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
                PageHeading(title: tr("Prima, chiusa, aperta, richiusa"), subtitle: tr("Il banco usa la cartella di prova sul Desktop e conserva gli esiti reali di ogni fase."))
                Banner(text: tr("A cosa serve: è una prova facoltativa, per vedere con i tuoi occhi che la protezione funziona. Paratia protegge una cartella di prova e controlla quattro momenti: prima della protezione i file si leggono; con la cartella chiusa nessun programma li legge; riaperta tornano leggibili; richiusa spariscono di nuovo. Per ogni momento mostra anche cosa ha visto il registro. Per usare Paratia non serve."), icon: "questionmark.circle", color: .accentColor)
                Banner(text: tr("I tuoi file vengono esaminati solo attraverso metadati. I file sintetici vengono creati soltanto se la cartella di prova è vuota."), icon: "doc.text", color: .blue)
                Banner(text: tr("Non serve nessuna chiave: la prova ne crea una usa e getta che resta in memoria, e alla fine rimette folder-test com'era. Ci vuole circa un minuto."), icon: "key", color: .green)
                Toggle(tr("Autorizzo le CLI reali, incluse eventuali richieste del portachiavi"), isOn: $model.realAgents)
                Text(tr("Codex e Claude Code avviano processi figli per la prova, senza chiamare un modello. Le CLI possono chiedere autenticazione o accesso al portachiavi: decidi nei dialoghi di macOS. Un rifiuto degli hook resta un esito reale.")).font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button(tr("Controlla le condizioni")) { model.prepareBank() }
                    Button(tr("Esegui la prova")) { model.runBank() }.buttonStyle(.borderedProminent)
                    Spacer()
                    Button(tr("Esporta JSON…")) { model.export("banco.export_json", title: tr("Esporta lo storico del banco"), extension: "json") }
                    Button(tr("Esporta CSV…")) { model.export("banco.export_csv", title: tr("Esporta lo storico del banco"), extension: "csv") }
                }.disabled(model.busy != nil || model.fixtures)
                if !model.bankPreview.isEmpty {
                    GroupBox(tr("Condizioni del banco")) {
                        VStack(alignment: .leading, spacing: 10) {
                            Label(bankState(model.bankPreview.text("stato")), systemImage: model.bankPreview.flag("richiede_autorizzazione") ? "exclamationmark.circle" : "info.circle").font(.headline)
                            Text(model.bankPreview.text("messaggio", fallback: tr("Controlla le condizioni prima di avviare il banco.")))
                            Text(model.bankPreview.text("percorso")).font(.callout).textSelection(.enabled)
                            Text(inventory(model.bankPreview)).font(.caption).foregroundStyle(.secondary)
                            if model.bankPreview.flag("richiede_autorizzazione") { Text(tr("Autorizzazioni necessarie prima della prova.")).font(.caption).foregroundStyle(.orange) }
                            DisclosureGroup(tr("Dati della verifica")) { Text(prettyJSON(model.bankPreview)).font(.caption.monospaced()).textSelection(.enabled) }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                    }
                }
                GroupBox(tr("Ultima prova")) {
                    VStack(alignment: .leading, spacing: 12) {
                        if model.bank.isEmpty || model.bank.flag("pending") || history.isEmpty {
                            Label(tr("Nessuna prova reale confermata"), systemImage: "clock").font(.headline)
                            Text(model.bank.text("messaggio", fallback: model.bank.text("message", fallback: tr("Completa le autorizzazioni del registro e controlla le condizioni prima di avviare il banco."))))
                        } else {
                            HStack {
                                Label(bankState(model.bank.text("stato")), systemImage: model.bank.text("stato") == "completo" ? "checkmark.circle" : "exclamationmark.circle").font(.headline)
                                Spacer()
                                Text(plurale(history.count, uno: "%@ prova nello storico", molti: "%@ prove nello storico")).font(.caption).foregroundStyle(.secondary)
                            }
                            Text(model.bank.text("messaggio", fallback: tr("Consulta gli esiti delle singole fasi.")))
                            Text(model.bank.text("percorso")).font(.callout).textSelection(.enabled)
                            Text(inventory(model.bank)).font(.callout)
                            Text(tr("Avviata: ") + model.bank.text("iniziata") + tr(" · Conclusa: ") + model.bank.text("conclusa", fallback: tr("in attesa"))).font(.caption).foregroundStyle(.secondary)
                            if let finalState = model.bank["stato_finale"] as? String {
                                Text(tr("Chiusura finale: ") + bankState(finalState)).font(.callout)
                            }
                            if let migration = model.bank["verifica_migrazione"] as? Record {
                                Text(tr("Migrazione: %@ file, %@ prima → %@ file, %@ dopo. ", "\(migration.number("file_prima"))", "\(byteCount(migration.number("byte_prima")))", "\(migration.number("file_dopo"))", "\(byteCount(migration.number("byte_dopo")))") + (migration.flag("verificato") ? tr("Copia verificata.") : tr("Verifica mancante.")))
                                    .font(.callout).foregroundStyle(migration.flag("verificato") ? Color.primary : .orange)
                            }
                            if let warning = model.bank["avviso_registro"] as? String { Banner(text: warning, icon: "exclamationmark.triangle", color: .orange) }
                            ForEach(Array(phases.enumerated()), id: \.offset) { _, phase in BankPhaseCard(phase: phase) }
                            if history.count > 1 {
                                DisclosureGroup(tr("Prove precedenti (%@)", "\(history.count - 1)")) {
                                    VStack(alignment: .leading, spacing: 12) {
                                        ForEach(Array(history.dropLast().reversed().enumerated()), id: \.offset) { _, previous in
                                            VStack(alignment: .leading, spacing: 5) {
                                                Text(previous.text("iniziata") + " · " + bankState(previous.text("stato"))).font(.headline)
                                                Text(previous.text("messaggio", fallback: tr("Esiti conservati nello storico.")))
                                                Text(previous.text("percorso")).font(.caption).textSelection(.enabled)
                                                ForEach(Array(((previous["fasi"] as? [Record]) ?? []).enumerated()), id: \.offset) { _, phase in BankPhaseCard(phase: phase) }
                                            }.padding(.vertical, 6)
                                        }
                                    }
                                }
                            }
                        }
                        if !model.bank.isEmpty { DisclosureGroup(tr("Dettagli dello storico")) { Text(prettyJSON(model.bank)).font(.caption.monospaced()).textSelection(.enabled) } }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
            }.padding(28)
        }
    }
    private func inventory(_ record: Record) -> String {
        guard record["file"] is NSNumber, record["byte"] is NSNumber else { return tr("Conteggio e dimensione non ancora disponibili.") }
        return conteggioFile(record.number("file"), byteCount(record.number("byte")))
    }
    private func bankState(_ state: String) -> String {
        ["non-eseguito": tr("Prova da eseguire"), "vuota": tr("Cartella vuota"), "contiene-file": tr("La cartella contiene dati"), "sintetici": tr("File sintetici della prova"),
         "permesso-desktop": tr("Accesso al Desktop da autorizzare"), "aperta": tr("Cartella aperta"), "chiusa": tr("Cartella chiusa"),
         "completo": tr("Sequenza verificata"), "incompleto": tr("Sequenza con riscontri mancanti"), "in-corso": tr("Prova in corso"),
         "fallito": tr("Prova non completata"), "migrazione-incompleta": tr("Migrazione da recuperare"),
         "sintetica": tr("Anteprima sintetica")][state] ?? state
    }
}

struct BankPhaseCard: View {
    let phase: Record
    private var probes: [Record] { phase["prove"] as? [Record] ?? [] }
    private var title: String {
        ["prima": tr("Prima della protezione"), "chiusa": tr("Compartimento chiuso"), "riaperta": tr("Compartimento riaperto"), "richiusa": tr("Compartimento richiuso")][phase.text("nome")] ?? phase.text("nome")
    }
    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(title).font(.headline)
                    Spacer()
                    Text(phase.flag("ok") ? tr("Verificata") : phase["conclusa"] == nil ? tr("In corso") : tr("Riscontri mancanti")).font(.caption).foregroundStyle(phase.flag("ok") ? Color.green : .orange)
                }
                Text(tr("Esito atteso: ") + (phase.text("atteso") == "rifiuto" ? tr("accesso rifiutato") : tr("accesso consentito")) + tr(" · %@ file visibili · %@", "\(phase.number("file_visibili"))", "\(byteCount(phase.number("byte_visibili")))")).font(.caption)
                Text(tr("Avvio: %@ · Fine: %@", phase.text("iniziata"), phase.text("conclusa", fallback: tr("in attesa")))).font(.caption).foregroundStyle(.secondary)
                ForEach(Array(probes.enumerated()), id: \.offset) { _, probe in
                    let informational = probe["obbligatoria"] as? Bool == false
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text(actorName(probe.text("attore"))).font(.callout.weight(.semibold)).frame(width: 105, alignment: .leading)
                            Text(outcome(probe)).font(.callout)
                            Spacer()
                            Text(informational ? tr("Informativa") : probe.flag("esito_atteso") ? tr("Atteso confermato") : tr("Atteso non confermato")).font(.caption).foregroundStyle(informational ? Color.gray : probe.flag("esito_atteso") ? Color.green : Color.orange)
                        }
                        HStack(spacing: 16) {
                            Text(tr("errno: %@ · codice uscita: %@", probe.text("errno", fallback: "—"), probe.text("rc", fallback: "—")))
                            let matches = (probe["riscontri_kernel"] as? [Record])?.count ?? 0
                            let esito = informational ? tr("sonda informativa") : probe.flag("copertura_verificata")
                                ? (matches > 0 ? tr("riscontro kernel confermato") : tr("misura locale confermata")) : tr("evidenza richiesta mancante")
                            Text(tr("%@ · %@", plurale(matches, uno: "%@ riscontro kernel", molti: "%@ riscontri kernel"), esito))
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
        guard probe.flag("misurato"), let success = probe["riuscito"] as? Bool else { return tr("Non misurato") }
        return success ? tr("Accesso riuscito") : tr("Accesso fallito o rifiutato")
    }
}

struct SettingsView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PageHeading(title: tr("Autorizzazioni e controlli"), subtitle: tr("Le password amministratore e le autorizzazioni privacy restano nei dialoghi di macOS."))
                GroupBox(tr("Lingua")) {
                    VStack(alignment: .leading, spacing: 10) {
                        Picker(selection: Binding(get: { model.language }, set: { model.setLanguage($0) })) {
                            Text(tr("Sistema")).tag("sistema")
                            Text(tr("Italiano")).tag("it")
                            Text("English").tag("en")
                            Text("Español").tag("es")
                        } label: { EmptyView() }.labelsHidden().fixedSize().frame(maxWidth: .infinity, alignment: .leading)
                        Text(tr("Applicata subito alla finestra. La voce del menu cambia al riavvio.")).font(.caption).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
                RegistryUpdateSteps(model: model)
                GroupBox(tr("Registro kernel")) {
                    VStack(alignment: .leading, spacing: 12) {
                        Label(model.registry.flag("running") && model.registry.flag("healthy") ? tr("Registro attivo") : tr("Autorizzazione o verifica necessaria"), systemImage: model.registry.flag("healthy") ? "checkmark.circle" : "exclamationmark.circle")
                            .foregroundStyle(model.registry.flag("healthy") ? Color.green : .orange)
                        Text(model.registry.text("message", fallback: tr("Installa il servizio del registro e autorizza /Applications/Paratia.app.")))
                        RegistryHealthDetails(model: model, record: model.registry)
                        DisclosureGroup(tr("Prepara la copia per installare il registro")) {
                            VStack(alignment: .leading, spacing: 10) {
                                Text(tr("Chiudi Paratia. Esegui tu questo singolo comando nel Terminale; quando termina senza errori, apri la copia indicata sotto dal Finder e premi Installa il registro. L'app quotidiana e la voce Accesso completo al disco restano /Applications/Paratia.app."))
                                Text(NativeInstall.preparationCommand).font(.caption.monospaced()).textSelection(.enabled)
                                Text(NativeInstall.bootstrapBundlePath).font(.caption).textSelection(.enabled)
                                Text(tr("Dopo una nuova build, prepara di nuovo la copia in ParatiaBootstrap.noindex. Il comando verifica la nuova firma, poi elimina il vecchio bootstrap e le cartelle .prepara. Dopo l'installazione chiudi il bootstrap e riapri l'app normale.")).font(.caption).foregroundStyle(.secondary)
                            }.padding(.top, 8)
                        }
                        HStack {
                            Button(tr("Installa il registro…")) { model.installRegistry() }.buttonStyle(.borderedProminent)
                            Button(tr("Apri Accesso completo al disco")) {
                                if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") { NSWorkspace.shared.open(url) }
                            }
                        }.disabled(model.busy != nil || model.fixtures)
                        Text(model.registry.text("fda_message", fallback: tr("Aggiungi e abilita /Applications/Paratia.app in Accesso completo al disco. Dopo ogni nuova build controlla che il permesso sia ancora valido.")))
                            .font(.callout).foregroundStyle(.secondary)
                        if model.registry["needs_fda"] is NSNull || model.registry["needs_fda"] == nil { Text(tr("Accesso completo al disco: non ancora verificato.")).font(.caption).foregroundStyle(.orange) }
                        if model.registry["needs_update"] is NSNull || model.registry["needs_update"] == nil {
                            Text(tr("Versione del servizio: non ancora verificata.")).font(.caption).foregroundStyle(.secondary)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
                GroupBox(tr("Chiusura all'avvio di una sessione agente")) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(model.hooks.text("message", fallback: tr("Il gate deve essere collegato agli harness che usi. La fiducia va confermata anche dentro Codex.")))
                        HStack {
                            Button(tr("Rivedi e collega gli hook…")) { model.installHooks() }
                            Button(tr("Ripristina un backup…")) { model.restoreHooks() }
                        }.disabled(model.busy != nil || model.fixtures)
                        DisclosureGroup(tr("Dettagli della configurazione")) { Text(prettyJSON(model.hooks)).font(.caption.monospaced()).textSelection(.enabled) }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
                GroupBox(tr("Limiti del registro")) {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach((model.registry["limits"] as? [String]) ?? [tr("Le aperture per lettura non provano la lettura dei byte."), tr("I tentativi falliti non sono tutti osservabili dal kernel."), tr("Una catena di hash locale non prova da sola che la coda non sia stata troncata.")], id: \.self) { Text("• " + $0) }
                    }.font(.callout).frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
                GroupBox(tr("Integrità delle catene")) {
                    VStack(alignment: .leading, spacing: 10) {
                        Button(tr("Verifica il registro")) { model.verifyRegistry() }.disabled(model.busy != nil || model.fixtures)
                        Text(tr("La verifica controlla gli eventi presenti. Non prova da sola la copertura continua o l'assenza di una coda eliminata.")).font(.caption).foregroundStyle(.secondary)
                        if !model.integrity.isEmpty {
                            Label(model.integrity.flag("ok") ? tr("Eventi presenti integri") : tr("Verifica non superata"), systemImage: model.integrity.flag("ok") ? "checkmark.circle" : "exclamationmark.triangle")
                                .foregroundStyle(model.integrity.flag("ok") ? Color.green : .orange)
                            ForEach(Array(((model.integrity["catene"] as? [Record]) ?? []).enumerated()), id: \.offset) { _, chain in
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(tr("%@: %@ · %@", chain.text("source") == "eslogger" ? tr("Registro kernel") : tr("Operazioni di Paratia"), chain.flag("ok") ? tr("integra") : tr("errore"), plurale(chain.number("voci"), uno: "%@ evento", molti: "%@ eventi"))).font(.callout.weight(.medium))
                                    if let message = chain["errore"] as? String { Text(message).font(.caption).foregroundStyle(.orange) }
                                }
                            }
                            DisclosureGroup(tr("Dati della verifica")) { Text(prettyJSON(model.integrity)).font(.caption.monospaced()).textSelection(.enabled) }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                }
            }.padding(28)
        }
    }
}


/// "1 file" and "2 files": English and Spanish need the singular, Italian does not show it.
func conteggioFile(_ numero: Int, _ byte: String) -> String {
    numero == 1 ? tr("1 file · %@", byte) : tr("%@ file · %@", "\(numero)", byte)
}
