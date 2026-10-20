import Foundation

typealias Record = [String: Any]

extension Dictionary where Key == String, Value == Any {
    func text(_ key: String, fallback: String = "—") -> String {
        guard let value = self[key], !(value is NSNull) else { return fallback }
        return value as? String ?? String(describing: value)
    }
    func flag(_ key: String) -> Bool { self[key] as? Bool ?? false }
    func number(_ key: String) -> Int { (self[key] as? NSNumber)?.intValue ?? 0 }
}

struct FolderItem: Identifiable {
    let data: Record
    var id: String { data.text("id") }
    var name: String { data.text("nome") }
    var state: String { data.text("stato") }
    var source: String { data.text("origine") }
    /// Where the files are while open: in place, or in Paratia's area for disks without owners.
    var openPath: String { state == "aperta" ? data.text("montaggio_temporaneo", fallback: source) : source }
    var isIncomplete: Bool { state == "migrazione-incompleta" || state == "migrazione" }
}

struct EventItem: Identifiable {
    let id: String
    let data: Record
    var event: String { eventName(data.text("evento")) }
    var date: String { data.text("quando") }
    var path: String { data.text("percorso") }
    var process: String { data.text("processo") }
    var agent: String {
        guard let value = data["agente"] as? Bool else { return tr("Sconosciuto") }
        return value ? data.text("nome_agente", fallback: tr("Agente")) : "No"
    }
}

struct FileItem: Identifiable {
    let data: Record
    var id: String { data.text("percorso") }
    var name: String { data.text("nome") }
    var isDirectory: Bool { data.flag("cartella") }
}

enum Section: String, CaseIterable, Identifiable {
    case folders = "Cartelle", logs = "Registro", labels = "Etichette", bank = "Banco di prova", settings = "Impostazioni"
    var id: String { rawValue }
    var title: String { tr(rawValue) }
    var icon: String {
        switch self {
        case .folders: return "lock.rectangle"
        case .logs: return "list.bullet.rectangle"
        case .labels: return "tag"
        case .bank: return "checkmark.shield"
        case .settings: return "gearshape"
        }
    }
}

struct KeyRequest: Identifiable {
    let id = UUID()
    let action: String
    let title: String
    let parameters: Record
    let confirm: Bool
}

func eventName(_ event: String) -> String {
    ["open": tr("Apertura"), "close": tr("Chiusura file"), "write": tr("Scrittura"), "create": tr("Creazione"),
     "rename": tr("Rinomina"), "unlink": tr("Cancellazione"), "mount": tr("Montaggio"), "unmount": tr("Smontaggio"),
     "mmap": tr("Mappatura memoria"), "truncate": tr("Troncamento"), "lookup": tr("Ricerca percorso"),
     "cartella-aperta": tr("Cartella aperta"), "cartella-chiusa": tr("Cartella chiusa"),
     "cartella-protetta": tr("Cartella protetta"), "tentativo-fallito": tr("Tentativo fallito"),
     "diagnostico": tr("Diagnostico")][event] ?? event
}

func prettyJSON(_ value: Any) -> String {
    guard JSONSerialization.isValidJSONObject(value),
          let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]),
          let text = String(data: data, encoding: .utf8) else { return tr("Nessun dettaglio disponibile.") }
    return text
}

/// Dimensione in byte, KB, MB, GB o TB con il separatore decimale della lingua in uso.
func byteCount(_ count: Int) -> String {
    let formatter = NumberFormatter()
    formatter.locale = Localizzazione.locale
    formatter.minimumFractionDigits = 0
    formatter.maximumFractionDigits = 1
    let value = Double(count)
    let scale: [(Double, String)] = [(1e12, "TB"), (1e9, "GB"), (1e6, "MB"), (1e3, "KB")]
    for (factor, unit) in scale where value >= factor {
        return (formatter.string(from: NSNumber(value: value / factor)) ?? "") + " " + unit
    }
    return (formatter.string(from: NSNumber(value: count)) ?? "\(count)") + " B"
}

/// Testo visibile di un'etichetta. I codici riservato, pubblico e zona:nome restano
/// quelli del worker; qui diventano frasi nella lingua in uso.
func etichettaTesto(_ codice: String) -> String {
    switch codice {
    case "riservato": return tr("Riservato")
    case "pubblico": return tr("Pubblico")
    default:
        if codice.hasPrefix("zona:") { return tr("Zona: %@", String(codice.dropFirst(5))) }
        return codice
    }
}
