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
        guard let value = data["agente"] as? Bool else { return "Sconosciuto" }
        return value ? data.text("nome_agente", fallback: "Agente") : "No"
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
    ["open": "Apertura", "close": "Chiusura file", "write": "Scrittura", "create": "Creazione",
     "rename": "Rinomina", "unlink": "Cancellazione", "mount": "Montaggio", "unmount": "Smontaggio",
     "mmap": "Mappatura memoria", "truncate": "Troncamento", "lookup": "Ricerca percorso",
     "cartella-aperta": "Cartella aperta", "cartella-chiusa": "Cartella chiusa",
     "cartella-protetta": "Cartella protetta", "tentativo-fallito": "Tentativo fallito",
     "diagnostico": "Diagnostico"][event] ?? event
}

func prettyJSON(_ value: Any) -> String {
    guard JSONSerialization.isValidJSONObject(value),
          let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]),
          let text = String(data: data, encoding: .utf8) else { return "Nessun dettaglio disponibile." }
    return text
}

func byteCount(_ count: Int) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(count), countStyle: .file)
}
