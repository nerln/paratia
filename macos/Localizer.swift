import Foundation

/// Lingua dei testi dell'app: italiano, inglese o spagnolo.
/// "sistema" segue le preferenze di macOS e ripiega sull'inglese.
enum Localizzazione {
    static let chiaveImpostazione = "paratia.lingua"
    static let lingue = ["it", "en", "es"]

    /// Lingua in uso: it, en o es. Il worker riceve lo stesso codice in PARATIA_LANG.
    static var codice: String = risolvi(UserDefaults.standard.string(forKey: chiaveImpostazione) ?? "sistema")
    private static var tabelle: [String: Bundle] = [:]

    static func risolvi(_ preferenza: String) -> String {
        if lingue.contains(preferenza) { return preferenza }
        for lingua in Locale.preferredLanguages where lingue.contains(String(lingua.prefix(2))) {
            return String(lingua.prefix(2))
        }
        return "en"
    }

    /// Salva la preferenza e la applica alla finestra. Il menu cambia al riavvio.
    static func imposta(_ preferenza: String) {
        UserDefaults.standard.set(preferenza, forKey: chiaveImpostazione)
        usa(risolvi(preferenza))
    }

    /// Cambia solo la lingua in uso, senza salvarla (per le schermate di prova).
    static func usa(_ lingua: String) {
        codice = lingue.contains(lingua) ? lingua : "en"
        tabelle = [:]
    }

    static func tabella() -> Bundle {
        if let bundle = tabelle[codice] { return bundle }
        let cartella = Bundle.main.url(forResource: codice, withExtension: "lproj")
        let bundle = cartella.flatMap { Bundle(url: $0) } ?? Bundle.main
        tabelle[codice] = bundle
        return bundle
    }

    /// Numeri e misure nella lingua scelta nell'app, non nella lingua di sistema.
    static var locale: Locale {
        switch codice {
        case "it": return Locale(identifier: "it_IT")
        case "es": return Locale(identifier: "es_ES")
        default: return Locale(identifier: "en_US")
        }
    }
}

/// Testo nella lingua in uso. La chiave è il testo italiano; %@ riceve i valori in ordine.
func tr(_ testo: String, _ valori: CVarArg...) -> String {
    let modello = Localizzazione.tabella().localizedString(forKey: testo, value: testo, table: nil)
    return valori.isEmpty ? modello : String(format: modello, arguments: valori)
}

/// Singolare per 1, plurale per gli altri numeri. %@ nei due testi riceve il numero.
func plurale(_ numero: Int, uno: String, molti: String) -> String {
    numero == 1 ? tr(uno, "\(numero)") : tr(molti, "\(numero)")
}
