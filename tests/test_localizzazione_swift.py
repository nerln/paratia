"""Interfaccia macOS: tabelle it/en/es coerenti, chiavi usate, nessun testo italiano fuori da tr()."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lessico_italiano import contiene_italiano  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / "macos"
LINGUE = ("it", "en", "es")
SORGENTI = sorted(p.name for p in MAC.glob("*.swift"))
# Chiavi che la GUI costruisce da un valore (Section.title usa tr(rawValue)).
CHIAVI_DINAMICHE = {"Cartelle", "Registro", "Etichette", "Banco di prova", "Impostazioni"}
RIGA = re.compile(r'^"((?:[^"\\]|\\.)*)" = "((?:[^"\\]|\\.)*)";$')


def _tabella(lingua):
    testo = (MAC / "lingue" / (lingua + ".lproj") / "Localizable.strings").read_text(encoding="utf-8")
    voci = {}
    for riga in testo.split("\n"):
        m = RIGA.match(riga)
        if m:
            assert m.group(1) not in voci, (lingua, m.group(1))
            voci[m.group(1)] = m.group(2)
    return voci


def _salta_interpolazione(testo, j):
    """Indice dopo la parentesi che chiude \\( ... ), con stringhe annidate."""
    profondita, k = 1, j + 2
    while k < len(testo) and profondita:
        c = testo[k]
        if c == '"':
            k += 1
            while k < len(testo) and testo[k] != '"':
                if testo.startswith("\\(", k):
                    k = _salta_interpolazione(testo, k)
                else:
                    k += 2 if testo[k] == "\\" else 1
            k += 1
            continue
        if c == "(":
            profondita += 1
        elif c == ")":
            profondita -= 1
        k += 1
    return k


def _letterali(testo):
    """(testo prima del letterale nella stessa riga, contenuto grezzo) per ogni letterale a riga singola.

    Esclusi i commenti e i blocchi multilinea (comandi mostrati come codice).
    Le interpolazioni (tra parentesi, dopo una barra rovesciata) sono tolte dal contenuto.
    """
    trovati, i, n = [], 0, len(testo)
    while i < n:
        if testo.startswith("//", i):
            fine = testo.find("\n", i)
            i = n if fine == -1 else fine
            continue
        if testo.startswith("/*", i):
            i = testo.find("*/", i) + 2
            continue
        if testo.startswith('"""', i):
            i = testo.find('"""', i + 3) + 3
            continue
        if testo[i] == '"':
            prima = testo[testo.rfind("\n", 0, i) + 1:i]
            j, raw = i + 1, []
            while j < n and testo[j] not in '"\n':
                if testo.startswith("\\(", j):
                    j = _salta_interpolazione(testo, j)
                elif testo[j] == "\\":
                    raw.append(testo[j:j + 2])
                    j += 2
                else:
                    raw.append(testo[j])
                    j += 1
            trovati.append((prima, "".join(raw)))
            i = j + 1
            continue
        i += 1
    return trovati


def _testo_visibile(raw):
    """Vero se il letterale può comparire a schermo: ha uno spazio, una maiuscola o un accento."""
    if not raw.strip() or raw.startswith(("/", "x-apple")):
        return False
    if "/" in raw and " " not in raw:
        return False  # percorsi di file e di bundle: non sono frasi
    if re.fullmatch(r"[a-z0-9_.:\-]+", raw):
        return False  # codici e identificatori: riservato, aperta, migrazione-incompleta
    return " " in raw or raw[:1].isupper() or bool(re.search(r"[àèéìòùÀÈÉÌÒÙ]", raw))


def _chiavi_tr():
    chiavi = set()
    for nome in SORGENTI:
        for prima, raw in _letterali((MAC / nome).read_text(encoding="utf-8")):
            p = prima.rstrip()
            if p.endswith(("tr(", "uno:", "molti:")):
                chiavi.add(raw)
    return chiavi


def test_three_tables_have_the_same_keys_and_no_empty_value():
    tabelle = {lingua: _tabella(lingua) for lingua in LINGUE}
    chiavi = set(tabelle["it"])
    assert len(chiavi) > 300
    for lingua in LINGUE:
        assert set(tabelle[lingua]) == chiavi, lingua
        assert all(valore.strip() for valore in tabelle[lingua].values()), lingua
    for chiave in chiavi:
        for lingua in ("en", "es"):
            assert tabelle[lingua][chiave].count("%@") == chiave.count("%@"), (lingua, chiave)


def test_every_tr_key_exists_in_all_tables():
    tabelle = {lingua: _tabella(lingua) for lingua in LINGUE}
    for chiave in _chiavi_tr():
        for lingua in LINGUE:
            assert chiave in tabelle[lingua], (lingua, chiave)


def test_every_table_key_is_used_by_the_code():
    usate = _chiavi_tr() | CHIAVI_DINAMICHE
    inutili = sorted(set(_tabella("it")) - usate)
    assert inutili == [], inutili


def test_no_italian_text_is_shown_without_tr():
    colpe = []
    for nome in SORGENTI:
        for prima, raw in _letterali((MAC / nome).read_text(encoding="utf-8")):
            if prima.rstrip().endswith(("tr(", "uno:", "molti:")) or re.search(r"\bcase\b", prima):
                continue  # chiavi di traduzione e casi dell'enumerazione Section
            if _testo_visibile(raw) and contiene_italiano(raw):
                colpe.append((nome, raw[:70]))
    assert colpe == [], colpe


def test_no_hardcoded_datepicker_or_picker_labels():
    for nome in SORGENTI:
        testo = (MAC / nome).read_text(encoding="utf-8")
        assert not re.search(r'(DatePicker|Picker|Toggle|TextField|SecureField|Stepper)\("', testo), nome


def test_preview_paths_pass_through_tr():
    # I percorsi di anteprima contengono parole italiane (Esempio, disco): devono passare da tr(),
    # così ogni lingua mostra il suo nome. Il controllo sul testo non li vedeva: sono percorsi.
    colpe = []
    for nome in SORGENTI:
        for prima, raw in _letterali((MAC / nome).read_text(encoding="utf-8")):
            if not raw.startswith("/") or prima.rstrip().endswith(("tr(", "uno:", "molti:")):
                continue
            if contiene_italiano(raw):
                colpe.append((nome, raw[:70]))
    assert colpe == [], colpe
    anteprima = (MAC / "AppModel.swift").read_text(encoding="utf-8").split("private func loadFixtures()", 1)[1]
    assert "/Esempio" not in anteprima.replace('tr("/Esempio', "")  # ogni percorso e' dentro tr()


def test_post_install_text_follows_the_signing_mode():
    # La GUI sceglie il testo dopo l'installazione da fda_regrant_after_build, non da un testo fisso.
    modello = (MAC / "AppModel.swift").read_text(encoding="utf-8")
    installazione = modello.split("func installRegistry()", 1)[1].split("func verifyRegistry()", 1)[0]
    assert 'result["fda_regrant_after_build"]' in installazione
    assert "con la stessa firma il permesso resta valido" in installazione
    assert "rimuovi e aggiungi di nuovo la voce" in installazione
    assert 'plan.text("message"' in installazione
