"""Lessico per i controlli sui testi: parole italiane che in inglese e spagnolo non sono parole comuni.

Serve a trovare testo italiano visibile fuori dalle tabelle di traduzione. Non è un
dizionario completo: i test lo integrano con le regole sulle chiavi e sui codici.
"""
import re

PAROLE_ITALIANE = frozenset("""
il lo la gli le di da del della dello delle dei degli al alla alle agli dal dalla dalle dai
nel nella nelle nei sul sulla sulle con per tra fra che non più può deve devono sono è anche
ancora dopo prima come senza solo ogni quando questo questa questi queste tutto tutti tutte
nessuno nessuna nessun già sempre mai dove cosa ecco ma oppure perché però quindi
scegli scegliere conserva riprova apri chiudi chiusura apertura aggiorna installa installazione
verifica verificata verificato controlla premi usa rimuovi aggiungi abilita autorizza autorizzazione
autorizzazioni sorveglia sorveglianza sorvegliate cartella cartelle disco dischi errore errori
registro accesso servizio percorso impossibile processi riga troppo grande incompleta attributo
esteso sequenza conclusa rinominata conservato conservati configurata riscontro riscontri prova
prove storico sonda informativa ereditata codice uscita fine avvio avviata etichetta etichette
zona lavoro riservato pubblico aperta chiusa sintetica sintetico compartimento chiave banco
consenso richiesta richieste operazione dati messaggio demone esito esiti dettagli stato nome
montaggio scrittura lettura ricerca evento eventi lingua nuovo nuova nuove fallito fallita
riuscito confermato confermata disponibile necessario necessaria protetto protetta rifiutata
rifiutato negato consentito conferma mancante mancanti misura misurato locale reale reali
fase fasi copia copie esempio anteprima tentativo tentativi fonte migrazione immagine modifica
modifiche ritardo silenzio attendi passi aperto
""".split())

ACCENTI_ITALIANI = re.compile(r"[àèéìòùÀÈÉÌÒÙ]")
_PAROLA = re.compile(r"[A-Za-zÀ-ÿ]+")


def contiene_italiano(testo):
    """Vero se il testo ha accenti italiani o una parola del lessico."""
    if ACCENTI_ITALIANI.search(testo):
        return True
    return any(parola.lower() in PAROLE_ITALIANE for parola in _PAROLA.findall(testo))
