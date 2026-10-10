# Banco di prova di folder-test

**Stato: non eseguito.** La sequenza reale su `~/Desktop/folder-test` attende
le autorizzazioni amministratore, Accesso completo al disco per il registro,
l'accesso al Desktop se richiesto da macOS e la chiave inserita nella GUI.
Non sono disponibili orari, conteggi misurati, risultati degli agenti o
riscontri kernel. Il [JSON pubblico](banco-folder-test.json) mantiene `fasi`
e `prove` vuoti e gli orari a `null`.

La destinazione prevista è una cartella scelta sulla SSD **AppsAndFiles**.
Il nome del volume descrive la destinazione; il banco verifica il disco scelto
prima del campo della chiave e di nuovo al momento dell'avvio. Sono ammesse
le sottocartelle del volume esterno fisico; immagini disco e volumi interni
vengono rifiutati. La verifica temporanea separata è descritta nello
[stato di ottobre 2026](stato-2026-10.md).

## Avvio dalla GUI

1. Prepara la copia bootstrap protetta da root in
   `/Library/Application Support/ParatiaBootstrap/Paratia.app`, come descritto
   nella [guida GUI](gui-mac.md#impostazioni): vengono verificati questa copia,
   tutti gli antenati e ogni file letto dal bootstrap, inclusi permessi e ACL.
   Apri la copia bootstrap e, nelle sue **Impostazioni**, premi
   **Installa il registro…** e decidi nel dialogo amministratore di macOS.
   Chiudi il bootstrap e riapri l'app quotidiana in `/Applications/Paratia.app`.
   Da questa app premi **Apri Accesso completo al disco**,
   aggiungi e abilita `/Applications/Paratia.app`. Dopo una nuova build ad hoc,
   rimuovi e aggiungi di nuovo la voce, aggiorna il bootstrap e reinstalla il
   registro. La copia del servizio resta in
   `/Library/Application Support/Paratia/Paratia.app`. Non abilitare
   Python 3.9. Il registro deve risultare attivo e
   sano; anche la catena locale deve essere verificabile. I dettagli sono in
   [Registro degli accessi](registro-accessi.md).
2. In **Banco di prova**, premi **Scegli destinazione…** e seleziona una
   cartella sulla SSD AppsAndFiles. Premi **Controlla le condizioni**: questa
   anteprima controlla il disco e lo stato del registro e legge soltanto i
   metadati di `~/Desktop/folder-test`. Se macOS richiede l'accesso al Desktop,
   decidi nel suo dialogo. La GUI ricontrolla queste condizioni prima del campo
   della chiave.
3. Usa una cartella vuota. Se contiene file personali o non riconosciuti,
   spostali tu prima della prova. Il banco rifiuta la loro migrazione. Crea
   soltanto `LEGGIMI-SINTETICO.txt`, `campione.bin`, `grande.bin` e
   `sottocartella/note.txt`, dichiarati sintetici. Una ripetizione accetta
   soltanto l'identificatore del compartimento e i metadati riconosciuti dallo
   storico della prova precedente.
4. Decidi se attivare **Autorizzo le CLI reali, incluse eventuali richieste del
   portachiavi**. Le CLI usano le proprie configurazioni e autorizzazioni. Le
   richieste di macOS restano una scelta umana; login, hook o un diniego possono
   lasciare la prova incompleta.
5. Premi **Esegui la sequenza…**, inserisci e ripeti una chiave propria del
   compartimento, diversa dalla chiave del disco. La GUI la trasmette al worker
   tramite stdin; non entra negli argomenti dei processi, nell'ambiente, nello
   storico, nel registro o negli export.

Prima di creare i file, il banco controlla la salute del registro e attende
che il demone confermi la sorveglianza della cartella. Se esiste già una
sorveglianza sullo stesso percorso, ne riutilizza l'identificatore, conserva il
nome e la mantiene alla fine; altrimenti ne crea una per questa prova e rimuove
soltanto quella.
Dopo la protezione attende anche il riconoscimento del compartimento.

## Le quattro fasi

Ogni fase conserva orari, stato della cartella, numero di file e byte visibili,
quindi prova lo stesso file sintetico con shell, `mdls`, Codex e Claude Code.
La migrazione conserva anche i conteggi prima e dopo e l'esito della sua
verifica. Questi campi verranno popolati soltanto dalla sequenza reale.

| Fase | Stato | Esito da misurare |
| --- | --- | --- |
| `prima` | Cartella sintetica ancora in chiaro | Apertura del file e riscontro kernel |
| `chiusa` | Compartimento protetto e chiuso | Accesso rifiutato al percorso originale |
| `riaperta` | Compartimento aperto dalla persona | Apertura del file e riscontro kernel |
| `richiusa` | Compartimento nuovamente chiuso | Accesso rifiutato al percorso originale |

La shell esegue un helper che chiama `open` e `fstat`, senza leggere i byte.
L'helper conserva l'errno effettivo dell'operazione fallita, quando presente.
`mdls` interroga `kMDItemFSSize`: il suo exit code viene registrato, ma può
rispondere usando metadati in cache e quindi non produrre un'apertura kernel.
Spotlight può anche non indicizzare un volume riaperto da hdiutil e restituire
un errore. È una sonda informativa: il suo risultato non determina l'esito
della fase. Shell, Codex e Claude Code restano tutte obbligatorie, con misure
reali e i riscontri kernel richiesti nelle fasi aperte.

Codex avvia l'helper come figlio della propria CLI tramite
`codex sandbox -C … -- …`. Claude Code espone il server `claude mcp serve`:
il banco chiede un'unica chiamata MCP `tools/call` al tool `Bash`, con il
comando umano dell'helper. **Il banco non invoca modelli.** Ulteriori richieste
di consenso dal server MCP vengono rifiutate; le risposte grezze non vengono
salvate. Una CLI assente o un risultato non valido rimangono non misurati.

I processi avviati non bastano a dimostrare la discendenza agente. Nelle fasi
aperte il banco cerca eventi `eslogger` per PID, percorso e ora; per Codex e
Claude Code richiede anche la classificazione agente corrispondente. La
copertura live resta da verificare: un riscontro mancante rende la prova
incompleta. La discendenza kernel può restare sconosciuta e la classificazione
del nome non certifica l'identità del fornitore.

I probe misurati sono annotati con sorgente `paratia`; gli eventi kernel
mantengono la sorgente `eslogger`. Un errno misurato dal probe non viene
attribuito al kernel. Endpoint Security non garantisce una notifica per ogni
tentativo fallito né prova la lettura dei byte. Anche un diniego previsto a
cartella chiusa deve avere una misura reale, senza inventare un evento.

## Storico e conclusione

Lo storico privato è in `~/.paratia/banco/storico.json`; la GUI lo mostra nel
riquadro **Ultima prova**, con le prove precedenti espandibili. **Esporta JSON…** conserva fasi, conteggi e riscontri;
**Esporta CSV…** produce le righe dei probe, con protezione dei valori che
potrebbero essere interpretati come formule. Nessun export contiene la chiave
o il contenuto dei file; i metadati possono includere percorsi e processi.
Il JSON nel repository descrive soltanto lo stato di attesa, senza sostituire
questo storico.

Il banco tenta sempre la chiusura finale del proprio compartimento, anche
dopo un errore o un'interruzione. Se la chiusura fallisce o resta una migrazione
incompleta, lo storico lo segnala: controlla **Cartelle** e usa **Chiudi tutte**,
**Recupera** o **Annulla migrazione**, secondo lo stato mostrato. Un secondo
banco concorrente viene rifiutato senza chiudere il compartimento dell'altro.

I test automatici attraversano l'IPC del worker e il banco usando una cartella
temporanea e una chiave di prova ricevuta da stdin. Il test portabile simula il
disco; `strumenti/prova-banco-temporaneo.py` usa invece hdiutil AES-256/APFS e
ditto su macOS. Entrambi dichiarano simulata la salute del registro, lasciano
vuoti i riscontri kernel e disabilitano le CLI vendor. La shell misura davvero
`open`/`fstat`. Verificano il contratto, la privacy e la gestione degli errori;
non attestano i permessi TCC o il registro sul Desktop.
