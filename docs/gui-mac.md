# Paratia per Mac

L'app nativa richiede macOS 13 o successivo. Le cinque sezioni sono
**Cartelle**, **Registro**, **Etichette**, **Banco di prova** e **Impostazioni**.
Le operazioni quotidiane si svolgono nella GUI; **Aggiorna** rilegge lo stato.
Il giro 4 è stato pubblicato dal supervisore (`f54b403`) ed Eugenio ha installato
app, bootstrap e servizio e completato Accesso completo al disco. Il registro
è stato verificato dal vivo il 14 ottobre 2026, dalle 03:40 alle 03:46: create/write
di zsh, open/close di cat e ls, accessi di Claude classificati come agente,
Finder, Spotlight e pannello Apri/Salva. Questi riscontri riguardano il registro;
il banco pubblico resta non eseguito. La build del giro 5 e la misura delle sue
prestazioni dal vivo richiedono ancora i passi del supervisore e dell'utente.
Lo stato delle verifiche è in [stato di ottobre 2026](stato-2026-10.md).

## Cartelle

Premi **Proteggi una cartella**, scegli la fonte e una destinazione sul disco
esterno fisico, anche una sua sottocartella. Prima di mostrare il campo della
chiave, Paratia individua il volume effettivo e risale al disco fisico intero.
Per APFS segue gli store fisici, anche se il contenitore è virtuale; per altri
filesystem segue il disco padre. SSD APFS ed exFAT esterni sono accettati;
dischi interni e immagini disco vengono rifiutati. Paratia copia e verifica i
dati, prova la chiusura e la riapertura, poi rimuove l'originale. Chiudi prima
i documenti che possono modificare la fonte.
La scheda mostra stato, percorso, immagine cifrata, numero di file e dimensione.
Usa **Apri…**, **Mostra nel Finder**, **Chiudi** o **Chiudi tutte**; per una
migrazione incompleta sono disponibili **Recupera la fonte** e **Annulla migrazione**.

**Chiusura dopo N min** imposta da 1 a 1440 minuti. Se il montaggio è occupato,
chiudi l'app o il terminale aperto dentro e riprova. **Forza chiusura…** apre
una conferma con **Annulla** come prima scelta: forzare può perdere modifiche
non salvate. Timer, hook e **Chiudi tutte** continuano senza forzare.
Nelle migrazioni incomplete con montaggio temporaneo sono disponibili anche
**Chiudi montaggi** e **Forza chiusura…**. Chiudere il montaggio lascia la
migrazione da recuperare o annullare e può lasciare una copia in chiaro.
**Apri…** segnala una cartella già aperta
prima di chiedere la chiave e precisa che il timer e i minuti esistenti non
cambiano. Un disco scollegato chiede di ricollegarlo, prima del campo chiave.
**Chiudi** su una cartella già chiusa non aggiunge
un evento al registro. Una chiusura manuale riuscita annulla anche il timer,
che riconosce la cancellazione entro il successivo controllo, ogni 0,25 secondi.
Una chiave sbagliata produce un messaggio specifico per reinserirla, anche con
messaggi hdiutil in italiano o spagnolo. La verifica della chiave non monta il volume.
Prima della chiave, un controllo strutturale distingue un'immagine danneggiata
o incompleta: conserva la copia attuale e ripristina una copia integra; cambiare
chiave non risolve file mancanti o un token troncato.
Nei campi protetti **Chiave del compartimento** e **Ripeti la chiave** servono
almeno 12 byte UTF-8. La chiave passa al worker
tramite stdin; non viene salvata in file, registro o portachiavi, né inserita
negli argomenti o nell'ambiente dei processi. Conservane una copia tua.

## Registro

Premi **Sorveglia una cartella…** e scegli una directory nel selettore del
Finder. Puoi scegliere anche una cartella senza cifrarla. **Cartelle sorvegliate**
mostra le richieste configurate; **Rimuovi** rimuove la richiesta senza modificare
i file. Lo stato distingue una richiesta salvata dalla conferma del demone:
soltanto un registro attivo può raccogliere gli eventi successivi. Una voce
rifiutata mostra **Rifiutata dal raccoglitore** e il motivo; il rifiuto di un ID
non nasconde le altre cartelle. La conferma dell'ID e la salute complessiva del
flusso sono informazioni distinte. Anche le schede delle cartelle protette
mostrano lo stato della raccolta.
Sui dischi esterni con proprietari ignorati, come AppsAndFiles, l'UID della
directory può risultare diverso tra CLI utente e demone root. Il raccoglitore
accetta la richiesta dal file di configurazione posseduto e validato dell'utente
dopo aver confermato un volume esterno fisico e non di sistema. Lo stesso vale
per le cartelle protette; questa scelta permette la sorveglianza e non attesta
la proprietà dei file né l'isolamento tra account sul volume.
Scegliere di nuovo una cartella conserva il suo nome. Per rinominarla dalla CLI,
usa `registro sorveglia <percorso> --nome Nuovo`: l'ID resta invariato.
Il montaggio di una cartella protetta usa già il suo ID e non ammette una
sorveglianza separata.

Filtra con **Cartella**, **File o percorso**, **Processo o PID**, **Agente** e,
attivando **Intervallo**, **Da** e **A**. **Cerca** applica i filtri; la ricerca
del processo comprende anche l'app responsabile. L'agente può essere riconosciuto,
non agente o **Sconosciuto**: un valore sconosciuto non viene trasformato in certezza.

Seleziona una riga e premi **Apri dettaglio** per vedere tutti i metadati presenti:
fonte `paratia` o `eslogger`, PID, utente, app responsabile, cartelle interessate
e tipo di radice osservata, per esempio originale, montaggio o immagine cifrata.
La tabella mostra al massimo 2500 eventi; **Esporta CSV…** include tutti quelli
che corrispondono ai filtri. Accanto al conteggio, anche a **0 eventi**, compare lo stato della raccolta
kernel per la ricerca: attiva, inattiva o da verificare. Un filtro cartella
richiede anche la conferma del suo ID. Un percorso sconosciuto o ambiguo mostra
un messaggio specifico; non viene creato un CSV vuoto al suo posto. Un'apertura
per lettura non prova una lettura dei
byte e ogni tentativo fallito non produce necessariamente un evento kernel.
Vedi [Registro degli accessi](registro-accessi.md).

Registro e Impostazioni mostrano i motivi di **registro non sano**, fra cui
ritardo, eventi persi negli ultimi dieci minuti, cartelle rifiutate e nessuna
cartella confermata. Dopo dieci minuti senza nuove perdite il motivo sparisce e
il registro torna sano; il totale delle perdite resta nei dati. **Latenza
degli eventi** confronta il timestamp dell'ultimo evento con la sua ricezione;
**Flusso ricevuto** mostra tutte le righe eslogger al secondo, incluse quelle
scartate prima del parser perché estranee alle cartelle. **Ultimo evento ricevuto
N s fa** segnala il tempo trascorso dalla ricezione: il silenzio non prova un
ritardo. Una metrica assente è indicata come non misurata. Query e CSV riportano
gli stessi metadati di raccolta, anche quando non ci sono righe.

Una cartella già confermata che manca per un momento resta sorvegliata e
mostra **Confermata dal raccoglitore · Cartella assente…**. Lo stesso vale
per un timeout transitorio della verifica del volume, con il relativo avviso.
Una nuova cartella assente o un percorso sostituito restano rifiutati: la
conferma è legata al percorso corrente, senza riusare un vecchio ID per
coprire una richiesta diversa.

La raccolta predefinita esclude `lookup`, `mmap`, `close`, `mount` e `unmount`
(giro 8); i relativi eventi storici restano leggibili. Le modifiche sono `write`,
`create`, `rename`, `unlink` e `truncate`. Il registro non mostra più un evento di
chiusura file né di montaggio dal kernel. Un filtro economico prima della decodifica JSON
riconosce le radici sorvegliate e le loro forme alternative, senza scartare la
discendenza exec/fork/exit. I numeri di sequenza restano controllati anche per
le righe scartate: il filtro non può mascherare perdite dichiarate da eslogger.

## Etichette

**Scegli…** imposta la radice del browser; **Percorso della cartella** e **Vai**
permettono di cambiarla. Usa **Entra**, la freccia verso l'alto e **Nascosti**
per navigare. L'elenco mostra nomi, dimensioni ed etichette, senza contenuti o anteprime.
Assegna **Riservato**, **Zona…** o **Pubblico**; **Togli etichetta** rimuove
un'assegnazione specifica. Le etichette ereditate indicano da dove provengono.
**Il piano delle etichette** riepiloga decisioni e percorsi mancanti.
Un'etichetta registra una scelta: la cifratura comincia da **Proteggi una cartella**.

## Banco di prova

Premi **Scegli destinazione…**, **Controlla le condizioni** e **Esegui la sequenza…**.
La prova usa `~/Desktop/folder-test`, crea file sintetici soltanto nella cartella
vuota e richiede registro sano, sorveglianza confermata e chiave nella GUI.
**Autorizzo le CLI reali, incluse eventuali richieste del portachiavi** è una
scelta esplicita: Codex e Claude Code avviano figli CLI, senza invocare modelli.

**Ultima prova** mostra conteggi, migrazione, chiusura finale e quattro fasi:
prima, chiusa, riaperta, richiusa. Ogni scheda distingue esito del probe, errno
misurato e riscontri kernel. `mdls` è informativo: cache o mancata indicizzazione
del volume non fanno fallire la fase. Restano obbligatorie le misure di shell,
Codex e Claude Code e, nelle fasi aperte, i rispettivi riscontri kernel.
Una sorveglianza già configurata sulla stessa cartella viene conservata.
**Prove precedenti** conserva lo storico leggibile; **Dettagli dello storico**, **Esporta JSON…**
e **Esporta CSV…** mantengono i dati completi. La prova live è ancora
**non eseguita**: [workflow e stato del banco](banco-folder-test.md).

## Impostazioni

**Lingua** sceglie fra Sistema, Italiano, English ed Español. La finestra cambia subito;
la voce del menu cambia al riavvio.

Quando il servizio appartiene a una build diversa da `/Applications/Paratia.app`,
il Registro mostra **Passi per aggiornare…** e apre le Impostazioni, dove
**Aggiorna il registro** elenca i passi numerati in ordine. Se la vecchia build
non pubblica la sua identità, il messaggio dice che l'identità è indisponibile
e chiede di aggiornare per verificarla: non dichiara un confronto riuscito.
I passi minimi sono riportati anche in
[Aggiornare il registro dopo questo giro](stato-2026-10.md#aggiornare-il-registro-dopo-questo-giro).

Gli hook preferiscono la copia bootstrap protetta e sostituiscono i vecchi
handler Paratia, conservando gli hook estranei e i backup. Se il codice o i suoi
antenati sono modificabili dall'utente, le esenzioni CLI a cartella aperta sono
negate: chiudi dalla GUI o dal Finder. Un alias CLI che punta ancora al repository
non è esente; non viene modificato automaticamente. La configurazione degli
harness resta modificabile dal loro proprietario e richiede la sua fiducia.

Per installare il registro, apri la copia bootstrap dell'app preparata
manualmente in `/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app`.
Nelle sue **Impostazioni**, **Installa il registro…** prepara il piano e
presenta **Autorizza con macOS**.
Prima del dialogo, Paratia verifica che questa copia, tutti i suoi antenati e
ogni file letto dal bootstrap siano di root, senza collegamenti simbolici,
scrittura per gruppo/altri o ACL che concedano scrittura. La copia deve avere
la stessa firma e lo stesso CDHash della build corrente.

I tre percorsi hanno ruoli distinti:

- `/Applications/Paratia.app`: app quotidiana e voce Accesso completo al disco;
  conserva i permessi attuali.
- `/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app`: copia protetta
  da aprire per avviare il piano amministratore.
- `/Library/Application Support/Paratia/Paratia.app`: copia protetta del
  servizio installato, dentro la directory privata del servizio con modo `0700`.

Alla verifica del 14 ottobre 2026, gli antenati del bootstrap hanno permessi
Unix compatibili:
`/` e `/Library` sono `root:wheel 0755`, `/Library/Application Support` è
`root:admin 0755`. La preparazione riguarda soltanto la nuova directory
`ParatiaBootstrap.noindex` e la copia dell'app. Copiare la stessa build e cambiarne il
proprietario non cambia il CDHash: il permesso TCC dell'app quotidiana resta valido.

Chiudi tutte le copie di Paratia. Esegui personalmente nel Terminale questo
unico comando di preparazione; viene riportato qui senza essere eseguito:

```sh
sudo /bin/sh -c 'set -eu
[ ! -L "/Library/Application Support/ParatiaBootstrap.noindex" ]
[ -d "/Applications/Paratia.app" ]
[ ! -L "/Applications/Paratia.app" ]
/usr/bin/install -d -m 755 -o root -g wheel "/Library/Application Support/ParatiaBootstrap.noindex"
/bin/chmod -N "/Library/Application Support/ParatiaBootstrap.noindex"
paratia_bootstrap_stage=$(/usr/bin/mktemp -d "/Library/Application Support/ParatiaBootstrap.noindex/.prepara.XXXXXX")
/usr/bin/ditto --noacl "/Applications/Paratia.app" "$paratia_bootstrap_stage/Paratia.app"
/usr/bin/find "$paratia_bootstrap_stage/Paratia.app" ! -type d ! -type f -print > "$paratia_bootstrap_stage/percorsi-non-ordinari"
[ ! -s "$paratia_bootstrap_stage/percorsi-non-ordinari" ]
/usr/sbin/chown -R root:wheel "$paratia_bootstrap_stage/Paratia.app"
/bin/chmod -R go-w "$paratia_bootstrap_stage/Paratia.app"
/usr/bin/codesign --verify --deep --strict "$paratia_bootstrap_stage/Paratia.app"
[ ! -L "/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app" ]
if [ -e "/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app" ]; then
    /bin/mv "/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app" "$paratia_bootstrap_stage/precedente.app"
fi
/bin/mv "$paratia_bootstrap_stage/Paratia.app" "/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app"
/usr/bin/codesign --verify --deep --strict "/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app"
/usr/bin/find "/Library/Application Support/ParatiaBootstrap.noindex" -mindepth 1 -maxdepth 1 -type d -user root -name ".prepara.*" -exec /bin/rm -rf -- {} +
if [ -e "/Library/Application Support/ParatiaBootstrap" ]; then
    [ ! -L "/Library/Application Support/ParatiaBootstrap" ]
    [ -d "/Library/Application Support/ParatiaBootstrap" ]
    [ "$(/usr/bin/stat -f %u "/Library/Application Support/ParatiaBootstrap")" = "0" ]
    paratia_legacy_mode=$(/usr/bin/stat -f %Lp "/Library/Application Support/ParatiaBootstrap")
    [ $((0$paratia_legacy_mode & 022)) -eq 0 ]
    [ ! -L "/Library/Application Support/ParatiaBootstrap/Paratia.app" ]
    if [ -e "/Library/Application Support/ParatiaBootstrap/Paratia.app" ]; then
        [ -d "/Library/Application Support/ParatiaBootstrap/Paratia.app" ]
        [ "$(/usr/bin/stat -f %u "/Library/Application Support/ParatiaBootstrap/Paratia.app")" = "0" ]
        /bin/rm -rf -- "/Library/Application Support/ParatiaBootstrap/Paratia.app"
    fi
    /usr/bin/find "/Library/Application Support/ParatiaBootstrap" -mindepth 1 -maxdepth 1 -type d -user root -name ".prepara.*" -exec /bin/rm -rf -- {} +
fi'
```

La preparazione usa una directory temporanea di root con modo `0700`, rifiuta
collegamenti e file speciali prima di cambiare proprietario e permessi, e verifica
la firma prima e dopo la pubblicazione. A copia verificata elimina le directory
root `.prepara.*` e l'app del vecchio percorso `ParatiaBootstrap`. Il suffisso
`.noindex` evita l'indicizzazione della nuova copia senza cambiare i controlli
root. Apri la nuova copia dal
Finder soltanto se il comando termina senza errori, con codice di uscita `0`.

Il dialogo amministratore gestisce la password. L'installer copia il bundle
firmato in `/Library/Application Support/Paratia/Paratia.app`, protetto da root.
Il LaunchDaemon esegue il binario nativo di questa copia, che resta vivo e
avvia il raccoglitore Python come figlio.

L'installer attende che launchd abbia rimosso il servizio dopo ogni `bootout`,
con un limite di tempo, e riprova gli errori di corsa 5/37 con attesa crescente.
Se deve ripristinare il servizio precedente, applica gli stessi controlli.
In caso di errore la GUI mostra il messaggio dell'installer e il codice, anche
quando il ripristino fallisce. La risposta JSON include gli errori launchctl
ridotti, senza percorsi o dati privati dello stderr.

Conclusa l'installazione, chiudi la copia bootstrap e riapri l'app quotidiana
in `/Applications/Paratia.app`. Qui **Apri Accesso completo al disco** porta
alle impostazioni privacy:
aggiungi e abilita **`/Applications/Paratia.app`**. Con firma ad hoc, dopo ogni nuova
build rimuovi la voce precedente e aggiungi di nuovo l'app installata. Con un'identità
stabile il permesso resta valido finché l'app viene firmata con lo stesso certificato;
aggiorna la copia bootstrap e reinstalla il registro per aggiornare la copia
del servizio. Non abilitare
Python 3.9. Il passaggio del permesso ai figli e la raccolta kernel sono stati
verificati sulla build del giro 4. Il giro 6 è pubblicato (`91914a0`), ma la sua
installazione del servizio è fallita e lo ha lasciato scaricato. Per il giro 7, ripeti i passi
numerati e verifica un nuovo evento eslogger dopo **Aggiorna**; il registro
precedente funzionante non prova che la nuova firma sia già autorizzata.
**Verifica il registro** controlla le due catene presenti, senza attestare da sola
la copertura continua o una coda eliminata.

**Rivedi e collega gli hook…** mostra il piano prima di **Applica il piano**:
conserva le configurazioni esistenti e crea backup JSON. `SessionStart` richiede
la chiusura dei compartimenti all'avvio della sessione; riavvia le sessioni dopo
la configurazione. La fiducia Codex va approvata manualmente nella gestione hook
dell'app Codex. **Ripristina un backup…** ripristina soltanto una configurazione
ancora uguale a quella installata, preserva modifiche successive e crea un nuovo backup.

Il worker GUI usa Python Apple dei Command Line Tools, compatibile con 3.9,
in modalità isolata `-I -S`. Gli hook richiedono il runtime Apple dei Command
Line Tools protetto da root, Python 3.9 o successivo, con `-I -S -B`:
il loro stato verifica runtime e libreria standard e segnala dipendenze mancanti
o percorsi non protetti.

## Costruzione per il manutentore

Dal repository, con i Command Line Tools Apple e `rsvg-convert` disponibili:

```sh
python3 strumenti/build-app.py --render-fixtures
open -n build.noindex/Paratia.app --args --launch-check
~/.local/bin/installa-app build.noindex/Paratia.app
```

`--launch-check` apre la GUI e la chiude dopo quattro secondi. L'installazione
in `/Applications` è a carico del supervisore. Le immagini generate usano
fixture dichiarate sintetiche. La build produce `build.noindex/Paratia.app`,
che Spotlight deve ignorare. L'icona nasce da `macos/Assets/Paratia.svg`:
`strumenti/make-icon.py` genera dieci PNG da 16 a 1024 pixel e li converte con
`iconutil`, poi la build collega `Paratia.icns` in `Info.plist`. La preview è
in `docs/immagini/paratia-icona.png`. Nel sandbox i PNG sono verificati, ma
`iconutil` ha rifiutato l'iconset: il supervisore deve verificare la conversione
reale durante la build. La build firma
**ad hoc** per impostazione predefinita, senza identità dal portachiavi, e non è
notarizzata. Con `--sign-identity "<nome>"` o la variabile `PARATIA_SIGN_IDENTITY`
firma con un'identità stabile del portachiavi: la build non ne sceglie una da sola.
Con identità stabile il permesso di Accesso completo al disco resta valido finché si
firma con lo stesso certificato; la verifica della copia installata (stesso CDHash,
`codesign --verify --deep --strict`) resta attiva e `sudo bootstrap` non cambia.
Le tabelle dei testi stanno in `macos/lingue/{it,en,es}.lproj/Localizable.strings`.
`--render-fixtures` produce le schermate in `build.noindex/screenshots/<lingua>/`;
`--lang it|en|es` ne produce una sola. Il percorso
amministratore locale usa l'API deprecata `AuthorizationExecuteWithPrivileges`,
limitata al piano fisso del registro e al runtime root protetto. Eugenio ha già
eseguito l'installazione del giro 6; il servizio richiede una nuova installazione
umana con la correzione del giro 7.

Dopo la migrazione, verifica da Terminale:

```sh
mdfind "kMDItemCFBundleIdentifier == 'it.paratia.app'"
```

Deve comparire soltanto `/Applications/Paratia.app`. Nel sandbox la query
restituisce zero risultati anche per l'app normale esistente, quindi non prova
l'assenza di doppioni. Il supervisore ripete la query e controlla Spotlight e
Launchpad dopo la copia manuale. Nessun flag che nasconde l'app dal Dock viene
aggiunto al bundle.
