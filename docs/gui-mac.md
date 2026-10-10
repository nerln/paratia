# Paratia per Mac

L'app nativa richiede macOS 13 o successivo. Le cinque sezioni sono
**Cartelle**, **Registro**, **Etichette**, **Banco di prova** e **Impostazioni**.
Le operazioni quotidiane si svolgono nella GUI; **Aggiorna** rilegge lo stato.
L'installazione della nuova build e del servizio è un passo umano successivo.
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
Nei campi protetti **Chiave del compartimento** e **Ripeti la chiave** servono
almeno 12 byte UTF-8. La chiave passa al worker
tramite stdin; non viene salvata in file, registro o portachiavi, né inserita
negli argomenti o nell'ambiente dei processi. Conservane una copia tua.

## Registro

Premi **Sorveglia una cartella…** e scegli una directory nel selettore del
Finder. Puoi scegliere anche una cartella senza cifrarla. **Cartelle sorvegliate**
mostra le richieste configurate; **Rimuovi** rimuove la richiesta senza modificare
i file. Lo stato distingue una richiesta salvata dalla conferma del demone:
soltanto un registro attivo può raccogliere gli eventi successivi.

Filtra con **Cartella**, **File o percorso**, **Processo o PID**, **Agente** e,
attivando **Intervallo**, **Da** e **A**. **Cerca** applica i filtri; la ricerca
del processo comprende anche l'app responsabile. L'agente può essere riconosciuto,
non agente o **Sconosciuto**: un valore sconosciuto non viene trasformato in certezza.

Seleziona una riga e premi **Apri dettaglio** per vedere tutti i metadati presenti:
fonte `paratia` o `eslogger`, PID, utente, app responsabile, cartelle interessate
e tipo di radice osservata, per esempio originale, montaggio o immagine cifrata.
La tabella mostra al massimo 2500 eventi; **Esporta CSV…** include tutti quelli
che corrispondono ai filtri. Un'apertura per lettura non prova una lettura dei
byte e ogni tentativo fallito non produce necessariamente un evento kernel.
Vedi [Registro degli accessi](registro-accessi.md).

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

Per installare il registro, apri la copia bootstrap dell'app preparata
manualmente in `/Library/Application Support/ParatiaBootstrap/Paratia.app`.
Nelle sue **Impostazioni**, **Installa il registro…** prepara il piano e
presenta **Autorizza con macOS**.
Prima del dialogo, Paratia verifica che questa copia, tutti i suoi antenati e
ogni file letto dal bootstrap siano di root, senza collegamenti simbolici,
scrittura per gruppo/altri o ACL che concedano scrittura. La copia deve avere
la stessa firma e lo stesso CDHash della build corrente.

I tre percorsi hanno ruoli distinti:

- `/Applications/Paratia.app`: app quotidiana e voce Accesso completo al disco;
  conserva i permessi attuali.
- `/Library/Application Support/ParatiaBootstrap/Paratia.app`: copia protetta
  da aprire per avviare il piano amministratore.
- `/Library/Application Support/Paratia/Paratia.app`: copia protetta del
  servizio installato, dentro la directory privata del servizio con modo `0700`.

Alla verifica del 10 ottobre 2026, gli antenati del bootstrap hanno permessi
Unix compatibili:
`/` e `/Library` sono `root:wheel 0755`, `/Library/Application Support` è
`root:admin 0755`. La preparazione riguarda soltanto la nuova directory
`ParatiaBootstrap` e la copia dell'app. Copiare la stessa build e cambiarne il
proprietario non cambia il CDHash: il permesso TCC dell'app quotidiana resta valido.

Chiudi tutte le copie di Paratia. Esegui personalmente nel Terminale questo
unico comando di preparazione; viene riportato qui senza essere eseguito:

```sh
sudo /bin/sh -c 'set -eu
[ ! -L "/Library/Application Support/ParatiaBootstrap" ]
[ -d "/Applications/Paratia.app" ]
[ ! -L "/Applications/Paratia.app" ]
/usr/bin/install -d -m 755 -o root -g wheel "/Library/Application Support/ParatiaBootstrap"
/bin/chmod -N "/Library/Application Support/ParatiaBootstrap"
paratia_bootstrap_stage=$(/usr/bin/mktemp -d "/Library/Application Support/ParatiaBootstrap/.prepara.XXXXXX")
/usr/bin/ditto --noacl "/Applications/Paratia.app" "$paratia_bootstrap_stage/Paratia.app"
/usr/bin/find "$paratia_bootstrap_stage/Paratia.app" ! -type d ! -type f -print > "$paratia_bootstrap_stage/percorsi-non-ordinari"
[ ! -s "$paratia_bootstrap_stage/percorsi-non-ordinari" ]
/usr/sbin/chown -R root:wheel "$paratia_bootstrap_stage/Paratia.app"
/bin/chmod -R go-w "$paratia_bootstrap_stage/Paratia.app"
/usr/bin/codesign --verify --deep --strict "$paratia_bootstrap_stage/Paratia.app"
[ ! -L "/Library/Application Support/ParatiaBootstrap/Paratia.app" ]
if [ -e "/Library/Application Support/ParatiaBootstrap/Paratia.app" ]; then
    /bin/mv "/Library/Application Support/ParatiaBootstrap/Paratia.app" "$paratia_bootstrap_stage/precedente.app"
fi
/bin/mv "$paratia_bootstrap_stage/Paratia.app" "/Library/Application Support/ParatiaBootstrap/Paratia.app"
/usr/bin/codesign --verify --deep --strict "/Library/Application Support/ParatiaBootstrap/Paratia.app"'
```

La preparazione usa una directory temporanea di root con modo `0700`, rifiuta
collegamenti e file speciali prima di cambiare proprietario e permessi, e verifica
la firma prima di pubblicare la copia. Un bootstrap precedente resta conservato
nella directory `.prepara` sotto `ParatiaBootstrap`. Apri la nuova copia dal
Finder soltanto se il comando termina senza errori, con codice di uscita `0`.

Il dialogo amministratore gestisce la password. L'installer copia il bundle
firmato in `/Library/Application Support/Paratia/Paratia.app`, protetto da root.
Il LaunchDaemon esegue il binario nativo di questa copia, che resta vivo e
avvia il raccoglitore Python come figlio.

Conclusa l'installazione, chiudi la copia bootstrap e riapri l'app quotidiana
in `/Applications/Paratia.app`. Qui **Apri Accesso completo al disco** porta
alle impostazioni privacy:
aggiungi e abilita **`/Applications/Paratia.app`**. Dopo ogni nuova build con
firma ad hoc, rimuovi la voce precedente e aggiungi di nuovo l'app installata;
aggiorna la copia bootstrap e reinstalla il registro per aggiornare la copia
del servizio. Non abilitare
Python 3.9. Il passaggio del permesso ai figli e la raccolta kernel devono
ancora essere verificati sulla macchina dopo questi clic.
**Verifica il registro** controlla le due catene presenti, senza attestare da sola
la copertura continua o una coda eliminata.

**Rivedi e collega gli hook…** mostra il piano prima di **Applica il piano**:
conserva le configurazioni esistenti e crea backup JSON. `SessionStart` richiede
la chiusura dei compartimenti all'avvio della sessione; riavvia le sessioni dopo
la configurazione. La fiducia Codex va approvata manualmente nella gestione hook
dell'app Codex. **Ripristina un backup…** ripristina soltanto una configurazione
ancora uguale a quella installata, preserva modifiche successive e crea un nuovo backup.

Il worker GUI usa Python Apple dei Command Line Tools, compatibile con 3.9,
in modalità isolata `-I -S`. Gli hook richiedono Python 3.11 o successivo:
il loro stato risolve il runtime disponibile e segnala una dipendenza mancante.

## Costruzione per il manutentore

Dal repository, con i Command Line Tools Apple disponibili:

```sh
python strumenti/build-app.py --render-fixtures
open -n build/Paratia.app --args --launch-check
~/.local/bin/installa-app build/Paratia.app
```

`--launch-check` apre la GUI e la chiude dopo quattro secondi. L'installazione
in `/Applications` è a carico del supervisore. Le immagini generate usano
fixture dichiarate sintetiche. La build firma
**ad hoc**, senza identità dal portachiavi, e non è notarizzata. Il percorso
amministratore locale usa l'API deprecata `AuthorizationExecuteWithPrivileges`,
limitata al piano fisso del registro e al runtime root protetto; non è stato eseguito.
