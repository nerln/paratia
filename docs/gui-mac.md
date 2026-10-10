# Paratia per Mac

L'app nativa richiede macOS 13 o successivo. Le cinque sezioni sono
**Cartelle**, **Registro**, **Etichette**, **Banco di prova** e **Impostazioni**.
Le operazioni quotidiane si svolgono nella GUI; **Aggiorna** rilegge lo stato.
L'installazione della nuova build e del servizio è un passo umano successivo.
Lo stato delle verifiche è in [stato di ottobre 2026](stato-2026-10.md).

## Cartelle

Premi **Proteggi una cartella**, scegli la fonte e una destinazione sul disco
esterno. Paratia copia e verifica i dati, prova la chiusura e la riapertura,
poi rimuove l'originale. Chiudi prima i documenti che possono modificare la fonte.
La scheda mostra stato, percorso, immagine cifrata, numero di file e dimensione.
Usa **Apri…**, **Mostra nel Finder**, **Chiudi** o **Chiudi tutte**; per una
migrazione incompleta sono disponibili **Recupera la fonte** e **Annulla migrazione**.

**Chiusura dopo N min** imposta da 1 a 1440 minuti. Se il montaggio è occupato,
la chiusura ritenta senza forzarla. Nei campi protetti **Chiave del compartimento**
e **Ripeti la chiave** servono almeno 12 byte UTF-8. La chiave passa al worker
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
misurato e riscontri kernel; `mdls` può usare la cache. **Prove precedenti**
conserva lo storico leggibile; **Dettagli dello storico**, **Esporta JSON…**
e **Esporta CSV…** mantengono i dati completi. La prova live è ancora
**non eseguita**: [workflow e stato del banco](banco-folder-test.md).

## Impostazioni

**Installa il registro…** prepara il piano e presenta **Autorizza con macOS**.
Il dialogo amministratore gestisce la password. L'installer copia il bundle
firmato in `/Library/Application Support/Paratia/Paratia.app`, protetto da root.
Il LaunchDaemon esegue il binario nativo di questa copia, che resta vivo e
avvia il raccoglitore Python come figlio.

Poi **Apri Accesso completo al disco** porta alle impostazioni privacy:
aggiungi e abilita **`/Applications/Paratia.app`**. Dopo ogni nuova build con
firma ad hoc, rimuovi la voce precedente e aggiungi di nuovo l'app installata;
reinstalla anche il registro per aggiornare la copia protetta. Non abilitare
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
