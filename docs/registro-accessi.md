# Registro degli accessi

Il registro conserva solo metadati. Non apre contenuti dei file o trascrizioni
e non conserva argomenti dei comandi o variabili d'ambiente. Distingue due sorgenti: le
operazioni dell'app (`paratia`) e gli eventi kernel osservati da `eslogger`.

## Eventi e limiti

Il demone sottoscrive `open`, `close`, `write`, `create`, `rename`, `unlink`,
`mount`, `unmount`, `mmap`, `truncate`, `lookup`; `exec`, `fork` ed `exit` servono
alla mappa dei processi. Non salva il JSON grezzo di eslogger: gli eventi exec
possono includere dati riservati negli argomenti e nell'ambiente.

Ogni evento conserva ora, percorso e destinazione quando presente, processo,
PID e pidversion, UID/utente, app responsabile quando identificabile, esito ES,
cartella interessata ed evidenza della classificazione agente. L'identità
`(pid, pidversion)` evita di attribuire un evento a un PID riutilizzato.

Il nome dell'agente deriva da executable/signing ID riconoscibili, non da una
prova autenticata dell'identità del fornitore. La discendenza tramite i token ES
può essere `true`, `false` o sconosciuta (`null`). Lo snapshot iniziale di `ps`
legge solo PID, PPID, UID e comm: senza pidversion può suggerire un candidato,
ma non produce una certezza di discendenza. Non vengono lette trascrizioni.

**ES non offre un evento per ogni lettura dei byte.** Una apertura con FREAD
significa apertura per lettura. Non prova che una lettura sia avvenuta, né ne
misura quantità o contenuto. `close.modified` non copre tutte le modifiche via
mmap: viene conservato anche `was_mapped_writable`, quando disponibile.

**ES non osserva ogni tentativo fallito.** La decisione di autorizzazione ES
non è il return code o errno della syscall. Un ENOENT su una cartella chiusa
non deve essere presentato come una notifica kernel garantita. Gli errori
riscontrati dalle operazioni dell'app e dagli accessi scriptati del banco sono
annotazioni della sorgente `paratia`, con esito/errno quando realmente misurati.

Apple specifica che [eslogger non è un'API stabile né un sostituto completo
del client nativo Endpoint Security](https://developer.apple.com/videos/play/wwdc2022/110345/).
L'adapter accetta schema_version 1; uno schema incompatibile ferma la raccolta
e produce un diagnostico, senza fingere che il registro sia attivo. I buchi di
seq_num/global_seq_num sono segnalati. Quando questi campi mancano, lo stato
indica che il rilevamento delle perdite non è disponibile. I diagnostici
ripetuti vengono aggregati per evitare crescita illimitata e feedback.

## Catena e confine root

`catena.py` estende il formato esistente di `fanale.annota`: ogni riga nomina
il digest della precedente. Un lock serializza gli append concorrenti; le
letture prendono un lock condiviso. Righe parziali e collegamenti simbolici
sono rifiutati. Una modifica interna rompe la verifica; il troncamento della
coda richiederebbe un checkpoint esterno per essere attestato.

Le operazioni dell'app sono in `~/.paratia/registro/catena.jsonl`, modificabile
da chi possiede quell'account. Il registro kernel è sotto
`/Library/Logs/Paratia/<uid>/`: file root con modo 0600 e ACL di sola lettura per
quel singolo utente. La directory comune concede soltanto attraversamento;
le directory degli utenti hanno modo 0700 e ACL di lettura/ricerca individuale.
Non viene concesso accesso al gruppo staff. Le ACL preesistenti dei percorsi
gestiti vengono rimosse prima di applicare quelle previste.

Il bundle firmato viene copiato in
`/Library/Application Support/Paratia/Paratia.app`, insieme ai tre moduli
del raccoglitore in `/Library/Application Support/Paratia`. Il LaunchDaemon
esegue `Contents/MacOS/Paratia --registro --uid <uid>`: lo stesso binario
nativo firmato dell'app, senza avviare la GUI. Questo processo resta vivo e
avvia Python come figlio. Il servizio non importa codice dal repo,
dalla home dell'utente o da una venv. Il runtime viene risolto e verificato,
comprese le ACL che potrebbero consentire modifiche:
si preferisce il Python Apple dei Command Line Tools sotto `/Library/Developer`,
con `-I -S`, così non vengono caricate personalizzazioni Python o site packages.
Il launcher `/usr/bin/python3` può risolvere Xcode sotto `/Applications`, il cui
antenato può essere scrivibile dal gruppo admin: non basta verificarne il nome.
L'installer rifiuta un runtime o librerie modificabili senza root; non modifica
i permessi globali di Xcode o Applications.

La provenienza del payload prima dell'installazione dipende dall'app che la
persona autorizza. Il dialogo amministratore non rende a prova di modifiche
preesistenti un'app posseduta dallo stesso UID. La protezione root descritta
vale per la copia installata; non viene promessa una protezione di bootstrap
equivalente a quella di una System Extension firmata.

Il demone legge i registri dell'utente ottenuto da `pwd`, senza importare codice
o accettare home/command arbitrary dal JSON. Apertura dei registri tramite
directory descriptor e O_NOFOLLOW, controllo del proprietario, limite 4 MiB,
allowlist dei campi, rifiuto di radici universali e di cartelle di altri utenti.
Originali, montaggi e recuperi appartengono all'utente; il bundle deve avere il
nome generato per quell'identificatore e, se presente, lo stesso proprietario.
Backup e residui plaintext sono sorvegliati solo nei percorsi previsti dalla
migrazione o dal recupero. I percorsi del collector sono sempre esclusi. Il bundle registra accessi al
cifrato, non prova accessi al testo in chiaro.

## Installazione e autorizzazioni ancora necessarie

`registro_installa.piano()` prepara gli argv e la plist senza installare nulla.
Il pulsante **Installa il registro** consegna quel piano al dialogo amministratore
nativo. La password viene gestita da macOS, mai dall'app o da un modello.
L'installer verifica la firma ad hoc e il marker del launcher, copia il bundle
senza symlink o hardlink, verifica che la copia abbia lo stesso CDHash e applica
proprietà/ACL. Prepara i tre moduli del raccoglitore da quella copia verificata.
Conserva bundle, moduli e plist precedenti fino al bootstrap; se questo fallisce,
tenta il ripristino. Non modifica TCC né il portachiavi.

Poi, in **Impostazioni di Sistema → Privacy e Sicurezza → Accesso completo al
disco**, aggiungi e abilita **`/Applications/Paratia.app`** con il pulsante `+`.
Dopo ogni nuova build ad hoc, rimuovi la voce precedente e aggiungi di nuovo
l'app installata; reinstalla il registro per aggiornare anche la copia protetta.
Non concedere l'Accesso completo al disco a Python 3.9: quel runtime esegue
anche altri programmi. Il vecchio servizio avviato direttamente da Python deve
essere reinstallato. `registro stato` indica `launch_mode`, `needs_reinstall`,
`fda_entry` e `fda_regrant_after_build`.

Le due copie dell'app mantengono la stessa firma verificata. Questa architettura
mantiene l'eseguibile dell'app come padre del raccoglitore; il riconoscimento
dell'identità da parte di TCC e il permesso a eslogger restano da verificare live.
Il servizio riprova con throttling dopo un errore; un heartbeat recente e sano
è necessario per considerare la raccolta attiva.

La preparazione e i test sintetici non attestano root, FDA, copertura live,
persistenza al riavvio o correttezza delle ACL installate: questi controlli
richiedono il clic umano e l'attivazione effettiva del servizio.

## Banco e API dell'app

La GUI offre **Sorveglia una cartella…**, elenco e rimozione delle richieste.
Lo stesso dalla CLI:

```sh
paratia registro sorveglia ~/Documenti/progetto
paratia registro sorveglianza
paratia registro elenco --cartella ~/Documenti/progetto --processo nome
paratia registro esporta --cartella ~/Documenti/progetto
paratia registro smetti ~/Documenti/progetto
```

`--cartella` accetta un ID oppure il percorso assoluto esatto di una cartella
configurata. Un percorso ambiguo richiede la scelta dell'ID. Sono disponibili
anche `--file`, `--agente true|false|unknown` oppure il nome dell'agente
(per esempio `--agente Codex`), `--da` e `--a`.

`sorveglia(id, percorso, nome)` registra una cartella plaintext nel file separato
`~/.paratia/registro/sorveglianza.json`; non la spaccia per un compartimento.
`rimuovi_sorveglianza(id)` elimina questa richiesta. Il demone rilegge entrambi
i registri ogni cinque secondi; `stato().watched_ids` permette al banco di
attendere che il percorso sia effettivamente configurato prima degli accessi.

`query(filters)` restituisce le due sorgenti con filtri `folder`, `file`,
`process`, `agent`, `since`, `until`; ogni riga mantiene i dettagli e la sorgente.
`export_csv(filters)` protegge i valori da formula injection quando il CSV è
aperto in un foglio di calcolo. `verifica()` controlla separatamente le due
catene. `stato()` distingue installazione, processo attivo, salute, necessità di
root/FDA, perdite e integrità del registro locale.

Verifica sintetica ripetibile, senza root o FDA:

```sh
python3 tests/test_registro.py
python3 tests/test_fanale.py
```

Copre segreti rimossi dai record, identità PID riutilizzate, discendenza incerta,
esiti ES senza errno inventati, buchi e schema incompatibile, filtro di rinomina
e collector, append concorrenti/manomissioni, query/CSV, registri ostili e
sorveglianza plaintext separata. La preparazione dell'installer viene controllata
senza invocare il percorso privilegiato.
