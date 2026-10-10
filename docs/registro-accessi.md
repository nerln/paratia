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

Il bootstrap amministratore usa una copia separata in
`/Library/Application Support/ParatiaBootstrap/Paratia.app`. Verifica il bundle,
ogni suo file e tutti gli antenati: proprietario root, nessuna scrittura per
gruppo/altri o tramite ACL, nessun collegamento simbolico. Verifica anche la
firma e le risorse sigillate e ripete il controllo subito prima del dialogo.
La copia normale in `/Applications/Paratia.app` resta l'app d'uso quotidiano e
la voce FDA; non si richiede di cambiare i permessi globali di `/Applications`.
La copia di bootstrap è distinta da quella del servizio, sotto
`/Library/Application Support/Paratia`, il cui parent è protetto con modo 0700.

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

Dopo aver installato l'app normale in `/Applications`, chiudi tutte le copie
di Paratia e prepara personalmente nel Terminale la copia di bootstrap:

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

Il comando non modifica `/Applications` o i suoi permessi. Prepara la copia in
un'area root con modo 0700, rifiuta link e file speciali prima di cambiare
proprietario/permessi e verifica la firma prima di pubblicarla. Un bootstrap
precedente resta nella cartella `.prepara` protetta. Solo se il comando termina
senza errori (codice 0), apri
`/Library/Application Support/ParatiaBootstrap/Paratia.app` **dal Finder** e usa
**Installa il registro**. Anche i suoi antenati devono superare il controllo
root e ACL; se il controllo fallisce, il dialogo resta bloccato.

La copia conserva la firma dell'app normale. Cambiare proprietario e permessi
non modifica il CDHash; il solo `chown` non cambia l'identità firmata. Il
riconoscimento TCC fra le copie resta da verificare live. Dopo ogni nuova build,
aggiorna anche la copia di bootstrap prima di reinstallare il servizio.

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

Le copie normale, di bootstrap e del servizio mantengono la stessa firma
verificata. Questa architettura mantiene l'eseguibile dell'app come padre del raccoglitore; il riconoscimento
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
configurata, con normalizzazione di slash, alias e Unicode NFC/NFD. Un percorso
sconosciuto o associato a più ID produce un errore; nel secondo caso scegli
l'ID dall'elenco. Sono disponibili
anche `--file`, `--agente true|false|unknown` oppure il nome dell'agente
(per esempio `--agente Codex`), `--da` e `--a`.

`sorveglia(id, percorso, nome)` registra una cartella plaintext nel file separato
`~/.paratia/registro/sorveglianza.json`; non la spaccia per un compartimento.
La cartella deve esistere ed essere di proprietà dell'utente. Ripetere la
richiesta per lo stesso percorso normalizzato conserva l'ID e il nome esistenti e
restituisce `riutilizzata: true`, anche se viene passato `--nome X`. La risposta
include `nome` con il valore effettivo e il messaggio «Sorveglianza esistente
riutilizzata: ID e nome conservati.». `rimuovi_sorveglianza(id)` elimina la
richiesta; un ID sconosciuto produce un errore.

`configurata: true` indica una richiesta salvata. `sorvegliata` e
`raccolta_attiva` diventano vere soltanto con raccoglitore attivo e sano e ID
confermato in `stato().watched_ids`. Il demone rilegge i registri ogni cinque
secondi; il banco attende questa conferma prima degli accessi e conserva una
richiesta dell'utente eventualmente riutilizzata. La conferma non prova la
copertura di ogni accesso. Con raccolta ferma o non sana, `registro elenco` ed
`esporta` avvisano su stderr anche se il risultato è vuoto; stdout conserva il
formato JSON o CSV e gli eventi già presenti restano consultabili.

`query(filters)` restituisce le due sorgenti con filtri `folder`, `file`,
`process`, `agent`, `since`, `until`; ogni riga mantiene i dettagli e la sorgente.
Il filtro `folder` accetta un ID o un percorso assoluto esatto configurato in
sorveglianza o fra le cartelle protette. `risolvi_cartella()` converte quel
percorso nell'ID con gli stessi controlli usati dalla CLI; il worker applica
questa risoluzione sia a `registro.query` sia a `registro.export_csv`.
Percorsi sconosciuti o ambigui producono `ValueError`, anziché un risultato
vuoto; la GUI riceve un errore e non crea il CSV. Gli ID consentono di consultare
eventi storici anche dopo la rimozione della configurazione.

Un filtro `file` assoluto seleziona quel percorso o i suoi discendenti:
`/a/b` comprende `/a/b/x`, ma esclude `/a/bc/x`. Vengono normalizzati slash,
alias di percorso e Unicode NFC/NFD. Un filtro non assoluto cerca liberamente
nel nome/percorso con normalizzazione Unicode e `casefold`, senza distinzione
fra maiuscole e minuscole.

`export_csv(filters)` protegge i valori da formula injection quando il CSV è
aperto in un foglio di calcolo. `verifica()` controlla separatamente le due
catene. `stato()` distingue installazione, processo attivo, salute, necessità di
root/FDA, perdite e integrità del registro locale.

I nuovi timestamp locali usano l'offset ISO con i due punti, per esempio
`+02:00`. La lettura accetta anche gli offset storici `+0200` e `Z` con Python
3.9, senza riscrivere le righe o alterare la catena di hash.

Nel [banco di prova](banco-folder-test.md), `mdls` è informativo: Spotlight può
usare una cache o non indicizzare un volume montato. Il suo risultato non
determina l'esito della fase né garantisce un accesso osservabile dal kernel.

Verifica sintetica ripetibile, senza root o FDA:

```sh
python3 tests/test_registro.py
python3 tests/test_fanale.py
/Library/Developer/CommandLineTools/usr/bin/python3 -I -S -B strumenti/prova-registro-python39.py
```

Copre segreti rimossi dai record, identità PID riutilizzate, discendenza incerta,
esiti ES senza errno inventati, buchi e schema incompatibile, filtro di rinomina
e collector, append concorrenti/manomissioni, query/CSV, registri ostili e
sorveglianza plaintext separata. La preparazione dell'installer viene controllata
senza invocare il percorso privilegiato. La prova di fumo Python 3.9 usa eventi
locali veri, query/CSV del worker e il banco in una home temporanea; salute kernel
e immagini disco sono simulate, senza CLI degli agenti o Desktop personale.
Questa prova e `strumenti/prova-banco-temporaneo.py` rispettano `TMPDIR` e
accettano soltanto la propria fixture al suo interno; anche il Desktop sintetico
rimane nella home temporanea.
