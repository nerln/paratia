# Registro degli accessi

Il registro conserva solo metadati. Non apre contenuti dei file o trascrizioni
e non conserva argomenti dei comandi o variabili d'ambiente. Distingue due sorgenti: le
operazioni dell'app (`paratia`) e gli eventi kernel osservati da `eslogger`.

## Eventi e limiti

Il demone sottoscrive `open`, `write`, `create`, `rename`, `unlink`, `truncate`;
`exec`, `fork` ed `exit` servono alla mappa dei processi. Non salva il JSON grezzo
di eslogger: gli eventi exec possono includere dati riservati negli argomenti e
nell'ambiente.

`open` dice chi ha aperto un percorso; `write`, `create`, `rename`, `unlink` e
`truncate` dicono chi lo ha modificato. Il registro non ha più un evento di
chiusura: il flag `close.modified` e `was_mapped_writable` non arrivano dal
raccoglitore attuale.

`close`, `mount`, `unmount`, `lookup` e `mmap` sono esclusi dalla sottoscrizione
predefinita: il traffico globale aveva provocato CPU elevata, perdite e minuti di
ritardo nella misura live del 14 ottobre (con la sottoscrizione precedente eslogger
arrivava in media al 70% di CPU). Il parser li riconosce per le fixture e i formati
storici, ma non c'è un'opzione per riattivarli. Un mapping ereditato senza nuova
apertura non produce quindi un evento `mmap` nel nuovo registro.

Conseguenze da tenere presenti: le scritture fatte solo tramite `mmap` non
risultano più come modifiche nel registro kernel. Montaggi e smontaggi non
compaiono nel registro kernel; l'apertura e la chiusura di una cartella protetta
restano nel registro di Paratia come `cartella-aperta` e `cartella-chiusa`.

Il raccoglitore cerca le radici sorvegliate nei byte prima di `json.loads`,
includendo `/System/Volumes/Data`, alias `/private`, Unicode e escape JSON;
i candidati incerti passano al parser completo. Le notifiche di discendenza
restano sempre elaborate. Se una radice o il suo genitore contiene caratteri
di controllo, virgolette, backslash o una codifica incerta, tutte le righe
passano al parser completo: gli escape brevi JSON non devono nascondere accessi.
Le sequenze delle righe scartate intenzionalmente
continuano ad aggiornare il rilevamento dei buchi: il filtro non deve simulare
perdite ES. Le righe grezze e i campi riservati non vengono salvati.
I nomi degli account sono uno snapshot di sessione in una cache limitata a
256 UID, inclusi gli account sconosciuti: eventuali rinomine si riflettono
al riavvio del servizio. L'UID numerico e l'identità PID/pidversion restano
quelli dell'evento.

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
misura quantità o contenuto. Le modifiche sono quelle di `write`, `create`,
`rename`, `unlink` e `truncate`; non coprono le modifiche solo via mmap, perché
la sottoscrizione non include più `close`, che le riportava in parte con
`modified` e `was_mapped_writable`. Le righe storiche con quei campi restano leggibili.

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
`/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app`. Verifica il bundle,
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
Sui volumi con `MNT_IGNORE_OWNERSHIP`, rilevato nei flag reali di `statfs`,
il proprietario apparente restituito da `stat` non dimostra la proprietà.
La richiesta deve provenire dal file dell'utente già verificato, senza
scrittura gruppo/altri o ACL di scrittura. Si accetta la cartella soltanto
su un volume esterno fisico e non di sistema, risalendo tutti gli store APFS.
La stessa regola vale per cartelle protette, bundle e recuperi sulla SSD.
Questa scelta autorizza il percorso selezionato dall'utente; non dimostra chi
possiede i dati su un disco che ignora i proprietari. I controlli di radice,
symlink e provenienza restano necessari. I probe del volume sono condivisi
fra le voci e i poll della sessione: il risultato positivo resta in cache
soltanto con identità kernel del volume invariata, controllata a ogni uso
con statfs, fsid, sorgente, flag e radice del montaggio. Identità cambiate
o volumi non più osservati invalidano la cache. Le chiamate diskutil hanno
un timeout di tre secondi ciascuna, senza dividere un secondo fra più chiamate.
Durante i poll un solo worker valida la configurazione, mentre il filo che
legge eslogger continua a drenare lo stream; non ci sono probe sovrapposti.

Ogni voce è validata separatamente. Una voce rifiutata viene esclusa subito,
mentre le altre continuano a essere sorvegliate. `watch_status` riporta ID,
`confirmed` o `rejected`, codice e motivo fisso; un ID non valido viene
anonimizzato. Anche una configurazione interamente illeggibile è segnalata,
senza mantenere silenziosamente autorizzazioni precedenti di quel file.
ID duplicati fra i due file sono rifiutati. CLI e GUI distinguono richiesta
salvata, conferma e «rifiutata dal raccoglitore: …».

Una sorveglianza già confermata non viene esclusa per una breve assenza del
percorso o un timeout di verifica del volume. Occorrono stesso ID, origine,
tipo, genitore e identità kernel, più JSON ancora attendibile e assenza di
symlink. Resta confermata con `warning_code` e messaggio fisso; il daemon
annota «cartella assente» o «verifica volume in ritardo». Nuove voci assenti,
cambi di percorso o volume, rifiuti espliciti e configurazioni non attendibili
restano esclusi. `configuration_token` lega la conferma all'ID e al percorso
senza pubblicare il percorso nel report: un vecchio ACK non rende attiva
una nuova cartella assente con lo stesso ID. GUI ed elenco mostrano l'avviso
della voce confermata; questi avvisi transitori non spengono la raccolta.
Backup e residui plaintext sono sorvegliati solo nei percorsi previsti dalla
migrazione o dal recupero. I percorsi del collector sono sempre esclusi. Il bundle registra accessi al
cifrato, non prova accessi al testo in chiaro.

## Installazione e aggiornamento

Dopo aver installato l'app normale in `/Applications`, chiudi tutte le copie
di Paratia e prepara personalmente nel Terminale la copia di bootstrap. Il comando vigente è nella [guida GUI, sezione Impostazioni](gui-mac.md#impostazioni): copialo da lì.

Il comando non modifica `/Applications` o i suoi permessi. Prepara la copia in
un'area root con modo 0700, rifiuta link e file speciali prima di cambiare
proprietario/permessi e verifica la firma prima e dopo la pubblicazione.
A copia verificata elimina le cartelle root `.prepara.*` e l'app del vecchio
percorso `ParatiaBootstrap`; il nuovo percorso `.noindex` mantiene la protezione
root e viene escluso da Spotlight. Solo se il comando termina
senza errori (codice 0), apri
`/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app` **dal Finder** e usa
**Installa il registro**. Anche i suoi antenati devono superare il controllo
root e ACL; se il controllo fallisce, il dialogo resta bloccato.

La copia conserva la firma dell'app normale. Cambiare proprietario e permessi
non modifica il CDHash; il solo `chown` non cambia l'identità firmata. Il
riconoscimento TCC e gli eventi kernel sono stati osservati dal supervisore
il 14 ottobre sul giro 4 installato. Dopo ogni nuova build, aggiorna anche la
copia di bootstrap prima di reinstallare il servizio e ripeti la verifica.

`registro_installa.piano()` prepara gli argv e la plist senza installare nulla.
Il pulsante **Installa il registro** consegna quel piano al dialogo amministratore
nativo. La password viene gestita da macOS, mai dall'app o da un modello.
L'installer verifica la firma ad hoc e il marker del launcher, copia il bundle
senza symlink o hardlink, verifica che la copia abbia lo stesso CDHash e applica
proprietà/ACL. Prepara i tre moduli del raccoglitore da quella copia verificata.
Conserva bundle, moduli e plist precedenti fino al bootstrap; se questo fallisce,
tenta il ripristino. Dopo ogni `bootout` attende, per un massimo di otto secondi,
che `launchctl print` non trovi più il servizio. Il bootstrap ha fino a tre
tentativi per gli errori di corsa 5/37, con pause crescenti. Il ripristino usa
la stessa attesa e gli stessi tentativi; un suo fallimento è segnalato e i
backup necessari restano disponibili. Non modifica TCC né il portachiavi.

L'installer restituisce sempre JSON con `installed`, `error_code`, `message`
e `launchctl_errors` (operazione, codice, stderr ridotto). La GUI mostra il
messaggio e il codice anche se il processo termina con errore. Gli stderr sono
limitati a 512 caratteri di diagnostica riconosciuta: percorsi e testo arbitrario
non vengono copiati. `service_stop_timeout`, `bootstrap_failed` e
`rollback_bootstrap_failed` distinguono rimozione lenta, nuovo bootstrap fallito
e impossibilità di riavviare il vecchio servizio; non viene dichiarato un
ripristino riuscito quando manca la conferma.

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
dell'identità da parte di TCC e il permesso a eslogger sono stati osservati
sulla build pubblicata; vanno nuovamente verificati sulla nuova build.
Il servizio riprova con throttling dopo un errore; un heartbeat recente e sano
è necessario per considerare la raccolta attiva.

Il daemon pubblica `installed_cdhash`; il worker legge l'identità di
`/Applications/Paratia.app` tramite `codesign -d`, senza firmare o accedere
al portachiavi. `build_comparison` distingue `equal`, `different` e
`unavailable`. Una build diversa o un vecchio servizio senza identità porta
`needs_update: true`: la GUI mostra `update_message` e sei `update_steps`
numerati nelle Impostazioni. Un'identità mancante non viene presentata come
un confronto riuscito. I passi minimi sono nella sezione
[Aggiornare il registro dopo questo giro](stato-2026-10.md#aggiornare-il-registro-dopo-questo-giro).

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
La cartella deve esistere ed essere di proprietà dell'utente, oppure soddisfare
la regola documentata per volumi esterni `noowners`. Ripetere la
richiesta per lo stesso percorso normalizzato conserva l'ID e restituisce
`riutilizzata: true`. Un nome esplicito non vuoto, per esempio `--nome Nuovo`,
rinomina la richiesta e restituisce `rinominata: true` e `nome` effettivo.
Senza nome esplicito, il nome precedente resta invariato: GUI e banco usano
questa forma. Non si può aggiungere una sorveglianza separata sul percorso
di montaggio di una cartella protetta: seleziona l'ID già presente nel Registro.
Il banco riusa direttamente quell'ID nelle prove successive.
`rimuovi_sorveglianza(id)` elimina la
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
Percorsi sconosciuti o ambigui producono `ErroreRegistro`, sottoclasse di
`ValueError`, con codici `folder_not_configured` e `folder_ambiguous`, anziché
un risultato vuoto. La GUI riceve il messaggio specifico e non crea il CSV;
`protected_folder_watch` spiega il rifiuto di una sorveglianza separata di
cartella protetta. Gli ID consentono di consultare
eventi storici anche dopo la rimozione della configurazione.

Le risposte worker di query ed export aggiungono `kernel_active` e
`kernel_collection`. La vista Registro mostra raccolta attiva, inattiva o da
verificare accanto al conteggio, anche a **0 eventi**. Attiva richiede processo
e salute correnti, FDA senza necessità pendenti e schema non dichiarato
incompatibile; con filtro cartella serve anche l'ID confermato in `watched_ids`.
I dettagli mantengono la distinzione fra stato del servizio e ACK e dichiarano
`coverage_guaranteed: false`: non provano la copertura di ogni accesso.

Un filtro `file` assoluto seleziona quel percorso o i suoi discendenti:
`/a/b` comprende `/a/b/x`, ma esclude `/a/bc/x`. Vengono normalizzati slash,
alias di percorso e Unicode NFC/NFD. Un filtro non assoluto cerca liberamente
nel nome/percorso con normalizzazione Unicode e `casefold`, senza distinzione
fra maiuscole e minuscole.

`export_csv(filters)` protegge i valori da formula injection quando il CSV è
aperto in un foglio di calcolo. `verifica()` controlla separatamente le due
catene. `stato()` distingue installazione, processo attivo, salute, necessità di
root/FDA, perdite e integrità del registro locale.

Lo stato include `event_lag_seconds` (timestamp dell'ultimo evento rispetto
alla sua ricezione), `last_event_received_at`, `last_event_age_seconds`
(tempo senza nuove righe), `lines_per_second` e contatori di righe ricevute,
prefiltrate e decodificate. Il silenzio non viene classificato da solo come
ritardo. Una latenza osservata oltre due secondi, eventi persi, voci rifiutate,
assenza di cartelle confermate e altri impedimenti sono spiegati in
`health_reasons`. Stato, metriche e ACK scaduti non dimostrano raccolta corrente.
Le perdite contate da eslogger restano nel totale `dropped_events` per tutta la
sessione del raccoglitore. Il motivo `dropped_events` e `healthy: false` valgono
soltanto per i dieci minuti dopo l'ultima perdita osservata (`last_dropped_at`);
poi lo stato torna sano, salvo altri motivi. Una perdita con timestamp assente,
non valido o più di un minuto nel futuro non produce un avviso permanente.
Una sequenza ripartita da capo (`sequenza-riavviata`) non è contata come perdita e
resta un impedimento per la sessione. Query ed export del worker includono questi
dettagli in `kernel_collection`.
Le frazioni di secondo fino a nove cifre e gli offset compatti sono
normalizzati anche per Python 3.9; la precisione è troncata ai microsecondi.
Aggiorna invalida lo stato della ricerca precedente preservando eventi e
conteggio: ripetere Cerca per rinnovare i dettagli di quella ricerca.

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

Benchmark del solo trattamento Python, senza eslogger, root, FDA o log reali:

```sh
/Library/Developer/CommandLineTools/usr/bin/python3 -I -S -B strumenti/prova-registro-throughput.py --lines 50000 --repeats 3
```

Confronta decodifica completa e prefilter sullo stesso normalizzatore e sulle
stesse righe sintetiche; il sink conta i record senza I/O. Riporta mediane di
righe/s, secondi CPU e microsecondi CPU per riga. La stima CPU a un input
ipotetico non è una misura live: il limite complessivo sotto il 10% a riposo
e il ritardo sotto due secondi richiedono la nuova installazione e misura.

## Rotte di paranco

`paratia registro rotte-paranco` legge il file delle rotte di paranco e propone
quali cartelle sorvegliare. Il file è `~/Library/Application Support/paranco/routes.json`.
Il comando lo apre in sola lettura con il lettore del registro: deve appartenere
all'utente, non deve essere scrivibile da gruppo e altri, non può essere un
collegamento simbolico e non può superare 4 MiB. Non importa né lancia codice di
paranco e non scrive mai nel file.

Se il file non esiste, il comando risponde con `paranco_presente: false`, non
propone nulla e termina con codice 0. Se il file non è leggibile o non è una
lista, mostra un messaggio fisso e non propone nulla. Se la configurazione delle
cartelle o delle sorveglianze di paratia non è leggibile, il comando si ferma con
errore e non propone nulla.

Il comando considera al massimo sedici rotte, e solo le voci che sono oggetti: le
altre sono contate in `voci_ignorate`. Di ogni rotta usa soltanto `name`, `enabled`,
`destination` e `sourceID`. Il nome perde i caratteri di controllo e di formattazione,
per esempio i segni che invertono la direzione del testo, e i surrogati isolati; si
tronca a 64 caratteri. Se la rotta non ha un nome, il nome è quello della cartella,
con la stessa pulizia. La destinazione deve essere un percorso `file://` assoluto,
senza `..`, e codificabile in UTF-8. Nel testo stampato, un percorso con caratteri di
controllo o di formattazione mostra quei caratteri come `\uXXXX`. Con `--esegui` la
cartella viene configurata con il suo percorso reale.

Ogni destinazione ha uno stato:

- `da-aggiungere`: cartella esistente, dentro la tua cartella utente, senza
  conflitti e non ancora sorvegliata. Con `--esegui` viene configurata.
- `gia-sorvegliata`: è già nel registro delle sorveglianze. Il comando non la tocca.
- `conflitto`: la cartella è protetta da paratia, sta dentro una cartella protetta
  o sta dentro un punto di montaggio. Anche una cartella che la configurazione
  rifiuta conta come protetta. Da chiusa una cartella protetta è una directory vuota
  sul disco interno, e paranco ci scriverebbe in chiaro.
- `rifiutata`: la destinazione non è valida, è fuori dalla tua cartella utente, è
  la cartella utente stessa, contiene un collegamento simbolico, o non esiste
  ancora. Una cartella mancante va creata: paranco la crea al primo sollevamento.
  Se i permessi non fanno vedere il percorso, il comando non può dire se esiste e
  lo rifiuta con quel motivo.
- `disabilitata`: `enabled` non è `true`. La rotta non viene proposta.

Quando `routes.json` esiste, il piano propone anche la cartella
`~/Library/Application Support/paranco`, con il nome `paranco: rotte e log`, se
non è già sorvegliata. Così si vede chi riscrive `routes.json`.

Con `--esegui` il comando configura soltanto le proposte `da-aggiungere`, una per
una, con un ID nuovo. Non rimuove sorveglianze e non cambia i nomi di quelle già
presenti. Il comando rifiuta `--esegui` in una sessione agente, prima di scrivere
qualunque cosa, perché la decisione spetta a una persona. Il controllo legge le
variabili d'ambiente degli agenti: è una barriera di cortesia, non un confine,
come nel resto di paratia. Una cartella configurata non è ancora raccolta attiva:
il raccoglitore la conferma soltanto dopo.

Negli esempi, `~/.scriba/inbox` è la cartella in cui scrive scriba, un altro programma
dello stesso autore.

Esempi:

```sh
paratia registro rotte-paranco
paratia registro rotte-paranco --esegui
paratia registro elenco --cartella ~/.scriba/inbox --agente true
paratia registro elenco --cartella "$HOME/Library/Application Support/paranco" --file routes.json
```

Il filtro `--file routes.json` è relativo. paranco riscrive il file con un
`.part` e poi lo rinomina, e il filtro relativo raccoglie entrambi i nomi.

Limiti:

- `routes.json` è un file che può riscrivere chiunque giri come te, agenti compresi.
  Il piano è un aiuto per configurare, non un confine, come le etichette.
- Il registro mostra dopo, non impedisce. Se un agente cambia la destinazione di
  una rotta, lo vedi nel registro, ma il registro non blocca la scrittura.
- Un evento `open` non prova che i byte siano stati letti.
- Atteso e non ancora misurato: se l'agente launchd di paranco è installato, paranco
  apre `routes.json` e la destinazione ogni cinque minuti. Anche scriba o altri
  processi possono aprire la destinazione. Sono eventi normali, e si separano con
  `--processo`.
- La cartella sorgente dei Memo Vocali non si sorveglia: produce rumore e non dà
  valore.
- Non puntare mai una rotta di paranco a una cartella protetta da paratia. Il
  comando lo segnala come `conflitto`.
- L'Accesso completo al disco di paratia, per eslogger, e quello di paranco, per
  leggere i Memo Vocali, sono due voci distinte nell'elenco di macOS. Una build ad
  hoc nuova riguarda soltanto la sua app.

Il test sintetico `tests/test_rotte_paranco.py` copre il file assente, le rotte
disattivate, le destinazioni rifiutate, i nomi ripuliti, i file malformati, il
limite di sedici voci, un `routes.json` come collegamento simbolico, l'invarianza
del file, due passate di `--esegui`, i conflitti con cartelle protette e punti di
montaggio simulati, e il rifiuto in sessione agente. Copre anche i caratteri di
formattazione nel nome e nella cartella di ripiego, i surrogati isolati, una cartella
senza permessi, un JSON molto annidato, il conflitto che prevale sulla convalida, e le configurazioni di cartelle o
sorveglianze illeggibili, rotte o scrivibili dal gruppo: in quei casi il comando si
ferma con errore e non scrive nulla. Il test usa una home temporanea e non legge la
home reale.
