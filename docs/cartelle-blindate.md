# Cartelle blindate

Una cartella protetta è un compartimento AES-256 con una passphrase propria.
Sbloccare il disco che contiene lo sparsebundle non apre il compartimento.
Da chiuso, il percorso originale è un punto di montaggio vuoto: i file stanno
solo nell'immagine cifrata. Da aperto, sono leggibili dai processi dell'utente.

La destinazione va scelta su un disco esterno fisico, anche in una sua
sottocartella. Prima di chiedere la chiave, GUI e CLI risalgono dal volume
al disco intero: per APFS seguono gli store fisici e il loro disco padre;
per exFAT e altri filesystem seguono direttamente il disco padre. Un volume
senza `VirtualOrPhysical` o un contenitore APFS virtuale non causano un rifiuto
se gli store appartengono a dischi esterni fisici. Dischi interni e immagini disco, incluso un volume
con protocollo `Disk Image`, vengono rifiutati. Non sono ammessi percorsi
sincronizzati con il cloud, destinazioni annidate nella fonte, collegamenti
simbolici, hard link, file speciali o volumi montati dentro la fonte.

## Migrazione

La migrazione registra numero di file e byte e verifica gli hash dei dati,
le modalità di accesso, gli attributi estesi, le ACL e i resource fork macOS.
Un manifest per il recupero resta dentro il compartimento cifrato.
Chiude l'immagine, la riapre con la stessa chiave e verifica di nuovo la copia.
Solo dopo una seconda chiusura confermata rimuove l'originale. La fonte deve
restare ferma durante l'operazione: chiudi i documenti e le applicazioni che
possono modificarla.

Un errore lascia uno stato di migrazione incompleta con le informazioni per
il recupero. Il gate rifiuta le sessioni anche quando resta una copia in chiaro
da sistemare. Migrazione, timer e chiusura di sessione non smontano un volume
occupato con la forza. La GUI offre **Forza chiusura…** per una cartella aperta
o un montaggio temporaneo di una migrazione incompleta, soltanto dopo conferma
esplicita del rischio di perdere modifiche non salvate. Chiudere il montaggio
temporaneo non completa la migrazione e non elimina le copie in chiaro:
restano necessari **Recupera la fonte** o **Annulla migrazione**.

`annulla_migrazione` conserva l'immagine e toglie la registrazione soltanto
quando la fonte è ancora integra. `recupera` richiede la chiave e un'immagine
già verificata; ricostruisce la fonte senza sostituire modifiche dell'utente.
Un recupero interrotto mantiene visibile anche la cartella temporanea in chiaro
e rifiuta un secondo tentativo finché quella copia non è stata sistemata.

La rimozione dell'originale non elimina eventuali copie già presenti in backup,
snapshot APFS, sincronizzazioni o altri programmi. Non è una cancellazione
sicura dei blocchi fisici di un SSD.

## Chiave e chiusura

La chiave passa al comando di sistema soltanto attraverso un pipe privato su
stdin. Non viene messa negli argomenti, nell'ambiente, nei metadati del registro
o in un file. L'app la richiede con un campo sicuro. Non usa il portachiavi.
Una passphrase distinta da quella del disco è una scelta dell'utente: Paratia
non legge la chiave del disco per confrontarle.

Una chiave sbagliata è distinta dagli altri errori disco: la GUI invita a
reinserirla, il worker restituisce `wrong_key` e la CLI restituisce un errore
JSON con `errore: "chiave_errata"`. Una verifica senza montaggio distingue la
chiave prima dell'apertura; i testi italiano/inglese/spagnolo sono un ripiego.
Gli errori non riportano gli stream del
comando di sistema né la chiave.

Ogni apertura avvia un timer da 1 a 1440 minuti. Il timer identifica quella
specifica apertura, quindi un timer vecchio non chiude una successiva
riapertura. Una chiusura manuale riuscita invalida il token del timer, che
controlla il registro ogni 0,25 secondi e termina senza segnali a PID.
Se il volume è occupato, il timer resta attivo e ritenta la chiusura senza
forzarla: chiudi l'app o il terminale aperto dentro e riprova. Il tempo impostato
non è una garanzia di chiusura al secondo in presenza di documenti
ancora aperti.

Aprire una cartella già aperta lo segnala prima della richiesta della chiave e
non avvia un secondo timer: anche `apri --minutes` precisa che i minuti e la
scadenza già impostati restano invariati. Un disco scollegato viene segnalato
prima di chiedere la chiave. Chiudere una cartella già chiusa restituisce il suo
stato senza scrivere un evento duplicato.

L'hook esistente continua a rifiutare ogni chiamata mentre un compartimento è
montato. Lo stesso file gestisce `SessionStart` per chiudere i compartimenti:
deve essere collegato a questo evento nell'harness. Un hook non installato
non protegge quella sessione. Il registro delle cartelle e l'hook sono
modificabili da processi con lo stesso UID; la cifratura da chiuso resta il
confine che non dipende dalla cooperazione dell'agente.

Per installare il registro, la [guida GUI](gui-mac.md#impostazioni) descrive la
copia bootstrap protetta in `/Library/Application Support/ParatiaBootstrap/Paratia.app`
e la copia separata del servizio. L'app quotidiana e la voce Accesso completo
al disco restano `/Applications/Paratia.app`.

## Prova nativa

`tests/prova_cifratura_macos.py` esegue una prova macOS separata con dati
sintetici e una chiave casuale temporanea, soltanto in memoria. Controlla
chiusura, assenza del marcatore nei band, rifiuto della chiave errata e
riapertura. Richiede l'accesso al servizio di immagini disco; i test ordinari
usano un backend finto e non montano volumi.

`tests/prova_cartelle_macos.py` collauda l'intera migrazione con file sintetici,
un attributo esteso e un resource fork. Per questa sola prova usa una
destinazione temporanea interna; il vincolo produttivo del disco esterno è
verificato separatamente. La prova termina richiusa e rimuove i dati temporanei.
