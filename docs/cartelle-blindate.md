# Cartelle blindate

Una cartella protetta è un compartimento AES-256 con una passphrase propria.
Sbloccare il disco che contiene lo sparsebundle non apre il compartimento.
Da chiuso, il percorso originale è un punto di montaggio vuoto: i file stanno
solo nell'immagine cifrata. Da aperto, sono leggibili dai processi dell'utente.

La destinazione va scelta su un disco esterno fisico. Non sono ammessi percorsi
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
da sistemare. Un volume occupato non viene smontato con la forza.

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

Ogni apertura avvia un timer da 1 a 1440 minuti. Il timer identifica quella
specifica apertura, quindi un timer vecchio non chiude una successiva
riapertura. Se il volume è occupato, ritenta la chiusura senza forzarla: il tempo
impostato non è una garanzia di chiusura al secondo in presenza di documenti
ancora aperti.

L'hook esistente continua a rifiutare ogni chiamata mentre un compartimento è
montato. Lo stesso file gestisce `SessionStart` per chiudere i compartimenti:
deve essere collegato a questo evento nell'harness. Un hook non installato
non protegge quella sessione. Il registro delle cartelle e l'hook sono
modificabili da processi con lo stesso UID; la cifratura da chiuso resta il
confine che non dipende dalla cooperazione dell'agente.

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
