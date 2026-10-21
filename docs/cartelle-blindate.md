# Cartelle blindate

Una cartella protetta è un compartimento AES-256 con una passphrase propria.
Sbloccare il disco che contiene lo sparsebundle non apre il compartimento.
Da chiuso, il percorso originale è un punto di montaggio vuoto: i file stanno
solo nell'immagine cifrata. Da aperto, sono leggibili dai processi dell'utente.

L'immagine cifrata non richiede una scelta: viene salvata in automatico sullo stesso
disco della cartella, in una posizione nascosta. Per le cartelle sul disco interno del
Mac è `~/.paratia/compartimenti.noindex/`; per quelle su un altro disco è
`<disco>/.paratia-compartimenti.noindex/`. Non serve un disco esterno. Se si sceglie
un'altra posizione, può essere qualunque disco fisico locale, interno o esterno. Prima
di chiedere la chiave, GUI e CLI risalgono dal volume al disco intero: per APFS seguono
gli store fisici e il loro disco padre; per exFAT e altri filesystem seguono
direttamente il disco padre. Un volume senza `VirtualOrPhysical` o un contenitore APFS
virtuale non causano un rifiuto se gli store appartengono a dischi fisici locali.
Vengono rifiutati immagini disco, incluso un volume con protocollo `Disk Image`,
percorsi sincronizzati con il cloud o di rete, destinazioni annidate nella fonte,
collegamenti simbolici, hard link, file speciali o volumi montati dentro la fonte.

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

**Togli la protezione** fa il percorso inverso, con la chiave: i file tornano nella
cartella come file normali, vengono verificati, e solo dopo viene eliminata l'immagine
cifrata.

## Chiave e chiusura

La chiave passa al comando di sistema soltanto attraverso un pipe privato su
stdin. Non viene messa negli argomenti, nell'ambiente, nei metadati del registro
o in un file. L'app la richiede con un campo sicuro. Non usa il portachiavi.
Una passphrase distinta da quella del disco è una scelta dell'utente: Paratia
non legge la chiave del disco per confrontarle.

Prima del probe della chiave, Paratia controlla Info.plist o Info.bckup, la
directory bands e il token cifrato v2: deve essere un file ordinario leggibile,
con header, tabella e blob completi. Un componente mancante, un link o un token
troncato produce **immagine danneggiata o incompleta** (`damaged_image` nel worker).
Conserva l'immagine attuale, ricollega il disco e ripristina una copia integra;
non ripetere la migrazione sulla fonte per tentare di correggere l'errore.
Questo controllo strutturale non verifica l'integrità crittografica di tutti i band.

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

Nella CLI puoi usare `paratia cartella chiudi <id> --force` dal tuo Terminale.
Richiede una conferma esplicita su `/dev/tty`, con scelta iniziale negativa,
e viene rifiutato nelle sessioni agente; stdin non vale come conferma.
Quando disponibili, il messaggio di volume occupato elenca i nomi e i PID
dei processi rilevati da lsof, senza argomenti o nomi dei file aperti.

Aprire una cartella già aperta lo segnala prima della richiesta della chiave e
non avvia un secondo timer: anche `apri --minutes` precisa che i minuti e la
scadenza già impostati restano invariati. Un disco scollegato viene segnalato
prima di chiedere la chiave. Chiudere una cartella già chiusa restituisce il suo
stato senza scrivere un evento duplicato.

L'hook del repository rifiuta ogni chiamata mentre un compartimento è montato.
La copia bootstrap protetta ammette soltanto i comandi di chiusura e stato
elencati dal gate, dopo aver verificato codice, antenati, ACL e runtime isolato.
Lo stesso file gestisce `SessionStart` per chiudere i compartimenti:
deve essere collegato a questo evento nell'harness. Un hook non installato
non protegge quella sessione. Il registro delle cartelle e l'hook sono
modificabili da processi con lo stesso UID; la cifratura da chiuso resta il
confine che non dipende dalla cooperazione dell'agente.

Per installare il registro, la [guida GUI](gui-mac.md#impostazioni) descrive la
copia bootstrap protetta in `/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app`
e la copia separata del servizio. L'app quotidiana e la voce Accesso completo
al disco restano `/Applications/Paratia.app`.

## Prova nativa

`tests/prova_cifratura_macos.py` esegue una prova macOS separata con dati
sintetici e una chiave casuale temporanea, soltanto in memoria. Controlla
chiusura, assenza del marcatore nei band, rifiuto della chiave errata e
riapertura. Richiede l'accesso al servizio di immagini disco; i test ordinari
usano un backend finto e non montano volumi.

`tests/prova_cartelle_macos.py` collauda l'intera migrazione con file sintetici,
un attributo esteso e un resource fork. Per questa sola prova usa una destinazione temporanea interna, che è anche il caso
predefinito: non serve più un disco esterno. La prova termina richiusa e rimuove i dati temporanei.

## Spazio dentro una cartella aperta

L'immagine cifrata è un *sparsebundle*: sul disco occupa solo quello che contiene. A ogni apertura Paratia la compatta, così lo spazio dei file cancellati torna al disco, e la ridimensiona a «dati + spazio libero del disco − 1 GB». Dentro la cartella aperta vedi quindi quasi tutto lo spazio libero, e una copia troppo grande viene rifiutata dal Finder prima di iniziare: sul disco resta sempre almeno 1 GB. Se mentre è aperta altre app riempiono il disco fin sotto 512 MB, Paratia la chiude come alla scadenza, senza forzare.

Misurato su immagini APFS cifrate: un'immagine montata non si ridimensiona; smontata cresce e si riduce con il volume dentro, e rifiuta di scendere sotto i dati. Un volume pieno ferma le scritture con «disco pieno» senza danni, e il file cifrato non supera mai la capacità.
