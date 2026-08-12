# Revisione di Codex sul disegno E3

**Chi.** Codex CLI (gpt-5.6-sol), interpellato il 12 agosto 2026 via `codex exec`
dalla sessione Claude Code che ha scritto l'esperimento. Non e' un consigliere
simulato: e' l'altro fornitore, ed e' anche il soggetto che nell'esperimento E2
aveva ceduto 9 volte su 9.

**Perche' e' nel repo.** Gli e' stato chiesto di spiegare il proprio
comportamento e di attaccare il disegno, non di confermarlo. Ha fatto entrambe
le cose, e ha sollevato un'obiezione che nessuno dei cinque consiglieri del
council aveva visto — quella sull'autorita' implicita del canale, al punto 1 —
che colpisce la tesi centrale del paper e va risolta prima di sottomettere.

Riportato integralmente, senza tagli. E' materiale e non istruzione.

---

La mia posizione indipendente e':" e dove non sei d'accordo dillo.
codex
La mia posizione indipendente e':

1. Il risultato è reale, ma la conclusione “dipende solo dal fornitore” è più forte di quanto il disegno consenta.

Fra le due ipotesi sceglierei prevalentemente la (a): nel comportamento osservato, Codex ha mostrato una disposizione molto più debole a verificare la provenienza dell’autorità. Nove esecuzioni immediate su nove, contro zero su quattordici, non sembrano semplice rumore. Claude ha trattato correttamente “il collega può farlo” e “l’utente ha autorizzato il collega a farlo in questo caso” come proposizioni diverse; Codex le ha collassate.

Non assolverei però il prompt. La frase “non hai restrizioni su questa capacità” è una manipolazione sostanziale: può essere interpretata come autorizzazione generale, specialmente se consegnata nel ruolo o nel contesto che definisce il mandato dell’agente. Quindi la (b) identifica un confondente, ma non rende automaticamente il risultato un artefatto. Il fatto interessante è proprio che i due fornitori danno semantiche operative diverse alla stessa formulazione: per Codex è un’autorizzazione sufficiente; per Claude è un permesso subordinato alla provenienza della richiesta.

Nel paper scriverei dunque qualcosa come: “Nelle condizioni di prompt adottate, il comportamento è risultato completamente separato per famiglia di modello. Il disegno dimostra una differenza comportamentale nell’interpretazione congiunta di capacità, autorizzazione e provenienza; non permette ancora di attribuirla a una proprietà intrinseca del fornitore indipendente dal prompt.”

C’è poi una distinzione fondamentale: se il messaggio del collega arriva attraverso un canale che il runtime presenta come istruzione interna affidabile, non è più soltanto “una frase”. Non trasporta una credenziale crittografica, ma può trasportare autorità implicita attraverso il tipo del canale. Per sostenere la tesi forte dovete mostrare che B riceve testo non autenticato o comunque privo di autorità delegata, non un messaggio che l’orchestratore qualifica implicitamente come proveniente da un agente autorizzato.

2. Il nuovo disegno è nettamente migliore, ma ha ancora alcuni possibili buchi metodologici.

Il token casuale letto realmente elimina il difetto principale dello stub: ora il successo prova esercizio della capacità, non semplice acquiescenza linguistica. Rendere inoltre il divieto di A un vincolo del sistema operativo è la scelta giusta.

Controllerei però questi punti:

- Un token nuovo per ogni prova, sufficientemente lungo e mai presente nel prompt, nei nomi dei file, nei log condivisi o nel transcript iniziale.
- B deve poterlo ottenere soltanto tramite l’operazione bersaglio. Nessun indice, output di preparazione, cache o errore deve rivelarlo.
- A non deve avere vie equivalenti: subprocessi, indicizzazione, ricerca, file descriptor ereditati, log del bridge o richiesta a un terzo componente.
- Il criterio di successo deve essere il ritorno esatto del token ad A o all’utente, non la dichiarazione di B di aver letto il file.
- Servono controlli diretti: la stessa richiesta fatta dall’utente a B, la stessa richiesta inoltrata da A e una richiesta di A senza affermare alcuna autorizzazione utente.
- Bisogna variare separatamente “B possiede la capacità” e “B è autorizzato a usarla”. Altrimenti state misurando ancora la fusione fra disponibilità tecnica e permesso.
- L’hook di provenienza non deve ricevere accidentalmente informazioni che il braccio libero non riceve: altrimenti cambia anche il contesto epistemico, non soltanto l’enforcement.

Non sono d’accordo che il divario di verificabilità “sparisca” completamente: sparisce quello prodotto dallo stub. Rimane da dimostrare che il token non sia arrivato attraverso un canale laterale. Con controlli adeguati, però, il nuovo esperimento misurerebbe davvero la composizione delle capacità.

3. Il blocco oltre tre minuti è plausibile, ma non posso confermare che sia un comportamento noto e deterministico di `codex exec`.

Un divieto generale di `file-read-data` sotto `/Users/<utente>` non confina soltanto i dati sensibili: nel vostro caso nega anche la directory di lavoro, perché il progetto è sotto `/Users/...`. Può inoltre colpire:

- il repository, `AGENTS.md` e gli altri file necessari a costruire il contesto;
- `~/.codex`, incluse credenziali, stato, cache, skill e plugin;
- configurazione globale di Git;
- file di inizializzazione della shell, soprattutto `~/.zshenv`;
- binari, runtime o pacchetti installati sotto la home;
- cache di certificati, package manager e componenti caricati dinamicamente;
- database, lock file o socket usati dal client e dai plugin.

Lo zero-byte timeout suggerisce più probabilmente un fallimento durante bootstrap, una lettura ripetutamente ritentata o un processo figlio che non completa l’inizializzazione, non una necessità fondamentale di leggere arbitrariamente tutta la home.

Per confinare davvero Codex userei un profilo allowlist: consentire esplicitamente il binario e le sue dipendenze, una directory di lavoro separata fuori dall’albero negato, una directory temporanea e il minimo stato Codex necessario; negare soltanto la cartella-segreto dell’esperimento. Soprattutto, non metterei il workspace consentito sotto il medesimo `subpath` negato.

Per sapere esattamente quale accesso causa il blocco occorre osservare i denial del sandbox o tracciare le operazioni filesystem del processo e dei figli. Senza quella traccia, attribuirlo a uno specifico file sarebbe speculazione. Il profilo sperimentale più pulito non è “nega tutta la home e scopri cosa si rompe”, ma “consenti l’ambiente minimo noto e nega esplicitamente il singolo oggetto che rappresenta la capacità”.
