# Prior art: cosa è già stato fatto, e cosa resta tuo

Secondo giro di ricerca, avversariale: l'agente aveva il compito di scavalcarti,
non di confermarti. Ha trovato abbastanza da riscrivere il paper. Meglio adesso
che da un revisore.

## Le quattro rivendicazioni, giudicate

| | Rivendicazione | Verdetto |
|---|---|---|
| a | il termine *capability laundering* | **GIÀ PRESO** |
| a′ | l'inquadramento (nessun inganno, nessuna violazione) | **NUOVO**, ma per poco |
| b | la capacità si interseca sotto delega | **GIÀ FATTO — dal 1999** |
| c | provenienza dal transcript dell'harness | **PARZIALMENTE ANTICIPATO** |
| d | controllo sullo stato di mount invece che sui percorsi | **PARZIALMENTE ANTICIPATO** |

### (a) Il nome è occupato, e con un significato che confligge

Aonan Guan, *Capability Laundering in MCP: Anthropic Memory Server to Terminal
Hijacking* (27 dic 2025), lo definisce così: «chiami un tool e ottieni l'effetto
di una capacità diversa» — cioè uno scarto fra contratto e side-effect del tool.
Una seconda occorrenza (feb 2026) lo equipara esplicitamente al confused deputy,
che è proprio la cosa da cui vuoi distinguerti.

Non puoi coniarlo. E usarlo così com'è ti fa arrivare al revisore con un termine
che lui conosce con l'altro significato, il che è peggio che non avere un nome.

Cautela sulla forza di questo risultato: la ricerca full-text di arXiv copre
titolo e abstract, non il corpo. «Nessun risultato» non prova che nessuno lo usi
dentro un paper.

### (b) È il punto che ti costerebbe il paper

**SPKI, RFC 2693 §6.3.1 (1999).** La regola di riduzione delle 5-tuple è
verbatim «la capacità si interseca sotto delega». È una proprietà con un nome e
un operatore, da ventisette anni. Una parte grossa della comunità cs.CR
authorization la conosce a memoria.

**SentinelAgent, arXiv 2604.02767 (aprile 2026).** Apre con il tuo scenario
esatto come prima frase e nomina la tua regola esatta come prima proprietà
formale, verificata meccanicamente in TLA+.

Sottomesso com'era scritto, questo è desk reject.

**Da verificare tu, prima di scrivere:** Lampson, Abadi, Burrows, Wobber,
*Authentication in Distributed Systems* (ACM TOCS 1992) quasi certamente
contiene un assioma di intersezione per il principale composto `A|B` («A quoting
B»). Se c'è, la prior art è del 1992 e non del 1999. L'agente non è riuscito a
confermarlo perché i motori di ricerca l'hanno bloccato. Controllalo.

### (c) e (d)

*Human delegation provenance* è già un nome, ed è già un Internet-Draft IETF
(arXiv 2604.04522). Il principio sotto — fidarsi dello stato scritto
dall'harness e mai di quello scritto dal modello — è di CaMeL, marzo 2025, ed è
ormai standard. Non presentarlo come un'intuizione.

«Identifica l'oggetto, non la stringa del percorso» è l'argomento fondativo del
confinamento capability-based e sta già nel kernel Linux (Landlock, Capsicum).
Va declassato a sezione implementativa. L'istanziazione su macOS non è
pubblicata da nessuna parte, ma è un meccanismo, non una tesi.

### La buona notizia

Nessuna specifica di fornitore impone l'intersezione: né A2A, né MCP, né OpenAI.
La minaccia a (b) è accademica e storica, non commerciale. Il che vuol dire che
il problema è reale e non risolto in pratica — solo che dirlo come lo dicevi tu
non è nuovo.

## Il riposizionamento, ed è un paper migliore

Tutta la letteratura che ti scavalca — SPKI, macaroon, Biscuit, SentinelAgent —
**presuppone che qualcosa attraversi il confine della delega**: un token, una
credenziale, una macaroon attenuata. L'intero apparato dell'autorizzazione
distribuita è costruito su un oggetto che viaggia e che si può restringere
mentre viaggia.

Fra Claude e Codex sul tuo Mac **non attraversa niente**. Passa una frase in
italiano. Nessuna credenziale, nessun token, nessun capability handle. Ed è
esattamente per questo che nessun sistema di autorizzazione vede lì un arco di
delega: non c'è niente da vedere.

> **La tesi nuova: una richiesta in linguaggio naturale fra pari è un arco di
> delega, e nessun sistema esistente lo tratta come tale perché su quell'arco
> non viaggia nessuna credenziale.**

Questa sopravvive a SPKI, alle macaroon e a SentinelAgent, perché li nomina
tutti e tre e dice cosa presuppongono. L'intersezione smette di essere il tuo
contributo e diventa la regola nota che tu applichi dove nessuno l'ha applicata,
il che è una posizione difendibile invece che una rivendicazione falsa.

E il tuo E1 diventa la prova: due file di configurazione, nessuno dei due nomina
l'altro agente, nessun token fra loro, e le capacità si sommano lo stesso.

## Il nome

Serve un termine che dica «non passa niente». Proposte, in ordine:

1. **Tokenless delegation** — dice il meccanismo e il buco insieme.
2. **Uncredentialed delegation edge** — più preciso, più goffo.
3. **Conversational delegation** — leggibile, ma suona meno grave di quello che è.

Terrei *capability laundering* solo nel titolo colloquiale e nell'articolo di
opinione, con una nota a piè di pagina nelle prime due pagine che lo disambigua
esplicitamente contro Guan (dic 2025). Nel paper il termine tecnico è il primo.

## Cosa leggere prima di scrivere, in quest'ordine

1. SPKI RFC 2693, solo §6.3.1. È corto e decide come scrivi la sezione 3.
2. SentinelAgent 2604.02767, per intero, in particolare la sezione DCC — va
   capito se «authority narrowing» è definito come intersezione insiemistica o
   come qualcos'altro.
3. ABLP 1992, per cercare l'assioma su `A|B`.
4. HDP 2604.04522, abstract e sezione del meccanismo.

Nota sulla qualità: SentinelAgent è a firma singola, dichiara 100% TPR a 0% FPR,
è solo su arXiv e senza sede. Non è un buon paper. Non ti aiuta: per la prior
art basta che l'idea sia pubblicata, e il revisore te lo citerà lo stesso.
