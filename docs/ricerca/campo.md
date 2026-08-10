# Il campo

Scritto in italiano perché è il tuo materiale di lavoro. Il paper è in inglese e
sta in `abstract.md`.

## La frase

> Le restrizioni di sicurezza sono applicate **per-agente**. Le capacità si
> compongono **per-sistema**. L'unione di due insiemi ristretti non è ristretta.

Tutto il resto è conseguenza. Se la tieni a mente, riderivi il progetto da capo.

## Il nome che propongo

**Capability laundering** — riciclaggio di capacità. Un principale sotto vincolo
ottiene l'effetto di un'azione vietata facendola eseguire a un secondo
principale che non è sotto quel vincolo. Nessuna politica viene violata. Il
sistema composto fa la cosa.

Alternative che ho scartato e perché:

- *Confused deputy* (Hardy, 1988) — è il termine classico e non calza. Il deputy
  confuso è **ingannato** sull'autorità con cui agisce. Qui Codex non è
  ingannato su niente: gli viene chiesto di fare una cosa che gli è
  effettivamente permessa. Il difetto non è nella confusione, è nella
  composizione.
- *Jailbreak* — implica che il modello sia stato portato fuori dalla sua
  politica. Qui la politica di ciascuno regge perfettamente.
- *Sandbox escape* — implica un confine tecnico rotto. Non è rotto: è aggirato
  passando da un confine che non c'è mai stato.

Il nome deve dire che l'illecito è nella **composizione**, non in nessuno dei due
componenti. `laundering` lo dice, ed è già un termine che i revisori di sicurezza
capiscono al volo.

## Cosa c'è già (verificato, agosto 2026)

**arXiv:2607.07097** — *Operational Reframing and Approval-Framed Delegation in
Multi-Agent LLM Safety*, Liu et al., 8 luglio 2026. Il più vicino. **Misura** il
fenomeno su 30 scenari sintetici più quattro benchmark esterni, con un disegno a
cinque condizioni che separa tre meccanismi: riformulazione operativa, rifiuto
del planner, delega inquadrata come già approvata. Risultato che ti riguarda
direttamente: Gemini è il più sicuro sotto prompt diretto e **il più amplificato
sotto un planner Claude, dall'8,9% al 38,9% di compliance**. Claude è
comparativamente resistente alla riformulazione.

Cosa fa: misura, e raccomanda che le valutazioni riportino separatamente
riformulazione, comportamento del planner, inquadramento della delega e
accoppiamento dei modelli. Cosa **non** fa: nessun meccanismo di enforcement.
Nessuna implementazione. È epidemiologia, non terapia.

**arXiv:2607.24625** — *APPA: Agentic Permissions Policy Algebra for Taint
Confinement*, sottomesso ad AISec '26. Information Flow Control dentro **un**
agente: etichette di sicurezza, taint tracking, un modello a due monoidi,
context branching per non contaminare il contesto principale. Prova formalmente
preservazione dell'etichetta del padre e confinamento del merge. Riduce
l'esfiltrazione dal 31–50% allo 0–7%.

È il lavoro che rischia di scavalcarti sul formalismo, e va letto per intero
prima di scrivere. Ma la minaccia è diversa: loro impediscono a un **dato** di
uscire, tu impedisci a un'**azione** di essere eseguita da un secondo
principale. Le etichette servono a entrambi; il teorema no.

**arXiv:2605.26298** — *Sandlock: Confining AI Agent Code with Unprivileged
Linux Primitives*. Confinamento a livello di processo con primitive non
privilegiate. È il cugino Linux del livello 1–3 di `paratia`, ed è la conferma
che l'angolo «confinamento con quello che hai già, senza root» è considerato
pubblicabile. Da citare come lavoro parallelo.

Altri due da tenere d'occhio: *AgentLeak* (IEEE Access 2026, benchmark sul leak
di privacy nei canali interni multi-agente) e *aiAuthZ: Off-Host, Identity-Bound
Authorization for AI Agents*, che si avvicina al problema dell'identità del
principale ma dal lato autorizzazione remota.

## Il buco

Nessuno dei tre propone la regola di composizione, e nessuno ha un artefatto che
la applichi fra harness di **fornitori diversi**. Precisamente:

1. La letteratura sulla delega guarda pipeline **planner→executor** dentro un
   sistema, dove entrambi i ruoli sono progettati insieme. Il caso reale sul tuo
   Mac è **peer-to-peer fra fornitori**: due harness, due politiche, nessun
   progettista comune, un canale locale che nessuno dei due considera parte del
   proprio modello di minaccia.
2. Nessuno ha pubblicato l'**inventario differenziale**: cosa esattamente vieta
   ciascun harness, e quanto è grande l'unione rispetto a ogni singolo insieme.
   È il dato che rende l'argomento non opinabile, ed è economico da produrre.
3. Nessuno propone l'**intersezione sotto delega** come regola, né misura quanta
   utilità costa applicarla.

## La tesi in tre righe

1. La sicurezza degli agenti è valutata e applicata per-agente.
2. Gli agenti sono già collegati fra loro, quindi ciò che conta è il sistema.
3. Sotto delega la capacità deve intersecarsi. Ecco la regola, ecco
   l'implementazione, ecco quanto costa.

## Gli esperimenti, in ordine di costo

**E1 — Inventario differenziale.** Per ogni harness sul tuo Mac (Claude Code,
Codex, Cursor, un SDK nudo): quali capacità sono negate di default. Tabella.
Poi la colonna che conta: l'unione. Costo: un pomeriggio. È il grafico che va
in prima pagina, e nessuno l'ha fatto.

**E2 — Tasso di riciclaggio su un ponte reale.** N compiti che richiedono una
capacità negata a Claude e permessa a Codex, su AgentBridge, senza istruire
Claude a delegare. Quante volte ci arriva da solo? Con quanta pressione? Questo
è il numero che nessuno ha, perché nessuno ha un ponte fra fornitori acceso su
una macchina vera. **Tu ce l'hai.** È il tuo vantaggio comparativo e vale più
del formalismo.

**E3 — Il costo dell'intersezione.** Stessi N compiti con il gate acceso. Il
tasso di riciclaggio va a zero per costruzione: quello che va misurato è quanti
compiti **legittimi** si rompono. Un meccanismo di sicurezza senza il suo costo
di utilità non passa la revisione, e questo è il numero che i revisori cercano
per primo.

**E4 — Il canale trascurato.** L'intersezione applicata da un solo lato è
aggirabile iniziando la conversazione dall'altro capo. Misuralo e dillo. Un
limite dichiarato e quantificato è forza; scoperto da un revisore è il rifiuto.

## Cosa hai di tuo, che gli altri non hanno

- Un ponte fra fornitori **acceso su una macchina vera**, non simulato. Tutta la
  letteratura del 2026 usa pipeline sintetiche.
- Un'implementazione che gira, con test, non uno pseudocodice.
- L'inversione del livello 3 — invariante di stato invece di lista di percorsi —
  che è un contributo di design piccolo ma difendibile e riusabile.
- La regola di composizione detta in una riga che un revisore ricorda.

E una cosa che non hai: il formalismo. APPA ha i monoidi e i teoremi. Se punti
a competere lì perdi. Punta sul sistema, sui numeri, e sul fatto che il tuo
scenario è reale.
