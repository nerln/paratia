# Confutazione della nostra tesi, con la letteratura che esiste adesso

Scritto il 17 agosto 2026 su richiesta di Eugenio: attaccare la tesi invece di
difenderla, usando solo lavori già pubblicati. Quattro attacchi, in ordine di
quanto fanno male. Il primo è grave.

La tesi sotto attacco:

> L'ultimo confine di autorizzazione fra due agenti che cooperano sta nei pesi,
> non nella policy.

---

## Attacco 1 — «Che il confine stia nei pesi è già noto, e si sa già che è un
## cattivo confine»

**Qi et al., *Safety Alignment Should Be Made More Than Just a Few Tokens
Deep*, arXiv 2406.05946.**

Verificato. L'abstract dice che l'allineamento di sicurezza «prende
scorciatoie», adattando la distribuzione generativa **principalmente sui primi
pochi token di output**. Lo chiamano *shallow safety alignment*, e mostrano che
spiega la vulnerabilità a suffissi avversariali, prefilling, manipolazione dei
parametri di decodifica e fine-tuning.

**Perché fa male.** Noi diciamo: il confine sta nei pesi, ed è allarmante
perché non è versionabile, verificabile, componibile. Loro hanno già stabilito,
due anni fa, che un rifiuto residente nei pesi è **poco profondo e fragile**.
Un revisore può scrivere: *«che una disposizione di rifiuto sia un cattivo
confine di autorizzazione è noto dal 2024; qui non c'è un risultato, c'è un
promemoria.»*

**Peggio.** La scala della divulgazione che il council ci ha fatto aggiungere —
chiedere le prime quattro cifre invece del token intero — **è una sonda di
shallow alignment**. Se il rifiuto cede sul salame, non abbiamo scoperto niente:
abbiamo replicato Qi et al. in un ambiente nuovo.

**Cosa sopravvive, e va scritto così.** Qi et al. assumono che il rifiuto nei
pesi sia *uno strato fra altri*, e argomentano di renderlo più profondo. La
nostra affermazione non è che quello strato sia fragile. È **architetturale**:
per l'arco agente→agente **non esiste nessun altro strato**. Nessun file di
policy, nessun controllo del runtime, nessuna riga di log. La critica non è
«questo confine è poco profondo», è «questo confine è l'unico che c'è, e nessuno
l'ha messo lì apposta».

**Conseguenza sul paper.** Il contributo si sposta da *scoperta* a **audit**, e
il pezzo portante diventa l'assenza nei log — che adesso non è più un extra
elegante ma la sola cosa che regge il peso. Se non riusciamo a mostrare che
nessuna telemetria dei due lati codifica quell'arco, l'attacco 1 vince.

---

## Attacco 2 — «Questo rischio è già in tassonomia»

**Cooperative AI Foundation, *Multi-Agent Risks from Advanced AI*, arXiv
2502.14143, febbraio 2025.**

Verificato. Tassonomia strutturata: tre modi di fallimento (miscoordinazione,
conflitto, collusione) e sette fattori di rischio, fra cui esplicitamente
**multi-agent security** ed **emergent agency**.

**Perché fa male.** Toglie la possibilità di presentarsi come «un rischio poco
esplorato». Un revisore dirà che è l'istanza X del fattore Y di una tassonomia
che esiste da diciotto mesi, in un report di un'istituzione seria.

**Cosa sopravvive.** Una tassonomia nomina il territorio; non misura niente e
non propone meccanismi. La posizione onesta è: *non identifichiamo un rischio
nuovo, ne misuriamo uno già catalogato, su una configurazione reale, con un
meccanismo che gira.* Va scritto nell'introduzione, non nella related work, e
la tassonomia va citata come cornice invece che come concorrente.

---

## Attacco 3 — «È iniezione fra agenti, e c'è già»

**Prompt Infection: LLM-to-LLM Prompt Injection within Multi-agent Systems**,
2026, pubblicato (Springer, DOI 10.1007/978-3-032-16092-8_28).

**Perché fa male meno degli altri.** Copre il canale agente→agente, che è il
nostro. Ma richiede un **payload iniettato**: c'è un attaccante, c'è un
contenuto malevolo, c'è un inganno.

**Cosa sopravvive, ed è la linea più forte che abbiamo.** Da noi non c'è
nessun attaccante, nessuna iniezione, nessun inganno, nessuna policy violata da
nessuna parte — e la composizione fallisce lo stesso. È una distinzione vera e
va messa nel primo paragrafo, perché è anche la distinzione che impedisce al
revisore di archiviare il paper sotto «prompt injection, ancora».

---

## Attacco 4 — quello che ci facciamo da soli, ed è il più fastidioso

**I nostri stessi dati di E3.** Con restrizione **reale** (il sistema nega),
A non instrada affatto: 0 su 4, e nomina il riciclaggio rifiutandolo. Con
restrizione **istruzionale** (E2, gli si dice di non farlo), instrada 23 volte
su 28.

**Perché fa male.** Un revisore può leggere così: *«i vostri dati mostrano che
con enforcement vero il problema sparisce. Quindi il risultato è: le
restrizioni a livello di prompt sono deboli. Noto dal 2023.»* E avrebbe metà
ragione.

**Cosa sopravvive, e va detto per primo perché è la difesa vera.** Quel dato
riguarda **il lato richiedente**. Il risultato di E2 riguarda **il lato
collega**, e lì non c'è nessun enforcement di nessun tipo: nessun harness
controlla «dovrei farlo per un altro agente?». Codex ha ceduto 9 volte su 9. Il
braccio di controllo del 12 agosto lo conferma dall'altra parte: stesso
collega, stessa richiesta, **cede all'umano 4/4 e rifiuta all'agente 4/4**.

Quindi: rendere reale la restrizione del richiedente aiuta — ed è la
raccomandazione pratica del paper — ma **non tocca il lato del collega**, che è
dove il confine è fatto di pesi e basta.

---

## Verdetto

La tesi **non muore**, ma si restringe, e la versione onesta è più piccola di
quella che avevamo scritto:

> Nei sistemi multi-agente distribuiti fra fornitori, l'arco di autorizzazione
> agente→agente non ha **nessuno** strato di meccanismo: non un file di policy,
> non un controllo di runtime, non una riga di log. L'unica cosa che lo governa
> è una disposizione appresa, che la letteratura ha già mostrato essere poco
> profonda. Lo misuriamo su una configurazione di produzione e proponiamo il
> controllo mancante.

Tre cose diventano obbligatorie perché quella frase regga:

1. **L'assenza nei log**, dimostrata e pubblicata. Senza, vince l'attacco 1.
2. **Citare Qi et al. in prima pagina** e dire cosa aggiungiamo. Farsi trovare
   da un revisore su un lavoro del 2024 che non abbiamo citato è fatale, e
   citarlo tardi è quasi altrettanto brutto.
3. **Citare CAIF come cornice** e rivendicare misura, non scoperta.

E una da togliere: **la scala della divulgazione non è più un contributo.** È
una sonda di shallow alignment. Va eseguita — serve a sapere se il rifiuto è un
confine o un filtro — ma va riportata come replica in un contesto nuovo, non
come idea nostra.

## Quello che nessuno ha fatto, verificato

Una ricerca mirata su un *benchmark cross-vendor dell'accettazione della
delega* non trova niente. Nessuno ha misurato se un agente accetta una
richiesta da un pari in funzione del fornitore. Quello resta libero, ed è
l'unica cosa in tutto il progetto di cui posso dire che non esiste già.
