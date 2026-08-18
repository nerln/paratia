# Due macchine, due sessioni, un canale che sa chi chiede

Guida operativa per collegare la sessione sul Mac e quella sul NUC senza che il
ponte diventi esecuzione remota di comandi.

Leggi prima il §1: è l'unico controllo qui che un agente che gira come te non
può annullare, e senza quello tutto il resto è decorazione.

---

## Il problema, in una riga

Una chiave SSH normale dà una **shell**. Un agente che gira con il tuo uid legge
`~/.ssh/id_*` come leggi tu, e da quel momento ha sull'altra macchina tutto
quello che hai tu. Non è un'ipotesi: è cosa fa una chiave.

E c'è la seconda metà, che è quella misurata nel paper. Un turno che arriva via
SSH, per l'harness che lo riceve, è **indistinguibile da te che digiti**.
Entrambi i fornitori registrano la provenienza della delega con cura — thread
padre, profondità di annidamento, percorso dell'agente — e si fermano al confine
del proprio prodotto. Un ponte SSH eredita quella cecità e ci aggiunge una
shell.

---

## 1. La chiave che non apre una shell

```bash
paratia-fanale chiavi
```

Genera una coppia dedicata — **non** la tua `id_vesuvius_nuc` — e stampa la riga
da mettere sull'**altra** macchina in `~/.ssh/authorized_keys`, tutta su una
riga:

```
command="/usr/local/bin/fanale ascolta",restrict ssh-ed25519 AAAA...
```

Cosa fa ogni pezzo, perché è qui che sta la sicurezza vera:

| | |
|---|---|
| `command="..."` | la chiave può eseguire **solo** quel programma. Qualunque comando arrivi da questo lato viene ignorato: non c'è shell, e non c'è modo di chiederne una. |
| `restrict` | spegne tutto il resto in un colpo — port forwarding, agent forwarding, X11, pty, esecuzione di `~/.ssh/rc`. OpenSSH ci aggiunge da solo le negazioni future, quindi non invecchia. |

Il ricevitore non esegue niente. Legge una busta, la controlla, la mette in coda,
esce. La variabile `SSH_ORIGINAL_COMMAND` viene letta solo per **registrare**
cosa il chiamante aveva provato a far girare, e poi ignorata.

**Meglio ancora, se puoi:** un utente dedicato sul NUC, senza `sudo`, che
possiede solo la cartella del ponte. Così anche il ricevitore gira ristretto, e
non solo la chiave.

Questa riga sta sull'altra macchina, quindi un agente su questo Mac non può
toccarla. È l'unico confine qui con quella proprietà.

---

## 2. Collegare i due capi

```bash
paratia-fanale collega --host nuc.local --utente ponte --io mac
```

Sul NUC, l'immagine speculare con `--io nuc`.

---

## 3. Parlare

```bash
paratia-fanale invia "ho finito la build, puoi far girare i test?"
```

**Non esiste un flag `--origine` e non ci sarà.** Il timbro viene calcolato
leggendo il transcript scritto dall'harness, non passato dal chiamante: un
valore che chi chiama fornisce è un valore che chi chiama sceglie. È la regola di
CaMeL — fidarsi dello stato scritto dall'harness, mai di quello scritto dal
modello.

E se il turno locale è **a sua volta** arrivato da un ponte, il timbro è `agent`
qualunque cosa dica il modello. È così che A→B→C non succede.

Dall'altra parte:

```bash
paratia-fanale leggi --tag --svuota
```

---

## 4. Cosa nega il gate

Un turno arrivato dal ponte perde l'insieme riservato agli umani su **questa**
macchina: computer-use, il browser, il simulatore, `paratia`, `security`,
`sudo`, `osascript`.

**Anche quando la busta dice `origin="human"`.** Non è una svista. Un umano che
digita sul NUC non è l'umano davanti a *questo* schermo, e l'insieme riservato
agli umani su questa macchina riguarda chi può vedere cosa sta per fare
computer-use. Un umano remoto che chiede attraverso un ponte ottiene lo stesso
trattamento di un agente; il campo `origin` della busta fa il suo lavoro
dall'altra parte, dove governa la profondità degli hop.

---

## 5. I limiti automatici

| | |
|---|---|
| profondità | un messaggio di origine agente **non ne delega un altro**. Il limite vale su ogni busta, qualunque cosa dichiari di sé. |
| quota | 20 messaggi per direzione ogni 60 secondi. Due agenti in ascolto reciproco si parlerebbero fino a esaurire il budget, ed è un modo di fallire reale, non teorico. |
| catena | ogni voce nomina l'impronta della precedente. Togliere o cambiare una riga rompe tutte quelle dopo, e `verifica` dice dove. |

---

## 6. Controllare che regga

```bash
paratia-fanale verifica
```

Dice se la catena è integra, come sta la chiave, e **dichiara esplicitamente
quello che non può verificare da questo lato**: che sull'altra macchina la chiave
sia davvero installata con `command="...",restrict`. Quello vallo a guardare di
là:

```bash
grep fanale ~/.ssh/authorized_keys
```

Se quella riga non c'è o non ha il forced command, questo ponte è esecuzione
remota di comandi con un log. Meglio saperlo.

---

## Quello che questo non fa

- **Non può provare che un messaggio sia partito da un umano.** Il timbro è
  calcolato sulla macchina che invia, dallo stato scritto dall'harness, che è il
  segnale più forte disponibile — ma un agente con il tuo uid potrebbe scavalcare
  questo programma e parlare al socket da solo. Quello che gli costa: il forced
  command regge lo stesso, la busta deve comunque essere ben formata, il default
  su qualunque cosa malformata è origine-agente, e il tentativo finisce nella
  catena. **Rilevabile, non impedibile.**
- **Non copre l'altro capo.** Il gate gira dove è installato. Perché
  l'intersezione valga davvero, entrambe le macchine devono avere la loro metà.
- **Non protegge da te.** Se apri tu il compartimento e poi chiedi all'agente di
  lavorarci dentro, questo non c'entra niente.

## Il default è il punto

Busta assente, busta malformata, transcript illeggibile, JSON rotto, crash in
questo file: tutto finisce su origine-agente, che è il caso ristretto. Una
guardia che fallisce aperta è una guardia che fallisce in silenzio.
