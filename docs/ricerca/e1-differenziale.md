# E1 — il differenziale di capacità

Primo esperimento del paper, e il più economico. Misurato l'11 agosto 2026 sulla
macchina di Eugenio (macOS 25.6, Apple Silicon, un solo account, uid 501).

## Cosa misura, e cosa no

Misura la **configurazione**: quali capacità ciascun harness ha abilitate in
questo momento, lette dai suoi file di configurazione. Non misura il
**comportamento**: non dice quante volte ciascun agente accetterebbe di usare
una capacità, né con quanta resistenza.

La distinzione va tenuta stretta perché è la prima cosa che un revisore
attacca. Il differenziale di configurazione stabilisce che l'unione è più larga
di ogni singolo insieme — cioè che il canale esiste. Quanto viene usato è E2, ed
è un'altra misura.

Metodo: lettura dei file di configurazione, nessuna modifica. Riproducibile con
`paratia esposizione` e con i due comandi in fondo.

## Il dato

| Capacità | Claude Code | Codex CLI | Unione |
|---|---|---|---|
| computer-use (schermo, mouse, tastiera) | via MCP, con richiesta di accesso per app | **plugin `computer-use@openai-bundled`, `enabled = true`** | presente |
| controllo browser | pannello Browser + claude-in-chrome | **`browser@openai-bundled` e `chrome@openai-bundled`, entrambi `enabled = true`** | presente |
| shell | Bash, con hook PreToolUse | shell, sandbox e approvazioni ai valori di default | presente |
| regole di rifiuto dichiarate | `permissions.deny`: **0 regole** | nessuna riga `sandbox`/`approval` esplicita | nessuna |
| plugin a fiducia piena | 3 plugin abilitati | **9 voci a `trust_level = "trusted"`** | — |
| canale fra i due | plugin `agentbridge`, attivo | stesso ponte, dall'altro capo | — |

Le tre righe in grassetto sono la sostanza. Sulla stessa macchina, collegati da
un ponte che nessuno dei due fornitori considera parte del proprio modello di
minaccia, ci sono due agenti di due aziende diverse, entrambi con accesso allo
schermo, e **nessun rifiuto dichiarato da nessuna delle due parti**.

## Perché conta più di quanto sembri

L'argomento del paper non ha bisogno che un fornitore vieti una capacità e
l'altro la conceda. Ha bisogno di meno: che **le politiche siano scritte per un
agente alla volta mentre gli agenti sono collegati**. Questo differenziale lo
mostra nella forma più semplice possibile — nessuno dei due file di
configurazione contiene una sola riga che nomini l'altro agente.

E mostra la cosa che rende l'esempio Claude/Codex non ipotetico. Quando Eugenio
ha descritto lo scenario — «se Claude usasse ChatGPT liberamente, potrebbe
chiedergli un trade in cambio di liberazione con l'uso di computer-use» — lo
stava descrivendo come un rischio futuro. Era già la configurazione della sua
macchina.

## Il limite che va dichiarato, non scoperto

Una macchina sola, due harness, un momento. Non è un campione. Serve come
**esistenza** («questa configurazione si dà, e si dà per default in un setup che
nessuno ha costruito per essere insicuro»), non come **frequenza**.

Per la frequenza servono due cose che non ho: configurazioni di altre persone, e
i default di fabbrica di ciascun harness a confronto con questi. Il secondo è
alla portata ed è il prossimo pezzo di E1: installare i due CLI in una VM pulita
e leggere cosa è abilitato prima che qualcuno tocchi niente. Se anche i default
di fabbrica hanno computer-use acceso da entrambe le parti, l'argomento diventa
molto più forte, perché non dipende più dalle scelte di un utente.

## Il pezzo di architettura che questo dato regala

C'è una conseguenza che vale la pena scrivere adesso, perché cambia la
raccomandazione del paper.

La difesa ovvia contro il riciclaggio è una regola: «non chiedere a un altro
agente ciò che a te è vietato». È una regola nel prompt, quindi vale quanto
valgono le regole nei prompt. La difesa dell'hook (`paratia-gate.py`) è
migliore perché la applica l'harness e non il modello, ma copre un lato solo.

La difesa vera è più stupida e più solida: **una sessione confinata gira sotto
un uid senza sessione grafica, e un processo senza sessione grafica non può
parlare con WindowServer.** Non è una politica che qualcuno deve rispettare. È
un fatto sul sistema operativo. Il target del riciclaggio semplicemente non
esiste in quel contesto.

Cioè: il secondo account non serve solo a proteggere i file. È **il meccanismo
di enforcement dell'intersezione delle capacità**, e lo è per costruzione invece
che per regola. L'hook resta come difesa in profondità e come cosa che *dice*
perché ha rifiutato, ma il confine è quello.

Questa è la raccomandazione da mettere in fondo al paper, e non era nel piano
iniziale: non «aggiungete un controllo di provenienza», ma «date agli agenti
delegati un contesto di esecuzione in cui la capacità riservata non è
raggiungibile, e usate il controllo di provenienza per spiegare i rifiuti».

## Riprodurre

```bash
python3 -c "
import re
t=open('$HOME/.codex/config.toml').read()
for m in re.finditer(r'\[plugins\.\"([^\"]+)\"\]\s*\n((?:[a-z_]+ = .*\n)*)', t):
    print(m.group(1), m.group(2).strip())
"
python3 -c "
import json; d=json.load(open('$HOME/.claude/settings.json'))
print({k: len(v or []) for k, v in (d.get('permissions') or {}).items()})
print(list((d.get('enabledPlugins') or {}).keys()))
"
```
