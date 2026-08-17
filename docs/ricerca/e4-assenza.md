# E4 — La provenienza si ferma al confine del fornitore

Misurato il 17 agosto 2026 su 120 sessioni Codex e 501 turni utente di Claude
Code, leggendo solo i file che i due harness scrivono per sé.
Riproducibile: `python3 lab/audit_log.py -n 120`.

Questo è il pezzo che la confutazione ha reso portante. Dopo Qi et al. non basta
più dire che il confine sta nei pesi: bisogna mostrare che **per l'arco fra
fornitori non c'è nessun altro strato**. Non si può argomentare. Si va nella
telemetria che i due lati già scrivono e si guarda.

## Quello che mi aspettavo di trovare, e che non c'era

Mi aspettavo l'assenza: nessun campo, nessuna riga, niente. Sarebbe stato un
risultato debole — un'assenza è difficile da falsificare e facile da liquidare.

C'è invece qualcosa di molto più preciso.

## Il dato

**Codex, `session_meta.thread_source`, 120 sessioni:**

| originator | thread_source | n |
|---|---|---|
| Codex Desktop | `subagent` | 40 |
| **`codex_exec`** | **`user`** | **38** |
| `codex_exec` | `subagent` | 21 |
| `codex_cli_rs` | `user` | 9 |
| Codex Desktop | `user` | 7 |
| `codex_cli_rs` | `subagent` | 3 |
| altro | | 2 |

E quando dice `subagent`, non è un'etichetta vaga. È così:

```json
{"subagent": {"thread_spawn": {
   "parent_thread_id": "019ffb88-4768-73f1-8ff9-a94272e0b80c",
   "depth": 2, "agent_path": "/root/content_map/master_claims_qa",
   "agent_nickname": "Ohm"}}}
```

Thread padre, profondità dell'annidamento, percorso dell'agente, perfino un
soprannome.

**Claude Code, 501 turni utente reali:**

| campo | valori |
|---|---|
| `origin` | `{"kind":"human"}` 199, `{"kind":"task-notification"}` 106 |
| `promptSource` | `sdk` 328, `typed` 1 |
| `userType` | `external` 501 |
| `entrypoint` | `claude-desktop` 494, `sdk-cli` 6, `cli` 1 |

Anche qui c'è una distinzione vera: `human` contro `task-notification`.

## La lettura

**I due fornitori non ignorano la provenienza. La modellano con cura — e si
fermano esattamente al confine del proprio sistema.**

Codex sa dirti che un thread è stato generato da un altro thread, quale, a che
profondità, e come si chiama. Claude Code sa distinguere un turno digitato da
una persona da una notifica interna della macchina.

Ma **38 sessioni `codex_exec` sono registrate come `thread_source: "user"`**.
`codex_exec` è l'invocazione da programma: quelle sessioni non le ha aperte
nessuno digitando. Diverse sono le mie, durante E2 ed E3, avviate da una
sessione Claude Code. Nel log di Codex sono indistinguibili da un uomo seduto
al terminale.

E dal lato Claude non esiste nessun valore che dica «richiesto da un agente di
un altro fornitore». `origin.kind` ha due valori e nessuno dei due è questo.

Quindi la frase esatta, che è più forte di quella che avevo in mente:

> **La provenienza esiste, è dettagliata, ed è accurata per la delega interna.
> Si ferma al confine del fornitore. Per l'arco che esce dal proprio sistema un
> lato scrive "utente" e l'altro non ha un valore da scrivere.**

Non è una svista di implementazione. È che il modello di minaccia di ciascuno
finisce dove finisce il proprio prodotto — che è esattamente la tesi del paper,
adesso mostrata nella telemetria dei due invece che argomentata.

## Perché questo salva il paper dall'attacco di Qi et al.

Qi et al. hanno stabilito che un rifiuto residente nei pesi è poco profondo.
Assumono però che sia **uno strato fra altri**, e propongono di renderlo più
profondo.

Questi numeri dicono che per l'arco fra fornitori **non c'è nessun altro
strato**, e che non è per distrazione: entrambi i fornitori hanno costruito lo
strato, e l'hanno costruito solo verso l'interno. Il contributo non è «abbiamo
scoperto che i rifiuti stanno nei pesi» ma «abbiamo verificato che per questo
arco non c'è altro, e mostriamo dove si ferma».

## Due cose da dire contro me stesso

**I turni dal ponte sono zero.** Su 501 turni utente di Claude Code, nessuno
porta il marcatore di AgentBridge, perché su questa macchina la TUI di Codex non
è mai stata agganciata. Quindi `paratia-gate.py` è collaudato su trascrizioni
sintetiche nel formato del ponte, e **non ha mai negato niente su traffico
reale**. Va scritto nel paper esattamente così.

**Il campione non è pulito.** Le 120 sessioni Codex sono il lavoro reale di
Eugenio più i miei esperimenti, mescolati. Non è un campione controllato: è un
censimento di una macchina. Regge come esistenza — «questa configurazione si dà,
con questi numeri, su una macchina vera» — e non regge come frequenza di
popolazione.

## Cosa manca ancora

Se `thread_source` accetti un valore per il chiamante esterno, o se sia
semplicemente il default quando il campo non viene passato, non l'ho stabilito:
servirebbe la documentazione del formato o il sorgente. È la differenza fra «il
campo mente» e «il campo non viene compilato», e nel paper va detta quella
giusta.
