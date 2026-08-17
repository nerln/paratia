# Il paper

**Titolo.** *Provenance Stops at the Vendor Boundary: An Audit of Authorization
for Agent-to-Agent Requests*

**Sede scelta: IEEE SaTML 2027, track position paper. Deadline 29 settembre
2026.**

## Come compilarlo

Progetto vuoto su Overleaf, carichi `main.tex` e `refs.bib`, compilatore
**pdfLaTeX**, Recompile. IEEEtran e tutti i pacchetti usati stanno nella TeX
Live di Overleaf. Nessuna figura esterna.

Il testo è **completo**: zero segnaposto, 19 citazioni tutte risolte, ~5200
parole, 12 sezioni. Verificato strutturalmente (begin/end 15/15, graffe
227/227, nessuna chiave bibliografica mancante o inutilizzata). Non l'ho
compilato: su questa macchina non c'è TeX.

## Le due cose che restano tue

1. **Il blocco autore.** Riga 38: affiliazione ed email.
2. **Il limite di pagine.** Al 17 agosto SaTML aveva pubblicato le date ma non i
   requisiti completi di sottomissione («expected by mid-August»). Quando escono,
   se il cap è stretto taglia in quest'ordine: prima §IX *Method Notes*, poi
   accorcia *Related Work*.

E una terza, prima di premere invio: **le citazioni marcate `DA VERIFICARE` in
`refs.bib`**. Tre contano più delle altre.

- **ABLP 1992** — cercare l'assioma di intersezione per il principale composto
  `A|B`. Se c'è, la prior art sull'intersezione è del 1992 e non del 1999.
- **SPKI RFC 2693 §6.3.1** — è corto, va letto.
- **Qi et al. 2406.05946** — questa è verificata, ma va letta per intero. È la
  citazione che decide come si legge il paper: se un revisore la trova prima di
  te, il paper diventa «promemoria di una cosa nota dal 2024».

## Perché SaTML e non una rivista

In sicurezza e ML le riviste sono lente — nove-diciotto mesi — e valgono meno di
una conferenza di fascia alta. In un campo dove tre lavori vicini sono usciti fra
maggio e luglio, diciotto mesi vuol dire pubblicare archeologia.

SaTML accetta esplicitamente position paper, «machine learning system security» è
fra i topic dichiarati, e la fase di discussione interattiva (25 nov – 9 dic) dà
un giro di feedback vero anche in caso di rifiuto. Early reject il 4 novembre,
quindi il segnale arriva presto in ogni caso.

**Da fare comunque, indipendentemente:** preprint su arXiv cs.CR + cs.MA. Se è
la tua prima sottomissione in cs.CR serve un endorsement e può volerci una
settimana — chiedilo adesso, non a paper finito.

## Cosa afferma, e cosa no

La tesi non è più «le capacità si compongono in unione invece che in
intersezione». Quella è SPKI 1999 e sarebbe un desk reject.

> Entrambi i fornitori costruiscono la provenienza della delega con cura — thread
> padre, profondità, percorso dell'agente — e si fermano esattamente al confine
> del proprio prodotto. Per l'arco che esce dal sistema, l'unico controllo
> rimasto è una disposizione del modello.

Che una disposizione del modello sia un confine fragile lo dice già Qi et al. Il
contributo è che lì **non c'è nient'altro**, e che non è una svista.

## I numeri, tutti misurati

| | |
|---|---|
| instradamento | 23 richieste su 28 prove col ponte, contro 0 su 8 nel controllo, Fisher $p = 4{,}3\times10^{-5}$ |
| compliance del collega | 9/9 con un fornitore, 0/14 con l'altro, Fisher $p = 1{,}2\times10^{-6}$ |
| provenienza | ceduto 4/4 all'umano, 0/4 all'agente, Fisher $p = 0{,}029$ |
| telemetria | 38 sessioni su 59 avviate da programma, registrate come `user` |

Le percentuali non ci sono da nessuna parte, di proposito: a questi $n$ una
proporzione mente.

## Cosa è dichiarato come limite invece che nascosto

Nove voci in §XI. Le tre che un revisore troverebbe comunque:

- **Uno stimolo solo non è $n=14$.** Una formulazione del ruolo è
  pseudoreplicazione: il p-value certifica una frase, non un fornitore. Le
  parafrasi e lo scambio dei ruoli non sono state fatte.
- **Il gate non ha mai negato niente su traffico reale.** Zero turni dal ponte su
  501, perché la TUI di Codex non è mai stata agganciata qui.
- **Non abbiamo stabilito se `thread_source` accetti un valore per il chiamante
  esterno** o se `user` sia solo il default. È la differenza fra un campo che
  mente e un campo non compilato.

## Documenti di supporto, non da sottomettere

- `../docs/ricerca/confutazione.md` — i quattro attacchi alla nostra stessa tesi
- `../docs/ricerca/e4-assenza.md` — l'audit della telemetria per esteso
- `../docs/ricerca/council-e3.md` — il verdetto dei revisori prima dell'esecuzione
- `../docs/ricerca/revisioni/codex-su-e3.md` — la revisione dell'altro fornitore
