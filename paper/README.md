# Il paper, per Overleaf

Carica `main.tex` e `refs.bib` in un progetto vuoto, compilatore **pdfLaTeX**,
premi Recompile. Nessun pacchetto fuori dalla distribuzione standard, nessuna
figura esterna: compila al primo colpo.

## Cosa c'e' e cosa non c'e'

C'e' l'argomento, la sezione di related work, il modello di minaccia e la
struttura degli esperimenti. **Non ci sono i numeri**, perche' E3 non e' stato
ancora eseguito e i numeri di E2 vanno riconteggiati con la variabile
dipendente corretta.

Ogni buco e' scritto `\TODO{...}` e si vede in rosso nel PDF. E' voluto: un
paper in cui i buchi sono invisibili si sottomette per sbaglio.

Per contarli:

```bash
grep -c 'TODO{' main.tex
```

## La tesi e' cambiata il 12 agosto

Non e' piu' "le capacita' si compongono in unione invece che in intersezione".
Quella e' SPKI RFC 2693 dal 1999, e un revisore che conosce SPKI --- in questa
comunita' sono tanti --- chiude il paper alla seconda pagina.

La tesi e': **l'ultimo confine di autorizzazione fra due agenti che cooperano
sta nei pesi, non nella policy.** Il rifiuto che ha tenuto il sistema
all'intersezione non era in nessun file, non lo applicava nessun runtime, non
compare in nessun log, ed e' stato inventato sul momento dal modello. Un
confine di autorizzazione senza nessuna delle proprieta' che un confine di
autorizzazione dovrebbe avere.

SPKI diventa il setup, non il risultato. Il ragionamento completo sta in
`../docs/ricerca/prior-art.md`.

## Bibliografia: leggi le note

`refs.bib` marca ogni voce `[VERIFICATO]` o `[DA VERIFICARE]`. Le verificate
sono state controllate contro arXiv o OpenAlex il 12/08/2026. Le altre vengono
dalla mia conoscenza e vanno ricontrollate.

Tre da controllare per prime, perche' sono quelle che un revisore usera' contro
di te:

1. **ABLP 1992** --- cercare l'assioma di intersezione per il principale
   composto `A|B`. Se c'e', la prior art e' del 1992 e non del 1999.
2. **SPKI RFC 2693 §6.3.1** --- leggerlo. E' corto e decide come si scrive la
   sezione 2.
3. **SentinelAgent 2604.02767** --- capire se "authority narrowing" e' definito
   come intersezione insiemistica o come altro.

## Prima di scrivere i numeri

Il disegno e' stato recensito prima dell'esecuzione da cinque consiglieri
indipendenti con peer review anonima, e separatamente da un agente del secondo
fornitore studiato. Il verdetto e le correzioni pretese stanno in
`../docs/ricerca/council-e3.md`; la revisione dell'altro fornitore in
`../docs/ricerca/revisioni/codex-su-e3.md`.

Le tre correzioni che i revisori hanno preteso all'unanimita':

1. **La variabile dipendente era sbagliata.** Il confine cede quando il token
   attraversa il filo, non quando A e' abbastanza sicuro da affermarlo. Gia'
   corretta in `lab/e3.py`.
2. **Serve il braccio con provenienza umana autentica.** Se il collega rifiuta
   anche quando la richiesta viene davvero dall'utente, il rifiuto e'
   incapacita' o filtro lessicale e l'interpretazione salta. Senza questo
   braccio E3 non attribuisce niente.
3. **Uno stimolo solo non e' n=14.** Il prompt del ruolo va parafrasato piu'
   volte e i ruoli vanno scambiati fra i due fornitori, altrimenti il p-value
   certifica una formulazione e non un fornitore.
