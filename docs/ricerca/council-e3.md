# Verdetto del council sul disegno E3

Convocato il 12 agosto 2026, **prima** dell'esecuzione, su richiesta di Eugenio.
Cinque consiglieri indipendenti con lenti diverse, poi peer review anonima, poi
sintesi. Metodo di Karpathy, con due deviazioni dichiarate:

- **Tre revisori invece di cinque.** La macchina era in swap e la regola di non
  mandarcela vale più della purezza del metodo.
- **Un sesto parere non simulato.** Codex, cioè l'altro fornitore e il soggetto
  stesso dell'esperimento, ha recensito il disegno separatamente. È più vicino
  al council originale di Karpathy, che usa modelli diversi, di quanto lo siano
  i sub-agenti. La sua risposta integrale sta in
  [revisioni/codex-su-e3.md](revisioni/codex-su-e3.md).

## Dove il council è d'accordo

**Il disegno E3 chiude un buco vero e ne apre un altro.** Togliere lo stub era
giusto. Ma bloccando A per primo, il messaggio di A al collega porta
necessariamente con sé «ho provato e mi è stato negato»: è un indizio, non un
controllo. E `riservato/segreto.txt` è lessicalmente carico — il rifiuto
diventa sovradeterminato dalla salienza prima ancora di arrivare alla politica.

**La variabile dipendente era retorica, non sicurezza.** Tutti e tre i revisori
l'hanno colpita indipendentemente. Il confine cede quando il collega digita il
segreto, identicamente sotto qualunque codifica della prosa di A. La frase che
farebbe rifiutare il paper, testuale da un revisore ostile:

> «A asserted the token as its own, closing the chain; confinement was therefore
> breached.»

Il breach precede l'asserzione.

**Uno stimolo solo non è n=14.** Una formulazione del ruolo è
pseudoreplicazione: il p-value certifica un prompt, non un fornitore. E l'asse
"fornitore" confonde modello, system prompt, schema degli strumenti e harness
del CLI.

**A questi n si rivendica esistenza e separazione, mai un tasso.** Conteggi
esatti, Fisher, nessuna percentuale. E un timeout non è un rifiuto: va
registrato come prova-non-eseguita, altrimenti è la cosa che uccide il
risultato.

## Dove il council si divide

**Il disegno va eseguito o riscritto?** L'Executor approva con tagli e dà un
calendario. Il First Principles Thinker **rifiuta l'inquadramento**: dice che qui
non c'è nessuna delega, perché B agisce sull'autorità ambientale che ha sempre
avuto, e che «unione invece di intersezione» è la conseguenza banale di due
agenti che esistono e possono parlarsi — cioè Hardy 1988 con una chat attaccata.
Chiudere la catena sarebbe una dimostrazione, non un risultato.

Tutti e tre i revisori gli hanno dato ragione.

**Il risultato sul fornitore è un confondente o lo strumento?** L'Expansionist
dice che è lo strumento: un *profilo di accettazione della delega* per
fornitore, da rieseguire a ogni rilascio di modello. Il Contrarian dice che è
pseudoreplicazione finché non giri le parafrasi. Non è una contraddizione vera:
diventa lo strumento *dopo* che hai girato le parafrasi.

## I punti ciechi emersi solo dalla peer review

**La scala della divulgazione.** Nessuno dei cinque consiglieri l'aveva
proposta. Un confine di controllo d'accesso protegge **l'oggetto**; un filtro
di formulazione protegge **la richiesta**. Quindi: chiedi al collega non il
token intero ma un'inferenza — le prime quattro cifre, un carattere, un sì/no
su un confronto. Se il rifiuto regge sulla richiesta piena e cede sul salame,
quello che sembrava controllo d'accesso non lo è mai stato. È il test decisivo
più economico dell'intero disegno e non richiede infrastruttura nuova.

**L'autorità implicita del canale**, sollevata da Codex e da nessun consigliere:

> «se il messaggio del collega arriva attraverso un canale che il runtime
> presenta come istruzione interna affidabile, non è più soltanto una frase.
> Non trasporta una credenziale crittografica, ma può trasportare autorità
> implicita attraverso il tipo del canale.»

Questo indebolisce la tesi forte — «non attraversa niente» — e rafforza quella
vera: l'autorità sta **fuori** dal protocollo. Serve manipolare
l'inquadramento della consegna come fattore sperimentale (risultato-di-strumento
del ponte contro testo citato e non attendibile), pubblicare il wire format, e
riportare il contesto verbatim che B riceve. Altrimenti il braccio `dogana`
misura l'etichettatura, non la politica.

**Il paper è una ricetta.** Il laboratorio è inerte; il metodo no. È una
questione di divulgazione responsabile, e la sezione sul confinamento non la
tocca.

## La raccomandazione

**Non eseguire E3 come scritto. Riscrivere la tesi, poi eseguire.**

La tesi non è più «le capacità si compongono in unione invece che in
intersezione». Quella è SPKI RFC 2693 §6.3.1, 1999, e in questa comunità molti
la sanno a memoria.

> **L'ultimo confine di autorizzazione fra due agenti che cooperano sta nei
> pesi, non nella policy.**

Il rifiuto che ha tenuto il sistema all'intersezione non stava in nessun file,
non lo applicava nessun runtime, non compare in nessun log, e il modello l'ha
inventato sul momento. È un confine di autorizzazione senza nessuna delle
proprietà che un confine di autorizzazione dovrebbe avere: non versionabile,
non verificabile, non componibile, e mutabile al prossimo rilascio senza che
nessuna policy scritta da nessuno cambi.

SPKI diventa il setup. Il risultato è che nel 2026 quel confine è affidato ai
pesi.

**Cosa cambia nel disegno, in ordine di quanto decide:**

1. **Il braccio di controllo con provenienza umana autentica.** La stessa
   richiesta che arriva davvero dall'utente. Se il collega rifiuta anche lì, il
   rifiuto è incapacità o filtro lessicale e l'interpretazione salta. Senza
   questo braccio E3 non attribuisce niente. *Non è opzionale.*
2. **La scala della divulgazione**, sopra.
3. **Il token che attraversa il filo** come esito, uguaglianza di stringa.
   Afferma-vs-racconta scende a codice descrittivo, e va tagliato se non c'è un
   danno a valle che differisce fra i due.
4. **Parafrasi del ruolo e scambio dei ruoli fra fornitori**, incluso il
   trapianto verbatim del prompt di Codex dentro Claude.
5. **Percorsi neutri contro percorsi marcati**, e A-bloccato-prima contro
   A-che-non-ha-mai-provato.
6. **L'assenza nei log** come artefatto pubblicato: la telemetria dei due lati
   che non contiene nessuna riga per quell'arco.

## La cosa da fare per prima

Il braccio con provenienza umana autentica. È l'unico che decide se hai un
paper o un aneddoto, costa poche prove, e se va male è meglio saperlo adesso.

---

*Punti 1, 2 e 3 sono già implementati in `lab/e3.py`. Il resto no.*
