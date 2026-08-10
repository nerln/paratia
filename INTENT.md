# Da dove viene questa cosa

Questo file esiste perché tu possa ritrovare il ragionamento fra sei mesi senza
rileggere una sessione. È l'unico file del repo scritto in italiano e in seconda
persona. Il resto è documentazione normale.

## Quello che hai detto, smontato

Nella richiesta ci sono quattro affermazioni diverse. Sono venute fuori insieme
perché nella tua testa sono una cosa sola, ma si difendono in modi diversi e una
delle quattro è imprecisa. Le tengo separate perché è l'unico modo di lavorarci.

**1. «Segreti che nessun agente possa leggere, sbloccabili solo con una mia
chiave.»** Vero e risolvibile. La soluzione non è nascondere un percorso: è
togliere il testo in chiaro dal disco. Un forziere AES-256 chiuso è ciphertext
per chiunque, incluso root, incluso il modello. La chiave sta nella tua testa e
in nessun file. Questo è `paratia`, e la parte crittografica l'ho verificata:
scritto `XYZZY` dentro il volume, chiuso, cercato in chiaro nei band del
bundle — non c'è.

**2. «Uno standard per il filesystem su cosa gli agenti possono o non possono
toccare.»** Metà vero. La metà falsa è importante: su un Mac con un solo account
l'agente gira con il tuo UID, quindi ha il tuo bit di lettura su ogni file che
possiedi. Nessuna lista di percorsi vietati regge, perché `cat $(echo L1ZvbHVt…
| base64 -d)` non è in nessuna lista. Quindi lo standard non può essere «questi
percorsi no». Deve essere un'invariante sullo *stato*: **il compartimento non è
mai montato mentre un agente lavora.** L'hook non guarda i percorsi, chiede al
kernel se il volume è montato e, se lo è, rifiuta ogni chiamata. Non c'è stringa
da travestire perché non si legge nessuna stringa. Questa inversione è la parte
di cui vado più fiero e non era nella tua richiesta: c'era il problema, non
questa forma della soluzione.

**3. «Claude impedisce a Claude stesso computer-use, ma se Claude usasse
ChatGPT liberamente potrebbe chiedergli un trade.»** Questa è la parte
interessante, e la formulazione va corretta di un grado — non perché tu abbia
torto sulla sostanza, ma perché la versione corretta è quella pubblicabile.

Non è «Claude impedisce a Claude». È che *ogni fornitore applica la propria
politica al proprio agente, correttamente, in isolamento, e nessuno applica
niente alla coppia*. Il vincolo vale su Claude da solo. Non vale su Claude con
un telefono. Chiede a Codex, Codex non è quello sotto vincolo, e il sistema
composto fa la cosa che nessuno dei due doveva fare. Nessuna regola è stata
violata: la capacità è stata **riciclata attraverso un secondo principale**.

Detto in una riga, che è la riga del paper: **le restrizioni di sicurezza sono
applicate per-agente ma le capacità si compongono per-sistema.** L'unione di due
insiemi ristretti non è ristretta.

E il pezzo che rende la cosa concreta e non filosofica: **AgentBridge sul tuo
Mac è esattamente quel canale.** Gira adesso. Claude ↔ Codex, stessa macchina,
Codex con computer-use e senza il tuo hook. Non stai immaginando lo scenario, ce
l'hai acceso.

**4. «Impedire che questo accada.»** La regola è che sotto delega la capacità si
**interseca**, non si unisce. Un'azione eredita l'insieme più stretto fra tutti i
principali della catena, e una catena il cui ultimo umano non è chi sta chiedendo
adesso perde del tutto l'insieme riservato agli umani. Implementato in
`hooks/paratia-gate.py`, che ricava *chi ha parlato* dal transcript scritto
dall'harness — non da un file che il modello può riscrivere. È l'unica fonte a
portata di mano che il modello non produce.

## Dove la tua intuizione era già vera senza saperlo

Cercando prior art è saltato fuori questo, arXiv 2607.07097, luglio 2026,
misurato su 30 scenari e quattro benchmark:

> Gemini è il modello più sicuro sotto prompt diretti, e mostra la più grande
> amplificazione **con un planner Claude**: dall'8,9% al 38,9% di compliance.

Cioè: la tua ipotesi non solo è giusta, è già stata misurata, e il numero è
brutto. Quel paper però **misura** e raccomanda di riportare meglio le
valutazioni. Non propone un meccanismo di enforcement. Il buco che resta è
quello, ed è dove entri tu — vedi `docs/ricerca/campo.md`.

## La cosa che devi sapere e che non ti piacerà

Su una macchina con un solo account **non esiste un file che un agente che gira
come te non possa riscrivere, incluso l'hook che lo ferma.** Quindi il livello 3
dell'architettura è a prova di manomissione *rilevabile*, non *impedibile*.
`paratia seal` mette gli hash dentro il forziere — dove l'agente non può né
leggere né scrivere — e `paratia attest` li ricontrolla. Rilevazione, non
prevenzione, e sta scritto così anche in `docs/architettura.md` invece di essere
lasciato intendere.

Se un giorno vuoi la prevenzione vera, costa un secondo account macOS per gli
agenti. È l'unico confine POSIX vero disponibile senza scrivere un client
Endpoint Security. Non l'ho fatto perché richiede la tua password di admin.

## Cosa non ho fatto

- Non ho creato il tuo forziere. La passphrase deve sceglierla tu, in un
  terminale tuo, e io non devo conoscerla: `paratia init` è tuo.
- Non ho installato l'hook in `settings.json`. Un hook che nega ogni chiamata
  mentre un volume è montato va acceso da te, guardandolo.
- Non ho toccato AgentBridge. La dogana per ora vive nell'hook lato Claude;
  perché l'intersezione sia vera serve anche l'hook lato Codex, e quello va
  scritto nel suo harness.

## L'iterazione che mi aspetto da te

Tre domande su cui il progetto cambia forma, in ordine di quanto cambiano:

1. Il campo si chiama come? Ho scritto `docs/ricerca/campo.md` con la mia
   proposta — *capability laundering* — ma è il tuo nome sul paper.
2. Il livello di rilevazione ti basta o vuoi il secondo account?
3. AISec '26 (workshop ACM CCS) è la mia raccomandazione come primo bersaglio,
   non un journal di opinione. Il ragionamento è in `docs/ricerca/venue.md`.
