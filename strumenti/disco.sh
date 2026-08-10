#!/bin/bash
#
# Three tiers on the external disk, and one thing to do tonight.
#
# Read on this machine before writing any of this, so the numbers are real and
# not an example:
#
#   Container disk6 is 1.0 TB and already holds TWO volumes sharing 448 GB free:
#     disk6s1  AppsAndFiles      483 GB used, APFS ENCRYPTED, mounted noowners
#     disk6s2  APFS-NonCriptata    1 MB used  — effectively empty
#
# So the thing you asked for — "preferirei delegargli un'altra partizione" —
# does not need repartitioning. APFS containers share free space between
# volumes, the second volume already exists, and it is empty. It costs nothing
# to hand over and there is no data to move.
#
# THE URGENT ONE, and it is not about agents at all.
#
# AppsAndFiles is encrypted with a single cryptographic user of type "Disk
# User" — a volume passphrase, not tied to your macOS account. That is the right
# design and it is why the disk is safe if it is stolen. But the volume mounts
# by itself, which means the passphrase is sitting in your login keychain, which
# means it is on the Mac.
#
# You asked for "recuperabile in qualche modo se perdo il mac". Right now, if
# the Mac dies and you do not independently know that passphrase, the 483 GB on
# that disk is gone — Vesuvius included. Step 1 fixes that and takes two
# minutes. Nothing else here matters as much.
#
# WHAT THIS SCRIPT DELIBERATELY DOES NOT DO
#
# It does not run `diskutil enableOwnership`. That command is only worth
# anything if a second account exists, and the research came back saying the
# second account is a bad trade on this machine (see docs/confini.md). It also
# carries a real risk here: files that arrived from another Mac carry a uid that
# is currently being ignored and would stop being ignored. Step 4 explains how
# to do it safely if you decide you want it.
#
# Run with no arguments to see the plan. --esegui to apply steps 2 and 3.

set -euo pipefail

VOL_MIO="/Volumes/AppsAndFiles"
DEV_MIO="disk6s1"
DEV_AGENTE="disk6s2"
VOL_AGENTE_ORA="/Volumes/APFS-NonCriptata"
NOME_AGENTE="Cantiere"

ESEGUI=0
[[ "${1:-}" == "--esegui" ]] && ESEGUI=1

for spia in CLAUDECODE CLAUDE_CODE_ENTRYPOINT CODEX_HOME CURSOR_AGENT; do
  if [[ -n "${!spia:-}" ]]; then
    echo "rifiuto: \$$spia è impostata. Questo script tocca i volumi del tuo disco." >&2
    echo "Aprilo in un terminale tuo." >&2
    exit 2
  fi
done

passo() { printf '\n\033[1m%s\033[0m\n' "$*"; }
nota() { printf '    %s\n' "$*"; }
fai()  { if (( ESEGUI )); then echo "  + $*"; eval "$@"; else echo "  · $*"; fi; }

(( ESEGUI )) || printf '\033[1mPROVA A VUOTO.\033[0m Niente viene cambiato.\n'

passo "0. Com'è il disco adesso"
diskutil list "$DEV_MIO" 2>/dev/null | sed -n '1,12p' | sed 's/^/    /'
df -h "$VOL_MIO" "$VOL_AGENTE_ORA" 2>/dev/null | sed 's/^/    /'

passo "1. LA COSA URGENTE — mettere al sicuro la passphrase del volume"
UUID="$(diskutil info "$DEV_MIO" 2>/dev/null | awk -F': *' '/Volume UUID/{print $2}' | tr -d ' ')"
nota "Il volume è cifrato con un solo utente crittografico, di tipo Disk User."
nota "UUID: ${UUID:-non letto}"
if security find-generic-password -s "$UUID" >/dev/null 2>&1; then
  nota ""
  nota "LA PASSPHRASE È NEL TUO PORTACHIAVI. Per questo il disco si monta da solo."
  nota "Se perdi il Mac e non la sai a memoria, i 483 GB non tornano."
  nota ""
  nota "Fallo adesso, a mano, perché non deve passare da uno script né da una"
  nota "sessione agente — finirebbe in un log o in un transcript:"
  nota ""
  nota "  1. Apri Accesso Portachiavi (Keychain Access)"
  nota "  2. Cerca:  $UUID"
  nota "  3. La voce si chiama \"Encrypted Volume Password\""
  nota "  4. Doppio clic, spunta \"Mostra password\", autentica"
  nota "  5. Copiala nel tuo gestore di password, E su carta, fuori casa"
  nota ""
  nota "Non la leggo io e non la stampo: sarebbe esattamente la cosa da cui"
  nota "paratia esiste per proteggerti."
else
  nota "Nessuna voce nel portachiavi per questo UUID."
  nota "O la passphrase la digiti a mano al montaggio (allora sei a posto, se la"
  nota "sai), oppure il volume non è cifrato come mi aspettavo: controlla con"
  nota "  diskutil apfs listCryptoUsers $DEV_MIO"
fi

passo "2. Il volume per gli agenti — esiste già ed è vuoto"
USATO="$(df -k "$VOL_AGENTE_ORA" 2>/dev/null | awk 'NR==2{print $3}')"
if [[ -z "${USATO:-}" ]]; then
  nota "$VOL_AGENTE_ORA non è montato. Salto."
elif (( USATO > 102400 )); then
  nota "ATTENZIONE: $VOL_AGENTE_ORA contiene $(( USATO / 1024 )) MB, non è vuoto."
  nota "Non lo tocco. Guarda cosa c'è dentro prima di riusarlo."
else
  nota "Vuoto ($(( USATO ))K). Diventa il volume di lavoro degli agenti:"
  nota "cifrato per conto suo, con la sua passphrase, e nel container che già c'è."
  nota "Nessun ripartizionamento, nessun dato da spostare, spazio condiviso."
  fai "diskutil rename $DEV_AGENTE $NOME_AGENTE"
  nota ""
  nota "Per cifrarlo serve una passphrase che scegli tu, quindi va a mano:"
  nota "  diskutil apfs encryptVolume $DEV_AGENTE -user disk"
  nota "Chiede la passphrase e cifra in background senza smontare. Mettila nel"
  nota "gestore di password come quella del passo 1."
fi

passo "3. Le tre fasce, e cosa vale ciascuna"
nota "FASCIA 1  $VOL_MIO — i tuoi dati."
nota "          Cifrato a riposo: se ti rubano il disco non leggono niente."
nota "          Montato, lo legge chiunque giri come te, agenti compresi."
nota "          Questo non è aggirabile: vedi la fascia 3."
nota ""
nota "FASCIA 2  /Volumes/$NOME_AGENTE — il lavoro che gli agenti possono toccare."
nota "          Il confine qui è organizzativo, non tecnico, finché gli agenti"
nota "          girano come te. Serve a sapere sempre cosa è esposto e cosa no."
nota ""
nota "FASCIA 3  lo specchio — l'unica che risolve davvero \"l'IA legge tranquilla\"."
nota "          paratia specchio nuovo lavoro --da <fascia 1> --a /Volumes/$NOME_AGENTE/specchio"
nota "          paratia specchio sincronizza lavoro"
nota "          Gli identificatori diventano token; la tabella per tornare"
nota "          indietro sta nel forziere, che l'agente non può aprire."

passo "4. enableOwnership — solo se fai davvero il secondo account"
if mount | grep -q "on $VOL_MIO .*noowners"; then
  nota "$VOL_MIO è noowners: i permessi lì non contano."
  nota "Ha senso cambiarlo SOLO se esiste un secondo account. Con un account solo"
  nota "non compra niente, e ha un rischio vero."
  nota ""
  nota "Se decidi di farlo, la procedura sicura è questa e non un comando solo:"
  nota "  1. chiudi VMware e ferma Time Machine"
  nota "  2. sudo diskutil enableOwnership $VOL_MIO"
  nota "  3. controlla subito: ls -l $VOL_MIO/VMWIsoImages $VOL_MIO/dev"
  nota "  4. se qualcosa è illeggibile:  sudo diskutil disableOwnership $VOL_MIO"
  nota ""
  nota "Il rischio: i file arrivati da un altro Mac hanno un uid che finora era"
  nota "ignorato. Da lì in poi non lo sarebbe più. Vesuvius sta su questo disco e"
  nota "scade il 31 agosto — se lo fai, fallo dopo."
fi

passo "Fatto"
if (( ESEGUI )); then
  nota "Rimane a mano: il passo 1 (portachiavi) e la cifratura del passo 2."
else
  nota "Prova a vuoto. Il passo 1 fallo comunque, anche senza --esegui."
fi
