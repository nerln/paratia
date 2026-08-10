#!/bin/bash
#
# Give agents a second local account to run in, without moving you into it.
#
# The usual advice — "run the agent as another user" — quietly assumes you will
# go and live in that account. You said no, and you are right to: you would lose
# the desktop app, the browser pane, computer-use, your Drive mount, your gh
# auth and your SSH keys, all in exchange for a boundary you only need on some
# of your sessions.
#
# So this does the other thing. You stay uid 501 with everything working. A
# second account exists that owns nothing of yours and can read nothing of
# yours, and a wrapper starts a Claude Code session inside it on demand. The
# tier is chosen per session, by what that session is allowed to touch:
#
#   normal session      you, uid 501       everything works, nothing is confined
#   confined session    _claude            reads only the shared yard, no GUI,
#                                          no keys, no Drive, no computer-use
#
# Which is the honest arrangement, because a boundary you have to cross for
# every task is a boundary you will switch off in a week.
#
# TWO THINGS THIS DOES NOT FIX, both verified on your machine:
#
#   /Volumes/AppsAndFiles is mounted noowners. On that disk the mode bits are
#   discarded and a second account has full access to everything regardless of
#   ownership. UID separation buys nothing there. Step 5 offers to change it,
#   and explains what that breaks.
#
#   Google Drive replicates your files to a server. No local account boundary
#   reaches that copy. Only `paratia zona` does, by putting ciphertext in the
#   folder that syncs.
#
# Run it with no arguments first: it prints what it would do and changes
# nothing. Add --esegui when you have read the output.

set -euo pipefail

UTENTE_AGENTE="_claude"
GRUPPO="cantiere"
CANTIERE="/Users/Shared/cantiere"
IO="$(id -un)"
MIA_HOME="$HOME"

ESEGUI=0
[[ "${1:-}" == "--esegui" ]] && ESEGUI=1

# An agent must never be the thing that creates an account for agents. This is
# a courtesy rail — the real one is that sysadminctl will ask for a password
# nobody in a session can type.
for spia in CLAUDECODE CLAUDE_CODE_ENTRYPOINT CODEX_HOME CURSOR_AGENT; do
  if [[ -n "${!spia:-}" ]]; then
    echo "rifiuto: \$$spia è impostata, quindi questa è una sessione agente." >&2
    echo "Questo script crea un account e cambia i permessi della tua home." >&2
    echo "Aprilo in un terminale tuo." >&2
    exit 2
  fi
done

passo() { printf '\n\033[1m%s\033[0m\n' "$*"; }
fai()   { if (( ESEGUI )); then echo "  + $*"; eval "$@"; else echo "  · $*"; fi; }
nota()  { printf '    %s\n' "$*"; }

if (( ! ESEGUI )); then
  printf '\033[1mPROVA A VUOTO.\033[0m Niente viene cambiato. Rilancia con --esegui.\n'
fi

passo "1. L'account per gli agenti"
if dscl . -read "/Users/$UTENTE_AGENTE" >/dev/null 2>&1; then
  nota "$UTENTE_AGENTE esiste già, salto."
else
  nota "Utente standard, senza privilegi di admin, nascosto dalla finestra di login."
  nota "Non ci entrerai mai da interfaccia: serve solo a possedere dei processi."
  fai "sudo sysadminctl -addUser $UTENTE_AGENTE -fullName 'Agenti' -password - -home /Users/$UTENTE_AGENTE"
  fai "sudo dscl . -create /Users/$UTENTE_AGENTE IsHidden 1"
  fai "sudo dscl . -create /Users/$UTENTE_AGENTE UserShell /bin/zsh"
fi

passo "2. Chiudere la tua home"
MODO="$(stat -f '%Lp' "$MIA_HOME")"
nota "Adesso è $MODO. Con 750 il gruppo legge, e su macOS ogni account locale"
nota "sta in staff: senza questo passo $UTENTE_AGENTE leggerebbe tutta la tua"
nota "home dal primo minuto, chiavi SSH comprese, e i passi 1 e 3 sarebbero teatro."
if [[ "$MODO" == "700" ]]; then
  nota "già a 700, salto."
else
  fai "chmod 700 '$MIA_HOME'"
  nota "Per tornare indietro: chmod $MODO '$MIA_HOME'"
fi

passo "3. Il cantiere condiviso"
nota "L'unico posto che entrambi vedono. Sta sul disco interno, che è l'unico"
nota "che fa rispettare la proprietà dei file."
if dscl . -read "/Groups/$GRUPPO" >/dev/null 2>&1; then
  nota "gruppo $GRUPPO già presente, salto."
else
  fai "sudo dseditgroup -o create $GRUPPO"
  fai "sudo dseditgroup -o edit -a $IO -t user $GRUPPO"
  fai "sudo dseditgroup -o edit -a $UTENTE_AGENTE -t user $GRUPPO"
fi
fai "sudo mkdir -p '$CANTIERE'"
fai "sudo chgrp $GRUPPO '$CANTIERE'"
fai "sudo chmod 2770 '$CANTIERE'"
nota "Il 2 davanti è setgid: i file creati qui dentro nascono già del gruppo."
nota "Da solo non basta, perché non fissa i permessi. Serve anche l'ACL:"
fai "sudo chmod +a '$GRUPPO allow list,add_file,search,delete,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,file_inherit,directory_inherit' '$CANTIERE'"
nota "file_inherit e directory_inherit sono la parte che conta: senza, il primo"
nota "file che scrive l'agente torna leggibile solo a lui e te ne accorgi dopo."

passo "4. Il comando per una sessione confinata"
BIN="$MIA_HOME/.local/bin/claude-confinato"
nota "Scrive $BIN. Lo lanci tu, dal tuo terminale, quando vuoi quel livello."
if (( ESEGUI )); then
  mkdir -p "$(dirname "$BIN")"
  cat > "$BIN" <<SCRIPT
#!/bin/bash
# Una sessione Claude Code dentro l'account degli agenti.
#
# Cosa perdi qui dentro, e va saputo prima: niente app desktop, niente
# computer-use, niente pannello browser, niente accesso al Drive, niente chiavi
# SSH e niente gh. Sono le stesse capacità che rendono grave il riciclaggio,
# quindi perderle è il punto e non un effetto collaterale.
#
# Cosa vedi: solo $CANTIERE.
set -euo pipefail
CARTELLA="\${1:-$CANTIERE}"
case "\$(cd "\$CARTELLA" 2>/dev/null && pwd -P)" in
  $CANTIERE|$CANTIERE/*) ;;
  *) echo "claude-confinato: \$CARTELLA sta fuori dal cantiere ($CANTIERE)." >&2
     echo "Una sessione confinata che lavora fuori dal cantiere non è confinata." >&2
     exit 2 ;;
esac
exec sudo -u $UTENTE_AGENTE -i /bin/zsh -lc "cd '\$CARTELLA' && exec claude"
SCRIPT
  chmod +x "$BIN"
  echo "  + scritto $BIN"
else
  echo "  · scriverebbe $BIN"
fi

passo "5. Il disco esterno — il passo che potresti non volere"
if mount | grep -q "on /Volumes/AppsAndFiles .*noowners"; then
  nota "/Volumes/AppsAndFiles è montato noowners: lì la separazione fra utenti"
  nota "non esiste, e $UTENTE_AGENTE leggerebbe e scriverebbe tutto comunque."
  nota ""
  nota "Si può accendere il rispetto della proprietà:"
  nota "    sudo diskutil enableOwnership /Volumes/AppsAndFiles"
  nota ""
  nota "COSA COSTA, e per questo non lo faccio io: da quel momento i file su"
  nota "quel disco hanno un proprietario che finora era ignorato. Il materiale"
  nota "Vesuvius sta lì (villa, op6-causal, vesuvius-op6) ed è il progetto che"
  nota "non può perdere operatività. Se qualche file risulta di un uid diverso"
  nota "dal tuo — capita a tutto ciò che è arrivato da un altro Mac o da un"
  nota "backup — dopo diventa illeggibile finché non fai chown. Provalo quando"
  nota "hai tempo di sistemare, non prima di una scadenza."
  nota ""
  nota "L'alternativa che non tocca la proprietà: 'paratia zona', che mette"
  nota "cifratura sul contenuto invece che permessi sul volume."
else
  nota "/Volumes/AppsAndFiles non risulta montato noowners adesso. Ricontrolla"
  nota "con 'paratia esposizione' dopo averlo rimontato."
fi

passo "Fatto"
if (( ESEGUI )); then
  echo "  Verifica con:  paratia esposizione"
  echo "  Sessione confinata:  claude-confinato"
  echo "  Sessione normale:  claude   (invariata, con tutto)"
else
  echo "  Prova a vuoto. Rilancia con --esegui quando hai letto il passo 5."
fi
