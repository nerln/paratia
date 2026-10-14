# paratia

[Site](https://nerln.github.io/paratia/) · [agent manual](https://nerln.github.io/paratia/llms.txt) · [SSH bridge](docs/ponte-ssh.md) · [paranco](https://github.com/nerln/paranco)

**A deny list is a list of the paths somebody thought of.** This is not one.

Watertight bulkheads are what stop a flooded compartment from taking the ship.
They do not ask the water where it is going.

## The problem, in two halves

**Half one.** You want a file an agent cannot read. The usual answer is to write
that down — a line in CLAUDE.md, a path in a deny list, a sentence in a skill.
All three live in the same place the agent's instructions live, so a model that
misreads them gets past all three, and so does a web page carrying an
instruction of its own that gets fetched mid-task. Worse, none of them is even
tested by the thing it claims to stop: the agent runs as your user, so it holds
your read bit on every file you own. `/Volumes/vault/token` is on your list.
`cat "$(printf '/Volumes/va''ult/token')"` is not, and never will be.

**Half two, which is the one nobody has fixed.** Claude will not drive
computer-use. Codex will. On this machine they are wired together by AgentBridge.
Each vendor enforces its own policy over its own agent, correctly, in isolation,
and nobody enforces anything over the pair. So the restriction that holds for
Claude alone does not hold for Claude with a phone line: it asks Codex, Codex
was never under that rule, and the composite system does the thing neither was
supposed to do. No policy was violated. The capability was laundered through a
second principal.

Said once: **restrictions are enforced per-agent, capabilities compose
per-system.** The union of two restricted sets is not restricted.

This is measured, not hypothetical. [arXiv:2607.07097](https://arxiv.org/abs/2607.07097)
finds Gemini the safest model under direct prompts and the most amplified under
a Claude planner — 8.9% to 38.9% compliance on harmful scenarios.

## What this does about each half

**Half one: remove the plaintext, do not hide the path.** Secrets live in an
AES-256 sparsebundle. Locked, the bytes on disk are ciphertext, and that holds
against every process at every privilege level, this program included. The
passphrase is in your head and in no file, so there is nothing for an agent to
find, and `unlock` refuses to run inside an agent session.

That leaves the window while it is open, and the window is held shut from the
other side. `paratia gate` is a PreToolUse hook that denies **every** agent tool
call for as long as the volume is mounted. It never looks at a path. It asks the
kernel one question — is this mounted — and there is no way to spell your way
around a bit the kernel owns. Coarse on purpose: coarse is what makes it hold.

What an agent gets instead is `paratia broker`. Verbs are declared inside the
compartment, where the agent can neither read nor extend them, and each is a
fixed argument list with the secret filled in by this program. The agent names a
verb and reads the output. It never holds the value and never picks the command.

**Half two: make capability intersect under delegation.** The same hook reads
the transcript — written by the harness, not by the model, which is the entire
reason it is worth reading — finds who actually spoke last, and if the answer is
another agent rather than you, takes the human-only set off the table for that
turn. Computer-use, the browser, the simulator, `paratia` itself, `security`,
`sudo`, `osascript`.

## Install

```bash
pip install git+https://github.com/nerln/paratia.git
paratia doctor
```

Or from a checkout, which is what you want if you also intend to run the hooks
and the scripts in `strumenti/`:

```bash
git clone https://github.com/nerln/paratia.git ~/dev/paratia
ln -s ~/dev/paratia/paratia.py ~/.local/bin/paratia
paratia doctor
```

Python 3.11+, macOS, no third-party packages.

`pip install` gives you the command. The native app is built separately; it can
review and connect the session hooks while preserving existing configuration.
For a CLI-only checkout, wire them into `~/.claude` by hand as described below.
Without that step you have the encrypted compartment without the session gate.

Then, in your own terminal, never in an agent session:

```bash
paratia init
```

It asks for a passphrase twice and writes it nowhere. Lose it and the contents
are gone — that property is the reason an agent cannot open this.

Add the hook to `~/.claude/settings.json` under `PreToolUse` with matcher `*`,
pointing at `hooks/paratia-gate.py`, then seal it so you find out if it changes:

```bash
paratia unlock && paratia seal ~/dev/paratia/hooks/paratia-gate.py ~/.claude/settings.json && paratia lock
```

## Mac app, existing folders and access history

The native app for macOS 13+ has **Cartelle**, **Registro**, **Etichette**,
**Banco di prova** and **Impostazioni**. To protect an existing folder, choose that
one folder and its passphrase in the GUI. The encrypted image (AES-256) is saved
automatically on the same disk, in a hidden place, so no external disk is needed.
The folder's content moves into the image, and the plaintext is removed only after
verification: closed, the folder is empty; opened with the passphrase, it shows its
files again. **Togli la protezione** puts the files back into the folder as normal
files, verified, and then deletes the image. If you prefer another location, you can
pick any local physical disk, internal or external; disk images, network or
cloud-synced folders, and a location inside the folder itself are refused. Migration
verifies the data before removing the source; an interrupted migration keeps recovery
actions visible. Timed closure retries a busy mount without force. Locations are
checked through their physical stores to the whole disk: APFS through its physical
stores, exFAT through its parent whole disk. Key verification
checks an encrypted image without mounting it, independently of localized
authentication messages. If the folder is busy, close apps using it and
terminals whose current directory is inside it. **Forza chiusura…** requires
explicit confirmation and can lose unsaved changes. In your own terminal,
`paratia cartella chiudi <id> --force` also requires confirmation on `/dev/tty`
and refuses to run inside an agent session. A busy-volume diagnostic lists
process names and PIDs when available, without their command arguments.
Before checking the key, missing image metadata or bands and unreadable or
truncated encrypted-v2 tokens produce a damaged-image message. Keep the image
and restore an intact copy. This structural check does not verify every band's
cryptographic integrity.

In **Registro**, use **Sorveglia una cartella…** to choose any supported folder
you own, including an unencrypted one. Remove watches, filter events by folder,
file, process, agent and time, and export CSV. Configured watches and daemon
acknowledgements are shown separately: saving a watch does not mean collection
is active. Repeating a path keeps its ID; an explicit `--nome Nuovo` renames the
watch and reports the effective name. Omitting the name preserves an existing
label. Nonexistent folders and unknown removals are refused. A protected folder's
mount path is already registered and cannot create a separate ambiguous watch.
On an external physical volume mounted with ownership ignored (`noowners`),
the collector cannot use `stat` UID as proof of ownership. It accepts a selected
folder only through the validated user-owned configuration and an external,
non-system volume check. Invalid entries are refused individually, preserving
other watches; the CLI and app show each collector refusal and its reason.
A confirmed watch survives a temporary disappearance of its unchanged path,
with a warning. Volume proofs are cached while their kernel identity remains
unchanged; a timeout preserves a confirmed watch, while new or replaced paths
still require validation. Slow volume probes run outside the stream reader.
The CLI offers the
same operations:

```sh
paratia registro sorveglia ~/Documenti/progetto
paratia registro sorveglianza
paratia registro elenco --cartella ~/Documenti/progetto
paratia registro esporta --cartella ~/Documenti/progetto
paratia registro smetti ~/Documenti/progetto
```

`paratia registro rotte-paranco` reads paranco's route file in read-only mode and proposes which folders to watch. `--esegui` applies those proposals, and it refuses to run inside an agent session. Limits and examples are in [Rotte di paranco](docs/registro-accessi.md#rotte-di-paranco).

`elenco` and `esporta` warn on stderr when collection is stopped or unhealthy,
including empty results. The CLI and worker query/CSV accept a folder ID or an
exact configured absolute path, with slash, alias and NFC/NFD normalization.
Unknown or ambiguous paths produce specific messages in the app. Query and
export results include `kernel_active` and collection details; the Registry view
shows active, inactive or unverified collection beside the event count, including
zero events. For a selected folder, active also requires acknowledgement of its
ID. This does not guarantee coverage of every access. An absolute `--file /a/b` matches that
path and its descendants, excluding `/a/bc`; paths normalize slashes and NFC/NFD Unicode.
Relative text uses case-insensitive `casefold` matching. New log timestamps use
colon-separated offsets; legacy offsets remain readable with Python 3.9.

The default subscription is `open`, `write`, `create`, `rename`, `unlink`,
`truncate`, plus `exec`, `fork` and `exit` for ancestry. It excludes `close`,
`mount`, `unmount`, `lookup` and `mmap` to reduce system-wide traffic. The live
measurement of 14 October was taken with the previous, larger subscription; the
effect of this reduction has not been measured live yet. `open` says who opened a path; `write`, `create`, `rename`,
`unlink` and `truncate` say who changed it. Writes made only through `mmap` are
no longer reported. Mounts and unmounts are not in the kernel registry; opening and
closing a protected folder stays in Paratia's own log. Before JSON decoding,
the collector filters unrelated raw lines, recognizing Data/private path aliases
and JSON encodings, while retaining sequence numbers for loss detection.
Roots containing JSON control escapes use full decoding to preserve events.
This does not add a guarantee for inherited mappings or byte reads.
`paratia registro stato` reports observed event latency, last receive time,
lines/s and readable `health_reasons`. The app shows delayed events, refused
watches and absence of confirmed folders as reasons for an unhealthy state; idle time
alone is not delay. A loss is counted in `dropped_events` for the whole run. It is a
notice, not a blocker: it does not make `healthy` false, and the app shows it as a
notice only for the ten minutes after it was observed.
The repeatable synthetic throughput measurement is documented in
[the October status](docs/stato-2026-10.md). It measures Python processing,
excluding eslogger and log fsync; live idle CPU and delay must be measured again
after installing this build.

The registry keeps metadata from Paratia operations and observed kernel events,
with distinct sources. An open event does not prove a byte read; missing events
do not prove that no access occurred. **Banco di prova** displays four phases,
counts, times, measured access results and any matching kernel evidence. Its
`mdls` probe is informational: Spotlight caches and unindexed mounted images
do not determine the phase outcome.

<img src="docs/immagini/paratia-icona.png" alt="Paratia: a sealed folder with a watertight door and wheel" width="128" height="128">

Build locally with Apple Command Line Tools and `rsvg-convert` (librsvg):

```sh
python3 strumenti/build-app.py --render-fixtures
open -n build.noindex/Paratia.app --args --launch-check
~/.local/bin/installa-app build.noindex/Paratia.app
```

The build bundles the CLI with the other nine Python modules. Its hook manifest
points to the protected bootstrap copy, never the writable repository.
The `.noindex` output directory keeps the development app out of Spotlight.
`strumenti/make-icon.py` renders `macos/Assets/Paratia.svg` at all ten macOS
icon sizes, then runs Apple's `iconutil`; the build includes `Paratia.icns`
and sets `CFBundleIconFile`. The PNG preview is rendered from the same source.
If conversion fails, the generator reports the error and retains the iconset
for inspection. Native ICNS conversion still needs the supervisor's build:
`iconutil` rejected the valid PNG set in this sandbox.

Close all copies of Paratia and run this yourself in Terminal to prepare a
separate root-owned bootstrap copy. It is needed for the first installation of the
service, and afterwards only when the service code changes: a new build alone does not
need it. The current command is in the [GUI guide, section Impostazioni](docs/gui-mac.md#impostazioni): copy it from there.

The command leaves `/Applications` permissions unchanged. It stages the copy
in a root-only directory, refuses links and special files before ownership or
permission changes, and verifies its signature before and after publication.
After that succeeds, it removes root-owned `.prepara.*` directories and the
old bootstrap app under `ParatiaBootstrap`. The new `.noindex` parent keeps
the bootstrap copy out of Spotlight without changing its protection. Only after exit code 0,
open `/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app` **from Finder**
for **Impostazioni → Installa il registro…** and the macOS administrator dialog.

Before the dialog, the bootstrap checks its signature, every bundle member and
all ancestors for root ownership and absence of group/other or ACL write access.
It retains the same signature as the normal app; ownership changes preserve
CDHash. The supervisor observed working TCC propagation and kernel events on
14 October 2026 after the human installation. Refresh the bootstrap copy and reinstall the service, then verify the new identity, only when the service code changes.

The daemon launches a native executable in a root-protected copy of the signed
app at `/Library/Application Support/Paratia/Paratia.app`, separate from the
bootstrap copy; it keeps Python and eslogger as children. In Full Disk Access, enable
**`/Applications/Paratia.app`**; remove and re-add it after every new ad hoc build (with a stable identity, only when the signature changes),
and reinstall the registry copy only when the service code changes. Do not enable Python 3.9.
Giro 6 was published as `91914a0` and installed. Its registry installation failed
and left the service unloaded, as reported by the supervisor. Giro 7 waits for
launchd removal, retries race errors, checks rollback and shows the installer
message and error code in the app. This update requires a new build, bootstrap
copy, registry installation and renewed Full Disk Access.
The app compares the installed collector's CDHash with `/Applications/Paratia.app`
and shows the update steps in order as a notice, not a blocker: the update is optional
and needed only when the service code changes. Older collectors without an identity report
are shown as unverified, without claiming two hashes were compared.

The app is signed ad hoc by default and is not notarized. Keep the normal app in `/Applications`.

To keep the Full Disk Access permission across builds, sign with a stable identity
from your keychain: `python3 strumenti/build-app.py --sign-identity "<certificate name>"`,
or set `PARATIA_SIGN_IDENTITY`. Without the option the build stays ad hoc and never
opens a keychain. With a stable identity the permission is tied to the signing
certificate, so builds signed with the same certificate keep it. The installer still
requires the installed copy to match the source CDHash and to pass
`codesign --verify --deep --strict`. The root trust anchor, `sudo bootstrap`, is unchanged.
The stable identity path was not run with a real certificate in this session; check
the permission after the first build.

The app is available in Italian, English and Spanish. It follows the macOS language,
with English as the fallback. Change it in **Settings → Language**: the window changes
at once, and the menu item changes after a restart.

See the [GUI guide](docs/gui-mac.md), [registry limits](docs/registro-accessi.md)
and [October 2026 implementation and verification status](docs/stato-2026-10.md).

## Use

```bash
paratia unlock            # your terminal, asks for the passphrase, auto-locks in 15 min
paratia put OPENAI_KEY    # value typed, not echoed, never on a command line
paratia ls
paratia lock
```

`paratia status` also lists open protected folders and unresolved migrations.
While a compartment is open, the gate permits `paratia cartella chiudi <id>`,
`paratia cartella chiudi-tutte`, `paratia cartella elenco`, `paratia lock`,
`paratia status` and `paratia status --json`. Equivalent absolute invocations,
including the absolute path to the `~/.local/bin/paratia` symlink and
an isolated Python invocation, must resolve to the protected bootstrap CLI.
The CLI, its Python resources and all ancestors must be root-owned, without
group/other or ACL write access. The literal `~/.local/bin/paratia` form expands
against the account's real home, then undergoes the same checks. A repository
CLI or an unprotected app has no exemption: close the folder from Paratia or
Finder. `paratia lock` closes the
main compartment; use `cartella chiudi` or `chiudi-tutte` for folder compartments.

Without that code check, an agent could alter a sibling module while the folder
is closed, then import it via an exempt status/close command when the human
opens the folder. The protected copy closes that route. User-owned hook settings
and other harnesses remain outside the guarantee; this does not make the whole
same-account setup tamper-proof. See [architecture](docs/architettura.md).

The optional CLI alias must point to the protected copy to qualify. Until the
human updates an alias that still points to the repository, use Paratia to close
the folder or the protected script's absolute path. Its bundled shebang uses
the verified Apple runtime with `-I -S -B`; explicit Python calls need those
same flags.

Declaring a verb, so an agent can use a key it cannot read. Edit `verbi.json`
inside the compartment while it is open:

```json
{
  "deploy": {"comando": ["curl", "-sS", "-H", "Authorization: Bearer <OPENAI_KEY>", "{}"]}
}
```

`<NAME>` is replaced by the secret stored under that name, `{}` by whatever the
agent passed. Now `paratia broker deploy https://api.example/v1/ping` works in a
session, and the key never appears in the transcript.

```bash
paratia attest            # did anything that enforces this change since you sealed it?
```

## Zones, which are not compartments

A compartment hides secrets **from** the session. A zone hides work from
everyone who **is not** the session. Conflating them gives you a workspace
nobody can work in.

```bash
paratia zona nuova lavoro --dove /Volumes/SSD --size 40g
paratia zona apri lavoro          # mounts at /Volumes/zona-lavoro
paratia zona chiudi lavoro
```

An open zone does not stop the session — the gate ignores zone mountpoints
entirely — because an agent that cannot read the repository cannot work on it.
What a zone buys is everything else: another local account, a stolen disk, and
the copy your cloud provider keeps. Creating one inside a synced folder is
refused by default, for a reason spelled out in [docs/confini.md](docs/confini.md).

## Labels, which are a plan and not a boundary

The compartment answers *how*. It does not answer *what*, and on a disk with
three hundred thousand files that is the part that actually stops people.

```bash
paratia etichetta segna ~/Documenti/contratti --come riservato --nota "scans"
paratia etichetta segna ~/dev/tesi --come zona:tesi
paratia etichetta piano          # what applying these would move, and where
paratia etichetta applica        # prints only; --esegui to copy
```

The vocabulary is four words and stays four words: `riservato` (into the
compartment), `zona:<name>` (into that encrypted zone), `pubblico` (looked at,
deliberately left alone), and absent (nobody has looked yet, which is the state
`piano` counts loudest). A label on a folder carries to everything under it
until a nearer label says otherwise, so a `pubblico` subfolder carves an
exception out of a `riservato` parent — and both the plan and the copy honour
the carve-out.

`paratia finder` serves one page to your own browser and does the same job with
a mouse, on macOS, Linux and Windows, because the standard library has an HTTP
server on all three and a native toolkit worth shipping on none. It binds
loopback, mints a token per run that is never written to disk, refuses to start
inside an agent session, and **never sends file contents** — names, sizes and
labels only. `?dove=<path>` opens it straight at a folder.

> **Read this part twice.** The label store is `~/.paratia/etichette.json`: a
> file in your home directory, owned by the uid the agent runs as. It can read it
> and it can rewrite it. Wiring it into the gate as a deny rule would buy nothing
> either, for the reason this whole README is about — a rule about paths is a
> rule about spellings. What protects bytes is `applica` moving them somewhere
> encrypted, where the cipher does the work. The label is the decision; the move
> is the mechanism. `applica` also never deletes your original: `rsync` and
> `stiva` do verified moves better than a reimplementation here would, and a
> program that copies and deletes on the same run is one bug away from doing
> only the second.

## Two machines, and the key that cannot open a shell

Wiring two agent sessions together over SSH so they can collaborate turns a
normal key into remote code execution: an agent running as you reads `~/.ssh`
exactly as you do. And a turn that arrives over SSH is, to the receiving
harness, indistinguishable from you typing.

```bash
paratia-fanale chiavi     # a bridge-only key, plus the far-side line that confines it
```

It prints the `authorized_keys` line to install on the **other** machine:

```
command="/usr/local/bin/fanale ascolta",restrict ssh-ed25519 AAAA...
```

That line is the only control here an agent running as you cannot undo, because
the file granting it lives on the other machine. The holder of that key can run
one program and cannot obtain a shell, a port, an agent or a pty.

The rest — origin computed from the harness transcript rather than supplied by
the caller, a hop limit so an agent-origin message cannot delegate onward, a
rate window, and a hash-chained log that breaks visibly if edited — is in
[docs/ponte-ssh.md](docs/ponte-ssh.md), along with the part it cannot do.

## Where a boundary is worth nothing

```bash
paratia esposizione
```

Reports what on **this** machine a second account would and would not protect.
It exists because the two ways this goes wrong are both silent: a home directory
that is group-readable is readable by every local account, since macOS puts them
all in `staff`; and a volume mounted `noowners` discards the mode bits, so uid
separation buys exactly nothing on that disk. Either one makes a second account
look installed when it is not there.

```bash
strumenti/secondo-account.sh          # prints what it would do, changes nothing
strumenti/secondo-account.sh --esegui
```

Sets up a second account for agents **without moving you into it**: you keep the
desktop app, screen access, your cloud mounts and your keys, and individual
sessions run confined when the work calls for it. The reasoning, and the two
cases where it buys nothing, are in [docs/confini.md](docs/confini.md).

## Read this before you trust it

[docs/architettura.md](docs/architettura.md) is a table of nine mechanisms and
what each one actually guarantees. Two of them are tamper-**evident**, not
tamper-proof: an agent running as you can rewrite your policy files and harness
settings, including which hook runs. Root-protected bootstrap resources resist
that UID, and open-folder exemptions require those resources. This does not
make the user-owned harness configuration immutable.

[docs/ricerca/](docs/ricerca/) is the research this came out of: what the field
already covers, what it does not, and where the unsolved half is publishable.

## Tests

```bash
python3 -m pytest -p no:cacheprovider -q
python3 tests/test_gate.py
python3 tests/test_fanale.py
python3 tests/test_specchio.py
python3 tests/test_zone.py
/Library/Developer/CommandLineTools/usr/bin/python3 -I -S -B strumenti/prova-registro-python39.py
```

Tests cover migration and recovery, worker IPC, watches, registry metadata and
installer rollback fixtures. The temporary bank runs the worker and four real
shell metadata probes with simulated registry health; it asserts that keys do
not enter JSON, logs, process arguments or environment. The Python 3.9 smoke
uses actual worker queries and CSV exports in a temporary home, with simulated
kernel health and disk images. A separate native macOS script uses hdiutil with
temporary fixtures. Both scripts respect `TMPDIR` and keep their synthetic
Desktop inside a temporary home. These tests do not certify live
TCC permissions or kernel coverage. Counts and commands are recorded in the
[verification report](docs/stato-2026-10.md).

## Name

A *paratia stagna* is a watertight bulkhead. It is not a lock and it does not
inspect anything. It is a wall in a place chosen so that what gets through it
cannot reach what matters.
