# paratia

[Site](https://nerln.github.io/paratia/) · [agent manual](https://nerln.github.io/paratia/llms.txt) · [SSH bridge](docs/ponte-ssh.md)

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

`pip install` gives you the command and nothing more. The hooks are not a Python
package and pip does not place them; they are wired into `~/.claude` by hand, in
the step further down. Skip that step and you have the compartment without the
gate, which is the half that does not need an agent to cooperate.

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

## Use

```bash
paratia unlock            # your terminal, asks for the passphrase, auto-locks in 15 min
paratia put OPENAI_KEY    # value typed, not echoed, never on a command line
paratia ls
paratia lock
```

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

[docs/architettura.md](docs/architettura.md) is a table of six mechanisms and
what each one actually guarantees. Two of them are tamper-**evident**, not
tamper-proof, because on a Mac with one account there is no file an agent
running as you cannot rewrite — including the hook that stops it. The document
says so in those words rather than leaving it to be discovered.

[docs/ricerca/](docs/ricerca/) is the research this came out of: what the field
already covers, what it does not, and where the unsolved half is publishable.

## Tests

```bash
python3 tests/test_gate.py
```

Sixteen cases against a fake mountpoint and a synthetic transcript, including
the base64'd path, the compound command hiding behind an allowed one, and the
tool result that must not be mistaken for a human taking the turn back.

## Name

A *paratia stagna* is a watertight bulkhead. It is not a lock and it does not
inspect anything. It is a wall in a place chosen so that what gets through it
cannot reach what matters.
