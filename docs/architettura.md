# What each layer actually guarantees

Six mechanisms sit between an agent and a secret on this machine. They are not
equally strong, and a document that presents them as one wall is lying by
omission. Read the last column first: it is the one that decides whether you
should rely on the row.

| # | Mechanism | Holds against | Enforced by | Honest limit |
|---|---|---|---|---|
| 1 | AES-256 sparsebundle, locked | every process at every privilege level, including root and including `paratia` itself | the kernel and the cipher | only while locked. Open, it is an ordinary volume |
| 2 | Passphrase exists only in your head | any agent, unconditionally | nothing — there is simply no copy to find | you type it by hand, every time, in a terminal no agent owns |
| 3 | Mount-state invariant: no agent tool call runs while the volume is mounted | path obfuscation, base64, `sh -c`, quoting, symlinks | the Claude Code harness, which runs the hook before the model sees a result | only sessions that installed the hook. Same-UID tampering is detectable, not preventable |
| 4 | Broker verbs | an agent choosing the command | the verb list living inside the compartment | only covers operations you declared in advance |
| 5 | Delegation intersection | one agent asking a second agent for what it may not do itself | the same harness hook, reading the harness-written transcript | one-sided until the other harness runs its half |
| 6 | Seal and attest | nothing. It reports | you, running `paratia attest` | detection after the fact, never prevention |
| 7 | Zone (encrypted workspace) | another local account, a stolen disk, the cloud provider's copy | the cipher | **not** the session working inside it, by construction |
| 8 | Second account | the agent reaching what you never handed it | the kernel, via uid | void on `noowners` volumes and on anything cloud-synced |
| 9 | Label | nothing. It records a decision about a path | you, reading `paratia etichetta piano` | a JSON file in `~`, owned by the uid the agent runs as. It is the input to row 1 or row 7, never a substitute for either |

Row 9 is the one most likely to be misread, so it is worth saying plainly: a
label is not a deny list that this document forgot to argue against. It is never
consulted at tool-call time by anything. It is a note to yourself about which
paths deserve row 1 or row 7, and its only mechanical effect is that `applica`
reads it and copies. If a future change ever makes the gate consult it, that
change has to delete `test_l_archivio_e_un_file_normale_scrivibile` and
`test_etichettare_non_sposta_nulla`, which exist to make that deletion a
deliberate act rather than a drift.

Rows 7 and 8 answer a different question from rows 1–6, and the difference is
the one people get wrong. Rows 1–6 keep something away from **the session**.
Rows 7 and 8 keep it away from **everyone who is not the session**. A zone
cannot do what a compartment does, and asking it to produces a workspace nobody
can work in — an agent that cannot read the repository cannot work on the
repository. See [confini.md](confini.md).

Row 8 has a precondition that voids it silently: macOS home directories are
group `staff`, every local account is in `staff`, so a second account without
`chmod 700 ~` reads the whole home on first login. `paratia esposizione` checks
for this and for `noowners` volumes, which are the other silent void.

## Why row 3 is the interesting one

The natural design is a deny list of paths under the mountpoint. It is also
worthless, and the reason is worth being precise about: a deny list is a list of
the spellings somebody thought of. `/Volumes/paratia/token` is on it.
`cat "$(printf '/Volumes/pa''ratia/token')"` is not. Neither is the same path
reached through a symlink, a relative path from a `cd`, a `find -exec`, or a
Python one-liner that opens a file descriptor by number. Every one of those is a
spelling, and spellings are infinite.

So row 3 does not read the command. It asks `is_mount()`. There is exactly one
bit, the kernel owns it, and the answer does not depend on how anything was
written down. The cost is that it is coarse — while the compartment is open,
*nothing* runs, not just the reads you were worried about — and that coarseness
is the reason it holds. A precise rule about paths would have to understand
shell semantics. This one does not have to understand anything.

The same inversion is why row 5 reads the transcript rather than a marker file.
A marker file saying "this turn came from Codex" is written by something, and on
a one-account machine that something can be overwritten. The transcript is
written by the harness as a byproduct of running the session, the model never
emits it, and it records who spoke in a slot the model does not control. It is
not tamper-proof either — same UID, same story — but forging it means editing
history the harness is concurrently appending to, which is a different and much
louder kind of attack than deleting a marker.

## Why row 6 is honest about doing nothing

On a Mac with one user account there is no file an agent running as you cannot
rewrite. That includes `paratia-gate.py`. Any claim that the gate cannot be
disabled by the thing it gates is false, and stating it plainly is better than
burying it.

What there is, is a place the agent can neither read nor write: inside the
locked compartment. So the hashes go there. `paratia seal` records what the
policy files look like at a moment you chose, with the compartment open and no
agent running. `paratia attest` compares. If the gate was edited, you find out —
the next time you look. That is the whole guarantee. It is worth having and it
is not a wall.

The upgrade that turns row 6 into prevention is a second macOS account owning
the policy files, so the agent's UID has no write bit on them. That is the only
real POSIX boundary available without writing an Endpoint Security client, and
it costs an admin password and a more annoying setup. It is a deliberate open
choice, not an oversight.

## The composition rule, stated once

Rows 1–4 are about one agent and a secret. Row 5 is about two agents and a
capability, and it is a different shape of problem.

Every vendor enforces its policy over its own agent. Nobody enforces anything
over the pair. A restriction that holds for agent A alone does not hold for A
with a channel to B, because A does not have to break its rule — it asks B, and
B was never under that rule. No policy was violated and the composite system did
the thing.

The rule that fixes it:

> Under delegation, capability **intersects**. An action inherits the narrowest
> set among every principal in the chain that asked for it. A chain whose most
> recent human principal is not the immediate requester loses the human-only set
> entirely.

Row 5 implements the second sentence for the Claude side of AgentBridge. The
first sentence needs both sides. Until Codex's harness runs its half, an agent
that starts the conversation from the Codex end is unrestricted, and this repo
does not pretend otherwise.

## What is not covered at all

- **A second machine.** Everything here is local. An agent with network access
  and an API key reaches a model that has none of these hooks.
- **The model's own memory.** A secret read while the compartment was open is in
  the context window, and closing the volume does not take it back. Rotate
  anything an agent has seen.
- **Other harnesses.** Cursor, Aider, a bare SDK script: each enforces its own
  hooks or none. Row 3 covers the sessions that installed it and no others.
