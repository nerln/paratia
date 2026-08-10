# Boundaries, and what each one is worth

Three different things get called "keeping the agent out", and they defend
against three different people. Picking the wrong one is not a small mistake:
two of them are silently worthless in situations where the third still holds.

## The three

**A compartment** holds secrets the agent must never read. The rule is that it
is closed while an agent runs, and the gate enforces exactly that by refusing
every tool call while the volume is mounted. Cost: you cannot use what is inside
it during a session, only what `paratia broker` will do on your behalf.

**A zone** holds work — a repository, a dataset, a client's files. The agent has
to read it to be useful, so there is no arrangement where it is hidden from a
session that is working on it. A zone is encrypted at rest, which defends
against a second account, a stolen disk and a cloud provider's copy. It does not
defend against the session you started.

**A second account** puts the agent's processes under a different uid, so the
kernel refuses its reads of your files. It defends against the agent reaching
things you never handed it. It is also the one with the most conditions
attached, and they are covered below.

The distinction that matters: **a compartment hides a thing from the session; a
zone hides it from everyone who is not the session.** Asking for both at once,
on the same directory, is asking for a workspace nobody can work in.

## Why a deny list is not on this list

Because it does not work, and the reason generalises. A deny list enumerates the
spellings of a path somebody thought of. `/Volumes/paratia/token` is on it;
`cat "$(printf '/Volumes/pa''ratia/token')"` is not; neither is the same file
reached through a symlink, a relative path after a `cd`, a `find -exec`, or an
open by file descriptor number. Spellings are unbounded, so the list is always
incomplete, and its incompleteness is invisible until it matters.

Everything in this repo is built to avoid needing one. The gate checks mount
state, which is one bit the kernel owns. A zone checks nothing at all, because
ciphertext does not need a policy.

## The second account, honestly

The advice "run the agent as another user" usually assumes you will move into
that account. Most people should not, and the reason is not laziness: from a
second account you lose the desktop app, screen access, the browser pane, your
cloud mounts, your SSH keys and your `gh` auth. That is a large, permanent cost
paid on every session, in exchange for a boundary that only some sessions need.

The arrangement that survives contact with actual work is **tiered**, and the
tier is a property of the session rather than of you:

| | runs as | can reach | use it for |
|---|---|---|---|
| normal session | you | everything | interactive work, while you are watching |
| confined session | the agent account | the shared yard only | autonomous runs, scheduled tasks, anything on the far end of an agent-to-agent bridge |

The second row is where the risk actually is. A session you are sitting in front
of is one you can interrupt. A scheduled task at 3am, or a turn opened by
another agent over a bridge, is not — and those are the ones worth confining.

`strumenti/secondo-account.sh` sets this up. Run it with no arguments first; it
prints what it would do and changes nothing.

### The step people skip, and it voids the rest

macOS home directories are `drwxr-x---`, group `staff`, and **every local
account is in staff by default**. So creating a second account without also
doing `chmod 700 ~` gives that account read access to your entire home on its
first login: SSH keys, tokens, browser profiles, everything. The boundary reads
as installed and is not there.

`paratia esposizione` checks this, among the rest.

## Where a second account buys nothing

Two cases, and both are common enough that assuming otherwise is the default
mistake.

**A volume mounted `noowners`.** macOS mounts most external disks with ownership
ignored, which discards the mode bits for that filesystem entirely. Every
account has full access to everything on it regardless of who owns what. If your
work lives on an external SSD, uid separation is doing nothing for it. Check
with `mount | grep noowners`, or `paratia esposizione`, which names the volumes.

You can turn enforcement on with `diskutil enableOwnership`, but understand the
cost first: files that arrived from another Mac or a restore carry a uid that
was being ignored and will stop being ignored, so some of them become unreadable
until you `chown` them. Do it when you have time to fix fallout, not the week
before a deadline. exFAT volumes cannot be fixed at all — the format has no
permissions to enforce.

**Anything in a cloud-synced folder.** The provider holds a copy on a server,
and no local uid reaches it. A second account does not touch this and neither
does `chmod`. The only thing that does is putting ciphertext in the folder that
syncs, which is what a zone is for — with the caveat in the next section.

## Zones in synced folders: read this before you do it

`paratia zona nuova` refuses a cloud-synced destination unless you pass
`--lo-so`, and the refusal is not decoration. A sparsebundle is thousands of
band files. The provider syncs them individually and has no idea they are one
object. A band written while the image is mounted can be uploaded torn, or
arrive out of order, or lose a conflict resolution — and the result is an image
that will not attach at all, taking everything in it.

If you do it anyway, the image needs a second copy somewhere that is not synced,
and it must be unmounted before the provider is allowed to catch up.

The safer shape for synced storage is to keep the plaintext work on a local
zone, and sync only what you would be willing to hand over.

## What none of this covers

- **The context window.** A secret read while a compartment was open is in the
  transcript, and closing the volume does not take it back. Rotate it.
- **A second machine.** An agent with network access reaches a model that runs
  none of these hooks.
- **Your own session.** Everything here is about what an agent can reach without
  you. It cannot help with what you hand it deliberately.
