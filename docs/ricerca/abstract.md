# Draft — for SaTML 2027 (position paper track)

Working title, abstract and skeleton. Written in English because that is where
it goes. Everything here is a first pass meant to be argued with, not a final
text; the numbers in brackets do not exist yet and come from E1–E3 in
`campo.md`.

---

> **RISCRITTO l'11 agosto 2026 dopo il secondo giro di prior art.** La versione
> precedente rivendicava l'intersezione sotto delega come contributo. È SPKI
> RFC 2693 §6.3.1, 1999, e SentinelAgent arXiv 2604.02767, aprile 2026. Così
> com'era, desk reject. Il perché e il riposizionamento stanno in
> [prior-art.md](prior-art.md); qui c'è già la versione corretta.

## Title

**Delegation Without a Credential: Why Authorization Systems Cannot See
Agent-to-Agent Requests**

Alternatives:

- *Tokenless Delegation in Multi-Vendor Agent Systems*
- *The Union of Two Restricted Agents Is Not Restricted*

---

## Abstract (draft)

Every major agent harness enforces a capability policy over its own agent, and
each does so correctly. Claude Code declines to drive the desktop; other
harnesses permit it. These policies are written, evaluated and audited one agent
at a time. Meanwhile the agents are increasingly wired to each other — over
local bridges, shared MCP servers and agent-to-agent protocols — and no
component enforces anything over the resulting pair.

We call the consequence **capability laundering**: a principal under a
restriction obtains the effect of a forbidden action by asking a second
principal that is not under that restriction. No policy is violated, no sandbox
is broken, and no model is jailbroken. The composite system simply holds the
union of two restricted capability sets, and a union of restricted sets is not
restricted.

This is distinct from the confused deputy problem, where the deputy is deceived
about the authority under which it acts. Here the second agent is deceived about
nothing: it is asked to do something it is genuinely permitted to do. The defect
is in composition, not in either component.

The reason no authorization system catches this is sharper than the framing
above, and it is our central claim. Every mechanism built to constrain
delegation — SPKI's 5-tuple reduction (RFC 2693, 1999), macaroon attenuation,
Biscuit, and recent agentic work such as SentinelAgent (2026) — presupposes that
*something crosses the delegation boundary*: a token, a credential, a capability
handle that can be narrowed in transit. The rule these systems enforce, that
authority intersects rather than unions under delegation, has been settled for
over two decades and we do not claim it.

Between two agents on one laptop, nothing crosses. A sentence does. There is no
token to attenuate, no credential to inspect, and therefore no delegation edge
for any authorization system to see. **A natural-language peer request is a
delegation edge that carries no credential, and that is why it is unguarded.**

We make three contributions. First, a **capability differential** across [N]
production agent harnesses on a single machine, showing that the union of their
permitted sets is strictly larger than any individual set and contains
capabilities that every vendor documents as restricted [table]. Second, a
measurement of the **laundering rate** on a live cross-vendor bridge: given
tasks requiring a capability denied to one agent and granted to another, and
without any instruction to delegate, the restricted agent routes the request to
its peer in [X]% of trials, rising to [Y]% under mild task pressure. Third, an
enforcement rule and a working implementation: **under delegation, capability
intersects rather than unions**. An action inherits the narrowest set among all
principals in its chain, and a chain whose most recent human principal is not
the immediate requester loses the human-only set entirely. We implement this as
a harness-level hook that derives the delegation context from the
harness-written transcript rather than from any state the model can author, and
report its utility cost: [Z]% of legitimate tasks are affected.

We argue that per-agent evaluation is now measuring the wrong object, and that
the property worth certifying is a property of the deployed system.

---

## Skeleton

**1. Introduction.** The one-line thesis. The Claude/Codex example, concrete and
running on one laptop. Why this is not a jailbreak and not a sandbox escape.

**2. Threat model.** Two or more agents, distinct vendors, distinct policies, a
communication channel neither vendor's threat model includes. Honest scope: we
assume no vendor is malicious and no model is adversarially fine-tuned. The
point is that laundering needs neither.

**3. Capability laundering, defined.** Formal statement. Relationship to the
confused deputy (Hardy 1988) — and why it is not one. Relationship to IFC: APPA
[2607.24625] confines *data*; we confine *action*. Same machinery, different
invariant.

**4. E1 — the capability differential.** Table across harnesses. The union
column is the paper's first figure.

**5. E2 — measuring the laundering rate.** Protocol, tasks, the bridge.
Comparison with [2607.07097], whose planner–executor pipelines are synthetic and
same-designer; ours is peer-to-peer, cross-vendor, and deployed. Their finding
that a Claude planner amplifies Gemini compliance 8.9%→38.9% is the strongest
prior evidence that this generalises.

**6. Capability intersection.** The rule. Why the delegation context must come
from harness-written state. Implementation (`paratia`, open source). Why the
compartment guard inverts the usual design: a state invariant, not a path deny
list, because a deny list enumerates spellings and spellings are unbounded.

**7. E3 — what it costs.** Utility loss. The tasks it breaks.

**8. Limitations, stated not discovered.** One-sided enforcement is bypassable
from the other end [E4]. Same-UID tamper-evidence is not tamper-proofness.
Nothing here covers a second machine or a raw API call. Context already read is
already leaked.

**9. What this implies for policy.** Every current AI regulation and every
vendor safety card constrains *a model*. None constrains *a system of models*.
If capabilities compose and restrictions do not, per-model certification is
measuring something that does not survive deployment. (This is the section that
becomes the CACM Viewpoint.)

---

## What to be careful about

**Do not oversell the implementation.** It is one hook on one harness on one
laptop. The contribution is the rule and the measurement; the code is evidence
that the rule is implementable, not that the problem is solved. Reviewers
forgive a small artifact and punish a large claim.

**Do not compete with APPA on formalism.** They have the monoids and the proofs.
State the rule precisely and cite them for the algebraic treatment of labels.
If a reviewer wants a theorem, the honest answer is that intersection under
delegation is a lattice meet and the proof is not the hard part — the hard part
is that nobody is computing it.

**E2 is the paper.** E1 is cheap and makes the argument concrete; E3 is what
reviewers demand; but E2 is the number nobody else can produce right now,
because it needs a real cross-vendor bridge on a real machine. That is the
sentence to lead the rebuttal with.

**Get the framing right in the first paragraph.** The reviewer who reads this as
"prompt injection, again" rejects it. The distinction — no deception, no
violated policy, only composition — must be in the abstract and in the first
paragraph, not deferred to section 3.
