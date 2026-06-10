# AXR Transparency Log — ECO Clean HU booking agent

This repository is the **public transparency stream** for one production AI-agent
deployment of [AXR](https://github.com/chrisconen/AXR) (Agent Execution Receipt):
the geo-cluster booking workflow of ECO Clean HU.

It is the moral equivalent of a Certificate Transparency log's public face,
scaled to a one-person operation — honestly labeled as such.

## What is published here

| File | What it is |
|------|------------|
| `sth-hu.jsonl` | The append-only stream of **Signed Tree Heads**: at each anchoring interval, the Merkle root over all production receipts, signed with a dedicated STH key |
| `anchors-hu.jsonl` | Anchor records binding each tree head to an external backend |
| `keys/sth-public.pem` | The STH-signing **public** key (separate from the receipt-signing key — key-role separation) |
| `monitor/` | The journal of the GitHub-hosted monitor (written by the scheduled Action, committed publicly) |

**What is *not* published:** the receipts themselves. `receipts-hu.jsonl` contains
customer-adjacent data and stays private. The tree heads commit to it
cryptographically; an auditor with authorized access to the private log can verify
every receipt against this public stream.

## What this gives you (and what it doesn't)

Every push of `sth-hu.jsonl` is checked by a scheduled GitHub Action running the
independent monitor (`axr-monitor.js`) **on GitHub's infrastructure, not the
operator's**. The monitor keeps its own journal in `monitor/` and will fail the
build and open an issue on:

- **EQUIVOCATION** — a different root at an already-witnessed tree size (split view)
- **TRUNCATION** — the published log shrank
- **NON_APPEND_ONLY** — a consistency proof fails: history was rewritten
- **ROOT_MISMATCH / BAD_SIGNATURE**

Honest caveats: the operator controls this repository and the Action definition,
so this is *not* adversarially independent third-party monitoring — it is
infrastructure-separated monitoring with a public, timestamped journal. The git
history itself acts as an additional weak witness: silently rewriting the
published stream would require rewriting public history. True third-party
monitoring means **you** running the monitor — see below.

## Run your own monitor (please do)

Anyone can witness this log independently. Zero dependencies beyond Node:

```bash
git clone https://github.com/chrisconen/AXR axr-tools
# daily, from any machine in the world:
node axr-tools/axr-monitor.js poll \
  https-or-local-copy-of/sth-hu.jsonl keys/sth-public.pem \
  --state my-own-journal.json --anchors anchors-hu.jsonl
# compare your view with the public one (split-view proof):
node axr-tools/axr-monitor.js compare my-own-journal.json monitor/monitor-state.json
```

If your journal ever disagrees with this repository's, you hold cryptographic
evidence of equivocation. Open an issue with both journals — that is the system
working as designed.

## Provenance

Protocol and tooling: [AXR](https://github.com/chrisconen/AXR) — built by
Conen Digital as a human + AI collaboration (Claude, Gemini). MIT licensed.
