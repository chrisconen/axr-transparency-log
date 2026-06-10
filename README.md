# AXR Transparency Log

Public Signed Tree Head (STH) stream for the [AXR](https://github.com/chrisconen/AXR) production receipt chain.

## What is this?

The AXR receipt generator on our production booking workflow (ECO Clean HU) signs every decision into a tamper-evident, append-only chain. Hourly, the chain is batched into an RFC 6962 Merkle tree and a **Signed Tree Head** is emitted.

This repository publishes those STHs so that **anyone can independently verify** that:

- the log has never been truncated (tree size only grows)
- the operator has never shown two different trees at the same size (equivocation)
- every new tree head is a consistent extension of the previous one

This is the Certificate Transparency model applied to AI agent accountability.

## How it works

1. **Operator side** (Z440, hourly cron): the anchoring sidecar (`axr-anchor.js`) runs inside the n8n Docker container, produces an STH, and a publish script pushes the updated files here.

2. **GitHub Actions** (daily, on GitHub's infrastructure): runs `axr-monitor.js poll` against the published STH stream with its own retained journal. If it detects any inconsistency, it opens an issue automatically.

3. **Anyone** can clone this repo and run the monitor themselves:
   ```bash
   git clone https://github.com/chrisconen/axr-transparency-log.git
   cd axr-transparency-log
   node axr-monitor.js poll logs/eco-clean-hu/sth.jsonl keys/sth-public.pem \
        --state my-monitor-state.json \
        --anchors logs/eco-clean-hu/anchors.jsonl \
        --log-id axr:eco-clean-hu:v1
   ```

## Structure

```
keys/
  sth-public.pem          # STH verification key (public only)
logs/
  eco-clean-hu/
    sth.jsonl             # Signed Tree Heads (append-only)
    anchors.jsonl         # Anchor records
monitor/
  journal.json            # GitHub Actions monitor's retained state
.github/
  workflows/
    monitor.yml           # Daily independent monitor Action
```

## Trust model

- The **signing key** never leaves the operator's infrastructure. Only the public key is here.
- The **monitor journal** lives in git history — rewriting it requires force-pushing, which is visible.
- The Action runs on **GitHub's infrastructure**, not the operator's.
- This is not perfect adversarial independence (the repo owner could disable the Action), but it is a meaningful trust-domain separation for a small team, and the full git history is publicly auditable.

## Related

- [AXR](https://github.com/chrisconen/AXR) — the protocol, verifier, and all tooling
- [Conen Digital](https://conendigital.hu) — the operator

## License

MIT
