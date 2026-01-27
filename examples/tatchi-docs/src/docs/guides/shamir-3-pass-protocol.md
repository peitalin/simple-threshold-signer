---
title: Shamir 3-Pass Protocol
---

# Shamir 3-Pass Protocol (Removed)

Shamir 3-pass was a legacy UX optimization for VRF-key “auto-unlock”. It has been removed as part of the lite signer refactor:

- No `/vrf/apply-server-lock` or `/vrf/remove-server-lock` endpoints.
- No server key rotation / grace lists for Shamir.
- Signing authorization uses standard WebAuthn challenge/response and (optionally) relay-minted session tokens (e.g. `POST /threshold-ed25519/session`).

For the current architecture and refactor plan, see `docs/lite-signer-refactor/plan.md`.
