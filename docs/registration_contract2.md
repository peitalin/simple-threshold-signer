# Registration Contract v2 (Future)

Today, the relay server provisions user accounts by signing `create_account` transactions directly as the relayer and persisting WebAuthn + threshold signer state off-chain (relay storage).

Future direction: deploy a dedicated “registration contract” that can atomically:

- Create the user account (subaccount under the contract).
- Create and initialize a per-user smart account used for email recovery.

This would move account provisioning back on-chain (contract-mediated) while keeping relay funding + UX, and would allow the relay account to remain distinct from the contract account.

