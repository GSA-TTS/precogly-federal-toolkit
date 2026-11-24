# Package migration

The toolkit is becoming an authoritative producer rather than a projection.
The first installed-wheel slice exposes `precogly_toolkit.flow_refs` and an
offline `precogly-toolkit flow-bindings` CLI. The wheel includes the existing
path-independent helper directly, so there is one implementation, not a copy.

Only this API is installed in this slice. Legacy repository scripts, packs,
schemas and templates retain their existing layout and cold-start contracts.
Do not assume those commands are portable installed entrypoints yet. Migrate
them with explicit consumer-root/resource parameters and parity tests before
retiring projection tooling. An editable install is not evidence of wheel
portability: CI builds a wheel and tests it from outside the checkout.

Downstream consumption must wait for this producer PR to merge; do not advance
a parent submodule pointer to an unmerged feature branch. Any old projection
job must also stop overwriting producer-owned packaging files before the next
projection is committed. This change does not authorize a public release.
