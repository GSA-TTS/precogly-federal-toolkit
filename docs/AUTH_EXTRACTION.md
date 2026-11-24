# Generic local-auth extraction

The first Phase 2 slice extracts the local credential payload helper to
`precogly_toolkit.auth`. It uses explicit caller mappings or the existing
environment variable contract, has no network calls, no built-in credentials,
no system defaults, and no repository paths. Missing credentials fail closed;
password whitespace is preserved. Synthetic unit tests cover the contract.

The consumer adapter should re-export the same exception and function only
after the producer merges. Do not remove a parent implementation while its
pinned toolkit lacks this module. Full API/sync, hosting analysis, CRM intake
and diagram extraction remain separate, dependency-reviewed slices. This
helper does not grant permission to import into a deployed service.
