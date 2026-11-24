# Cluster A: System/DFD contracts

This domain PR establishes explicit consumer-root contracts for system discovery,
path resolution, manifest validation and deterministic DFD formatting. Installed
APIs live under `precogly_toolkit.system_directory` and `precogly_toolkit.dfd_format`.
Legacy scripts bind repository paths and default system names; installed engines
have no implicit private consumer paths. Explicit schema requests fail if the
schema is missing or invalid; callers may omit schema validation deliberately.

This is the first dependency layer of Cluster A, not the whole domain. Remaining
scrub/rehydrate/source-validation modules currently import policy validators;
hosting/provider/profile modules assume repository schemas, tier data and an
example workload. Those dependencies must gain explicit contracts and regression
fixtures before extraction. Do not simply copy their implicit roots into src.

Consumer adoption waits for upstream merge and a validated pin advance. Keep
local system defaults/path bindings and test CLI compatibility. Legacy projection
audits must source implementation modules and preserve import/schema closure.
Full projection retirement and pack consumption remain separate acceptance items.
