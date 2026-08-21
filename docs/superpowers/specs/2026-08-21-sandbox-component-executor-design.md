# STARCOM local sandbox component executor — design

## Boundary

`SandboxComponentExecutor` is the first concrete C3 executor, but it is only a
local file-system proof. It accepts a single explicit `file://` source root and
writes only below one explicit sandbox root. It never uses network, subprocess,
shell, package manager, hooks, symlinks, path traversal, or external runtime.
This local proof does not change the four canonical external evidence statuses.

## Closed manifest and validation

The source root must contain `component_manifest.json` with exactly `component`,
`version`, and a sorted unique `files` list. Each file entry contains exactly
`path`, `digest`, and `size`. Every listed file is a regular file below the
source root, every source file except the manifest is listed, digests and sizes
match, and the source tree digest is the SHA-256 of the canonical manifest
material. Symlinks, absolute paths, `..`, backslashes, missing files, extra
files, and mismatched digests are rejected.

The C3 plan must use profile `starcom-local-component-v1`, a `sandbox:<id>`
target with a safe identifier, the exact source digest, and
`requires_network=false` with an empty allowlist.

## Atomic effect and rollback

Execution stages files under `releases/.staging-*`, atomically renames the
content-addressed release to `releases/<tree_digest>`, and atomically replaces
`current.json`. The pointer records component, version, release digest, and
file material. A journal keyed by the C3 idempotency key stores the prior
pointer and result. Exact replay returns the same result without copying or
reactivating files.

Rollback atomically restores the prior pointer or its absence and records a
rollback journal entry. Content-addressed releases remain intact. Rollback is
also idempotent and returns a canonical restored-state digest.
