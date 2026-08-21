# STARCOM unified composition root and cross-block verifier — design

## Intent

Add an explicit `StarcomProgram` composition root for the complete current
STARCOM authority graph. The root opens one SQLite database, creates the
shared infrastructure once, instantiates every canonical C1 through Block 19
authority in deterministic dependency order, exposes a stable catalog, and
provides a read-only cross-block verifier.

The composition root proves internal composability only. It does not contact a
network, spawn a subprocess, execute a worker, adopt a component, deploy a
node, publish an artifact, promote a release, or alter the canonical external
truth boundary.

## Scope and compatibility

The existing `Runtime.open` implementation in `src/starcom/cli.py` already
contains the intended constructor sequence. `StarcomProgram` becomes the
single owner of that sequence in `src/starcom/program.py`. The CLI keeps its
current public behavior through a compatibility alias or façade named
`Runtime`; CLI handlers continue to receive the same authority attributes and
the same `close()` lifecycle method.

The root includes these shared primitives:

```text
database      Database
ledger        EventLedger
trust         TrustPlane
continuity   ContinuityService
outbox        DurableOutbox
```

It also includes the current authority services already composed by the CLI:

```text
proof, missions, research,
recollection, census, certification,
qualification, c3, c3_decision, adoption, adoption_execution,
executor_registry,
architecture_input, architecture_candidate, architecture_review,
architecture_publication, architecture,
execution_plan, red_team, final_pack,
research_marathon, creative_jobs, cockpit, deployment,
release_candidate
```

No second database, ledger, trust plane, continuity service, or outbox is
allowed in this graph.

## Deterministic dependency catalog

`program.py` defines an immutable descriptor for each authority. A descriptor
contains a stable authority name, import module, class name, and an ordered
tuple of required dependency names. The published catalog is a tuple sorted by
authority name, with no duplicate names and no unknown dependency names.

The construction registry is explicit rather than reflective. Each factory
declares the exact dependency names it consumes and receives only resolved
objects from the root. A missing mandatory name raises `ValidationError` with
the authority name and missing dependency in its structured details before
the authority can be constructed. The root does not discover plugins or
silently substitute an object based on duck typing.

The catalog is read-only to callers. Its entries identify the concrete module
and class, and its dependency names are the names used by the root. Reopening
the same database path reconstructs the same catalog and the same schema
without appending ledger events or changing persisted authority state.

## Program API

The public root has the following behavior:

```python
program = StarcomProgram.open(path)
try:
    program.catalog             # tuple[AuthorityDescriptor, ...]
    program.authority("c7.final_pack")
    verification = program.verify()
finally:
    program.close()
```

`StarcomProgram.open` accepts the database path and an optional signature
verifier injection used by deterministic tests. It initializes the database
and all authority schemas in dependency order. It has no global operation
named `run`, `execute`, `deploy`, `release`, `publish`, or `promote`.

`authority(name)` returns the cataloged instance or fails closed with a
structured not-found error. The returned mapping of authority names is not
mutable through the public API. Existing convenience attributes and CLI
aliases remain available on the compatibility `Runtime` surface.

## Cross-block verification

`StarcomProgram.verify()` is read-only and returns a structured
`ProgramVerification` containing stable defect codes and the following
checks:

1. SQLite foreign-key enforcement is enabled and `PRAGMA foreign_key_check`
   returns no rows.
2. The fixed schema inventory for the composed graph is present exactly,
   including the shared `schema_meta`, ledger, core, C1–C7, 12A, creative,
   cockpit, deployment, and Block 19 tables. Unexpected user tables are
   reported as defects rather than silently accepted.
3. The catalog is sorted, unique, complete, and internally resolvable.
4. Every authority's declared `database`, `ledger`, `trust`, `continuity`, and
   `outbox` attributes point to the shared instances required by its
   descriptor. Missing or substituted infrastructure is a defect.
5. The append-only ledger verifies globally and each persisted ledger stream
   has contiguous sequence/hash provenance. An empty fresh program is valid;
   once events exist, every stream is independently checked.
6. The root's public surface contains none of the forbidden global operation
   names.
7. The program truth snapshot remains exactly:

   ```text
   project_state = RC_BLOCKED_EXTERNAL_EVIDENCE
   release_status = NOT_RELEASED
   live_census_certification_status = NOT_PROVEN
   external_runtime_integration_status = NOT_PROVEN
   component_adoption_status = NOT_PROVEN
   real_deployment_status = NOT_PROVEN
   ```

Verification never calls an authority operation that could create a record or
perform an external action. It only reads schemas, object identity, catalog
metadata, ledger data, and fixed canonical truth constants.

## Error and lifecycle rules

Construction is fail-closed. If any authority constructor or dependency
resolution fails, the database connection is closed and the original
`StarcomError` (or a structured wrapper) is re-raised. `close()` is
idempotent at the program boundary and does not delete or rewrite the
database. Reopening a previously initialized path is also idempotent and must
not create duplicate schema rows or ledger events.

The verifier reports defects instead of promoting a blocked program. It never
returns a release approval and never changes any canonical status.

## Tests and evidence

TDD tests will cover:

- complete construction of the graph in one database;
- one-object identity for all shared primitives;
- deterministic sorted catalog and resolved module/class/dependency metadata;
- fail-closed unknown mandatory dependency diagnostics;
- close/reopen idempotence with unchanged catalog, schemas, and ledger count;
- no network, subprocess, or external effect during composition;
- foreign-key, schema, catalog, dependency, ledger, forbidden-surface, and
  canonical-truth verification defects;
- compatibility of the existing CLI `Runtime` API.

The implementation is complete only after focused tests, the full unittest
suite, deterministic manifest verification, compilation, secret/style scans,
hash-seed variation, and warnings-as-errors checks pass. The issue changes no
external evidence status and does not make STARCOM a released product.
