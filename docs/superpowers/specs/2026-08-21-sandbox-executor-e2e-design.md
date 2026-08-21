# STARCOM registered sandbox executor — end-to-end proof

## Boundary

This proof exercises the real `SandboxComponentExecutor` through the existing
durable C3 worker. It uses only temporary local files, an explicit `file://`
source root, and a temporary SQLite database. It does not admit external
evidence and does not change any canonical external truth status.

## Authority sequence

The test performs the registry transitions independently and in order:

1. register the executor descriptor in `REGISTERED_DISABLED`;
2. accept an Ed25519 qualifier root;
3. admit an exact signed qualification as `QUALIFIED_DISABLED`;
4. enable the executor with a separate TrustPlane decision.

The worker must attest the enabled state, exact implementation identity,
qualified local profile, and network denial immediately before the effect.

## Durable effect

The execution plan binds the exact source URI, manifest digest, target,
`starcom-local-component-v1`, and `requires_network=false`. Admission creates
one durable outbox effect. The worker claims it, runs the real executor, and
leaves a content-addressed release plus an atomic current pointer. The
execution and registry verifiers must both remain clean.

## Negative boundaries

Registered-only, revoked, wrong source digest, and wrong implementation
version paths must terminate as `FAILED_NO_EFFECT`; no active pointer or
release is allowed. A successful local sandbox effect must leave all four
`ExternalEvidenceService.snapshot()` categories as `NOT_PROVEN`.
