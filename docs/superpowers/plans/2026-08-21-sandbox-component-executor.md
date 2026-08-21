# STARCOM sandbox component executor — implementation plan

1. Add RED tests for the closed manifest, exact plan validation, real local
   install, content-addressed release, replay, two-version rollback, and
   rejection of symlink/traversal/digest/network/subprocess paths.
2. Implement `SandboxComponentExecutor` as a `C3AdoptionExecutor` with
   deterministic descriptor identity, validation, atomic staging/pointer
   replacement, journaled idempotence, and pointer-only rollback.
3. Run focused/full verification, update the manifest, publish PR #73, and
   merge only after CI/Sonar and post-merge verification are green.
