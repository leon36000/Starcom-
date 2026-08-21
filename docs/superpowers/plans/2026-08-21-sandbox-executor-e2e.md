# STARCOM sandbox executor E2E — implementation plan

1. Add a temporary-file E2E fixture that registers, qualifies, enables, and
   attests the real sandbox executor through the durable C3 worker.
2. Prove real installation, terminal success, clean registry/execution
   verifiers, and an unchanged `NOT_PROVEN` external-evidence snapshot.
3. Prove registered-only, revoked, source-digest, and implementation-version
   failures terminate before any active sandbox effect.
4. Run focused and full repository gates, refresh the manifest, publish and
   merge only after CI and SonarCloud are green.
