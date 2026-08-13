# Adapter policy

External infrastructure such as Temporal, Neon Postgres, model gateways, static-analysis services and execution agents must remain replaceable adapters.

An adapter is eligible only when it has:

1. a STARCOM-owned typed interface;
2. explicit capability and trust boundaries;
3. deterministic contract tests;
4. timeout, retry, cancellation and reconciliation behavior;
5. secret-handling and egress policy;
6. observability without hidden external telemetry;
7. a fallback or documented fail-closed mode;
8. supply-chain provenance, exact versions and license review.

Using a product does not make it a canonical authority. The Mission Kernel, Trust Plane and Proof Engine retain ownership of their decisions.
