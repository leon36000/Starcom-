# STARCOM block 18 — deployment fabric design

## Scope

Implement a local, deterministic `DeploymentFabricService` that seals content-addressed bundle manifests, enrolls offline nodes, and authorizes compatible bundle-to-node assignments. The service records authority and proof only. It never downloads, installs, pushes, connects to, deploys, or executes anything.

## Closed contracts

`DeploymentPlatform` is one of `LINUX_SERVER`, `WINDOWS_DESKTOP`, `MACOS_DESKTOP`, `ANDROID_MOBILE`, `IOS_MOBILE`, or `EDGE_NODE`.

Bundle preparation accepts exactly these manifest fields: `bundle_id`, `version`, `platform`, `package_digest`, `sbom`, `configuration`, `provenance`, `artifacts`, `minimum_resources`, `gpu_required`, `offline_capability`, and `safety_profile`. The nested resources, GPU requirement, offline capability, and safety profile are normalized into closed objects. Artifact IDs and labels are sorted and duplicate-free. The sealed state is `DEPLOYMENT_BUNDLE_SEALED_NOT_DEPLOYED`.

Node preparation accepts a node ID, platform, Ed25519 public-key PEM, closed CPU/RAM/storage/GPU capabilities, offline mode, attestation digest, and sorted labels. The stored fingerprint is SHA-256 over the exact public-key bytes. The enrolled state is `NODE_ENROLLED_OFFLINE`.

Assignment preparation binds an assignment ID to an existing sealed bundle and enrolled node. Admission rechecks platform, CPU, memory, storage, GPU, and offline compatibility. The terminal state is `DEPLOYMENT_AUTHORIZED_NOT_EXECUTED`.

## Authority and persistence

The three actions are exact:

- `deployment.bundle.seal`, resource `deployment:bundle:<bundle_id>`;
- `deployment.node.enroll`, resource `deployment:node:<node_id>`;
- `deployment.assignment.authorize`, resource `deployment:assignment:<assignment_id>`.

Each request has a stable mission ID and context containing the relevant manifest/key/compatibility digests. Admission requires a verified, allowed TrustPlane decision and consumes it through `ContinuityService` exactly once. Every row is immutable through SQLite triggers; every record has an append-only ledger event and ledger-chain verification.

## Verification

Verification reconstructs the canonical material, checks every stored digest and closed field, validates Ed25519 key syntax and fingerprint, rechecks linked decisions and consumption, checks ledger event provenance and chain integrity, and for assignments re-runs compatibility against the linked immutable records. Exact replay returns the original record; material conflicts, decision reuse, malformed keys, incompatible targets, and tampering fail closed.

## Truth boundary

This block proves only local sealing, offline enrollment, and authorization. It does not prove a downloaded binary, a real node connection, a desktop/mobile installation, a deployment, or an executed command.
