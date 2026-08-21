# Block 16 creative and multimodal job authority design

## Boundary

`CreativeJobService` is a durable authority for requesting content-addressed creative jobs. It validates and stores a closed request, consumes one exact TrustPlane decision, records the initial state, and enqueues one durable outbox effect. It never loads an input file, contacts a model, opens a socket, invokes a process, uses a microphone/camera/GPU, or performs generation.

The only state produced by this block is:

`CREATIVE_JOB_REQUESTED_NOT_EXECUTED`

There is intentionally no worker, completion, result, generation, rendering, synthesis, transcription, processing, execution, or run surface in this block.

## Closed plan

`prepare()` is deterministic and has no database, ledger, TrustPlane, outbox, filesystem, or network side effect. Its inputs are:

- `job_id`, `job_type`, and logical `owner`;
- non-empty exact UTF-8 prompt bytes and their SHA-256 digest;
- requested `model_id`, `executor_id`, and executor descriptor SHA-256 digest;
- zero or more input artifact references with exactly `artifact_id`, `digest`, and `media_type`;
- output media type compatible with the closed job type;
- safety profile with exactly `profile_id`, `mode`, `allow_sensitive`, and `max_output_bytes`;
- safety policy SHA-256 digest;
- seed configuration with exactly `seed` and `options`;
- network requirements with exactly `mode` and `egress_allowed`;
- caller-provided idempotency key and deterministic effect ID `creative:job:<job_id>`.

Job types are exactly `IMAGE`, `TEXT_TO_SPEECH`, `SPEECH_TO_TEXT`, `AUDIO`, and `VIDEO`. Input references are sorted by artifact ID, unique, and digest-validated. Prompt bytes are retained without normalization; UTF-8 validation never replaces or reserializes them.

## Trust binding

The request uses:

- action `creative.job.request`;
- resource `creative:job:<job_id>`;
- mission `creative-job:<job_id>`;
- exact context containing the complete plan material, prompt digest and byte length, input memberships, policy/model/executor digests, idempotency key, effect ID, and request digest.

The operator must provide an already-created allowed `AuthorizationDecision`. The service never creates a rule or decision. The decision subject must equal the request actor, the action/resource/mission/context must match byte-for-byte at the structured canonical level, and one decision ID can authorize at most one creative job.

## Atomic admission

Inside one SQLite transaction, `request()` revalidates the preparation and decision, rejects default deny or dirty decisions, checks job/idempotency/effect/decision conflicts, then appends the creative admission ledger event, inserts the immutable job row and sorted input memberships, inserts the initial append-only transition, and calls `DurableOutbox.enqueue_in_transaction()` for exactly one `creative.job.request` effect. Any failure rolls back every row and ledger event.

Exact replay of the same job, plan, decision, and actor returns the original record without another event or effect. Any changed material is a conflict. The outbox payload carries content addresses and closed configuration, never raw prompt bytes or an executable instruction.

## Persistence and verification

The authority owns `creative_jobs`, `creative_job_inputs`, and `creative_job_transitions`. Job and membership rows are immutable; transitions are append-only. The verifier independently reconstructs:

- prompt UTF-8 validity, exact bytes, digest, and all closed fields;
- sorted input memberships and every digest/reference;
- exact TrustPlane decision and decision ledger chain;
- the creative admission event and transition;
- the unique outbox effect, payload, request digest, pending state, and outbox ledger chain.

Missing rows, malformed canonical JSON, changed prompt bytes, digest mismatch, decision reuse, altered event payload, changed effect payload, effect disappearance, or any non-pending effect produce stable defect codes and a non-clean verification result.

## Runtime and tests

The shared `Runtime` constructs one `CreativeJobService` over the existing database, ledger, TrustPlane, and DurableOutbox. Tests cover all five types, deterministic side-effect-free preparation, default deny, exact context, prompt and digest failures, closed schemas, exact replay, single-use decisions, transactional rollback, tampering, runtime wiring, and forbidden execution/network surface.

## Truth boundary

Fixtures prove only durable request authority. They do not prove generated media, model availability, external runtime integration, a real file/object store, microphone/camera access, GPU execution, or any external deployment.
