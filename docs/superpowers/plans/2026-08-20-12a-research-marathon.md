# 12A-LIVE Research Marathon Coordinator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify a signed, durable, no-network research marathon coordinator for issue #65.

**Architecture:** Add `ResearchMarathonService` as a composition boundary over the existing C7 final-pack verifier, `ResearchCampaign`, `DurableOutbox`, `ContinuityService`, `TrustPlane`, and `EventLedger`. Store immutable plan/membership material and append-only transitions/evidence mappings; make start and outbox fan-out transactional, while keeping workers responsible for recording test evidence through the existing research ledger.

**Tech Stack:** Python 3, SQLite, existing Starcom canonical JSON/ledger/TrustPlane/Continuity/C7/research/outbox services, `unittest`, Ed25519 signature verification.

**Spec:** `docs/superpowers/specs/2026-08-20-12a-research-marathon-design.md`

## Global Constraints

* The coordinator is self-hosted and fail-closed.
* Production code performs no network access, fetch, HTTP request, or source adapter dispatch.
* Exact UTF-8 canonical JSON bytes are signed and digest-bound.
* The plan has at least 48 profiles, at least 240 partitions, and a minimum identity target of 800.
* Start is default-deny, single-use decision-bound, and atomically transitions `ACTIVE` plus exactly one durable effect per partition.
* A research attempt is persisted before a hypothetical request; completion requires receipts, a `SUCCESS`, an observation, and a cursor.
* Completion is `COMPLETE_PENDING_CERTIFICATION`; it is not live census certification.
* All persisted plan and membership material is immutable; transitions and evidence mappings are append-only.

---

### Task 1: Lock the public contract with deterministic RED tests

**Files:**
- Create: `tests/test_research_marathon.py`

**Interfaces:**
- Consumes: existing `FinalPackGraph`, `ResearchCampaign`, `DurableOutbox`, `ContinuityService`, and `TrustPlane` test fixtures.
- Produces: failing tests that define `ResearchMarathonService.prepare`, `admit_plan`, `start`, `claim`, `begin_partition_attempt`, `complete_partition`, `progress`, `close_pending_certification`, and `verify`.

- [x] **Step 1: Write tests for closed plan shape and admission prerequisites.**

  Generate exactly 48 sorted profiles and 240 sorted partitions. Assert that a valid signed plan is prepared deterministically, while too few profiles, too few partitions, duplicate IDs, unresolved profile references, non-canonical bytes, a nonempty campaign, or a dirty C7 pack are rejected.

- [x] **Step 2: Write the default-deny and atomic-start test.**

  Admit a valid plan, authorize no start decision, assert `DEFAULT_DENY`, then issue an exact TrustPlane start decision and assert one `PENDING` effect per partition, the `ACTIVE` transition, the isolated topic, and exact context binding. Assert a replay/conflict does not fan out a second batch.

- [x] **Step 3: Write worker evidence tests.**

  Claim one effect, begin its partition attempt, inspect that `RESEARCH_ATTEMPT_STARTED` precedes any receipt, reject completion without a receipt, record a success receipt plus matching observation and cursor through `ResearchCampaign`, then complete and assert the effect is `SUCCEEDED` only after the proof.

- [x] **Step 4: Write recovery, tamper, progress, and close tests.**

  Expire and recover a lease, assert the next durable attempt key changes, tamper membership/evidence and assert `verify` reports defects, assert progress counts, and assert close refuses until every partition is proven.

- [x] **Step 5: Run the RED suite.**

  Run `python3 -m unittest tests.test_research_marathon -v` from the repository root. Expected result: failure because `starcom.research_marathon` and its public service are not yet implemented.

### Task 2: Implement exact-byte plan admission and immutable memberships

**Files:**
- Create: `src/starcom/research_marathon.py`
- Modify: `src/starcom/cli.py`
- Test: `tests/test_research_marathon.py`

**Interfaces:**
- Consumes: `C7FinalPackService.get_pack/verify_pack`, `ContinuityService.verify_trust_root`, `ResearchCampaign.get_campaign`, `Database.transaction`, and `EventLedger.append_in_transaction`.
- Produces: `ResearchMarathonService.prepare`, `admit_plan`, `get_plan`, `get_profile`, `get_partition`, and immutable schemas for plan, profiles, and partitions.

- [x] **Step 1: Add closed-object parsers and deterministic dataclasses.**

  Parse strict JSON objects, reject unknown/missing keys, validate bounds, RFC3339 timestamps, lowercase SHA-256 digests, sorted unique IDs, canonical request mappings, and exact state/gate values. Compute payload/signature digests from the supplied bytes without reserialization.

- [x] **Step 2: Add immutable schema and admission transaction.**

  Create the six marathon tables/triggers required by the spec, verify the configured Ed25519 root/signature, verify C7 and campaign preconditions, append the admission ledger event, and insert plan/profile/partition rows with ordinal and member ledger hashes.

- [x] **Step 3: Wire `Runtime.research_marathon`.**

  Construct the service after C7 and expose a stable `research_marathon` property without changing existing runtime constructor behavior.

- [x] **Step 4: Run the plan/admission tests green.**

  Run `python3 -m unittest tests.test_research_marathon.ResearchMarathonContractTests -v` and inspect the diff for accidental changes outside the new service and runtime wiring.

### Task 3: Implement authorized start and transactional outbox scheduling

**Files:**
- Modify: `src/starcom/research_marathon.py`
- Modify: `src/starcom/durable.py`
- Test: `tests/test_research_marathon.py`

**Interfaces:**
- Consumes: `TrustPlane.get_decision/verify_decision`, `DurableOutbox.enqueue_in_transaction`, and the immutable plan/membership APIs.
- Produces: `ResearchMarathonService.prepare_start`, `start`, `current_state`, `pause`, and `resume`; outbox transaction completion helper.

- [x] **Step 1: Implement exact start decision validation.**

  Require allowed, verified, exact action/resource/subject/context, one decision per marathon, current `PLANNED_NOT_STARTED`, clean C7, and an empty campaign inside the transaction. Reject mismatches before any effect is inserted.

- [x] **Step 2: Append `ACTIVE` and enqueue effects atomically.**

  Append the transition and enqueue effect IDs `research:marathon:<marathon_id>:partition:<partition_id>` on topic `research.marathon.partition:<marathon_id>`, with the plan digest, profile/partition material, and retry policy in each payload. Assert the effect count cannot exceed one per partition.

- [x] **Step 3: Add paused/resumed append-only transitions.**

  Require explicit TrustPlane actions for pause/resume, allow claims only while `ACTIVE`, and preserve all transition history.

- [x] **Step 4: Run focused start tests green.**

  Run `python3 -m unittest tests.test_research_marathon.ResearchMarathonStartTests -v`.

### Task 4: Implement claim, pre-request attempts, completion proofs, and progress

**Files:**
- Modify: `src/starcom/research_marathon.py`
- Modify: `src/starcom/durable.py`
- Test: `tests/test_research_marathon.py`

**Interfaces:**
- Consumes: `DurableOutbox.claim/recover_expired`, `ResearchCampaign.begin_attempt/verify`, and the immutable plan/membership records.
- Produces: `claim`, `begin_partition_attempt`, `complete_partition`, `progress`, `close_pending_certification`, and `verify`.

- [x] **Step 1: Implement isolated claim and attempt binding.**

  Filter by the marathon topic and `ACTIVE` state. Validate effect payload membership, derive a request key from marathon/partition/durable attempt number, call `ResearchCampaign.begin_attempt` first, then append the partition-attempt mapping.

- [x] **Step 2: Implement proof inspection and canonical result digest.**

  Require all mapped attempts to have receipts, at least one `SUCCESS`, and matching observation/cursor records. Bind the digest to partition material and all evidence IDs/digests.

- [x] **Step 3: Add atomic outbox success.**

  Add a public transaction-scoped outbox success helper that validates the current lease, appends `EFFECT_SUCCEEDED`, and updates the effect only after the marathon completion row and ledger event are persisted in that same SQLite transaction.

- [x] **Step 4: Implement progress and pending-certification close.**

  Return counts by partition/effect status and refuse close until all partitions, effects, and underlying campaign verification are clean. Append only `COMPLETE_PENDING_CERTIFICATION` and never a census certificate.

- [x] **Step 5: Run focused worker tests green.**

  Run `python3 -m unittest tests.test_research_marathon.ResearchMarathonWorkerTests -v`.

### Task 5: Implement independent verifier and tamper coverage

**Files:**
- Modify: `src/starcom/research_marathon.py`
- Modify: `tests/test_research_marathon.py`
- Modify: `src/starcom/cli.py` (only if verification output needs a CLI seam)

**Interfaces:**
- Consumes: all marathon records, C7 verification, Continuity trust-root verification, TrustPlane decision verification, outbox records, ResearchCampaign evidence, and ledger rows.
- Produces: defect-coded `ResearchMarathonVerification` and stable `verify` behavior with no mutation.

- [x] **Step 1: Reconstruct plan and membership bytes.**

  Reparse stored payload/signature, verify digests and signature, recompute each member digest/ordinal/reference, and check immutable trigger presence and counts.

- [x] **Step 2: Verify transitions, decisions, outbox, attempts, and completion evidence.**

  Check append-only sequence/state rules, exact decision context and ledger links, one effect per partition, topic/payload binding, attempt request keys, ResearchCampaign ledger evidence, and canonical completion digests.

- [x] **Step 3: Add tamper tests and run the full marathon suite.**

  Mutate only through dropped triggers/direct SQL in tests and assert stable defect codes. Run `python3 -m unittest tests.test_research_marathon -v`.

### Task 6: Repository gates, review, merge, archive, and handoff

**Files:**
- Modify: `docs/superpowers/specs/2026-08-20-12a-research-marathon-design.md` (only to record final evidence if needed)
- Modify: `docs/superpowers/plans/2026-08-20-12a-research-marathon.md` (check off completed steps)
- Create: `outputs/STARCOM-main-<sha>-issue65-12a-final-evidence-pack-complete.tar.gz`
- Create: `outputs/STARCOM-main-<sha>-issue65-12a-final-evidence-pack-reprise-complete.md`

**Interfaces:**
- Consumes: implementation, tests, repository verification script, GitHub CI, Sonar, issue #65, and branch protection status.
- Produces: reviewed merge on `main`, closed issue #65, source archive, SHA-256, and truthful handoff report.

- [x] **Step 1: Run focused, full, compile, scan, manifest, hash-seed, and warnings gates.**

  Use the repository’s `scripts/verify_repo.py` and record exact counts/output. Treat any failure as a fix loop, not as completion.

- [x] **Step 2: Run independent code verification and request review.**

  Inspect the final diff, run the code-verification skill, and verify no production network imports or transport names were introduced.

- [ ] **Step 3: Commit, push, open PR, and wait for CI/Sonar.**

  Push the recovery branch, open the issue #65 PR, and resolve every blocking check before merge.

- [ ] **Step 4: Merge and verify post-merge main.**

  Merge only after fresh green checks, fast-forward the canonical worktree, and rerun the complete repository verification on merged `main`.

- [ ] **Step 5: Archive exact merged source and write the reprise report.**

  Create the archive from the merged tree, compute SHA-256, test extraction/listing, and document implementation, evidence, truth boundary, PR/issue links, and remaining work.
