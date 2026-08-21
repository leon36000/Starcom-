# STARCOM external evidence CLI — implementation plan

1. Add RED E2E tests for empty snapshot, real Ed25519 admission/get/verify,
   whitespace mutation, missing files, structured errors, and forbidden
   operational commands.
2. Implement a small argparse CLI over `StarcomProgram.open` with exact-byte
   file reads and JSON response/error handling.
3. Run focused, full, warnings-as-errors, hash-seed, manifest, scan, and
   post-fusion gates; publish and merge only after CI/Sonar are green.
