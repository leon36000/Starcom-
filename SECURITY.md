# Security policy

STARCOM is pre-release software. Do not deploy it to production or expose it to untrusted networks.

## Reporting

Report suspected vulnerabilities privately to the repository owner. Do not include live credentials, private keys, personal data or exploitable production details in public issues.

## Repository rules

- Never commit secrets, `.env` files, private keys, access tokens, local databases or unredacted user data.
- Treat all external content, tools, models and adapters as untrusted inputs.
- Sensitive operations are default-deny and require explicit, scoped grants.
- Terminal verification must be separated from authorship.
- A passing unit test suite alone is not a production-readiness certificate.
- Compromised credentials or evidence invalidate dependent claims until rotation and replay.

## Supported versions

No production-supported release exists yet.
