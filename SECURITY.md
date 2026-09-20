# Security policy

Report vulnerabilities privately to security@aurels.dev. Do not include credentials, customer data, or a working exploit in public issues.

Supported releases receive fixes on the latest minor version of each plugin. Plugin packages fail closed by default when the Aurels decision service is unavailable, malformed, or returns an unsupported decision.

## Key scopes

Use a dedicated plugin key restricted to `actions:evaluate` and, if enabled, `telemetry:create`. Do not use workspace administration, billing, policy-write, membership, or key-management credentials in an agent runtime.

## Trust and disclosure

For a release, verify `SHA256SUMS`, `MANIFEST.json`, `SBOM.spdx.json`, and `PROVENANCE.json` against the GitHub release and its tagged commit. Release publication must additionally use a Sigstore/cosign signature before being declared production-ready.
