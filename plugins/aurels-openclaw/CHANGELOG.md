# Changelog

## 0.3.0

- Reject authenticated HTTP redirects and report actual host tool failures correctly.
- Freeze evaluated parameters through one-shot approval; remove duplicate blocked telemetry for flagged actions.
- Refuse untested OpenClaw runtimes at registration; support exactly 2026.3.28 and 2026.9.6.
- Harden snapshots, protocol validation, trace bounds and process-safe telemetry delivery.
- Add self-hosted evaluator configuration and host-level dispatch regression coverage.

## 0.2.2

- Add explicit local/remote modes, approval handoff, and telemetry lifecycle coverage.

## 0.2.1

- Require HTTPS endpoints, bound remote responses, and flag all non-blocked local actions.

## 0.2.0

- First independent package release.
- Explicit allow, flag, block, rewrite, timeout, and telemetry contracts.
