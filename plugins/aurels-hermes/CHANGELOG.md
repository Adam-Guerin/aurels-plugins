# Changelog

## 0.3.0

- Classify native Hermes `ok` as success and error, blocked, timeout, cancelled or unknown statuses as failure.
- Preserve action/trace correlation and verify both outcomes through the pinned host's real dispatcher.
- Add snapshot-bound synchronous dispatch; require explicit trust for native hook ordering.
- Harden endpoint and response validation, redaction and process-safe telemetry delivery.
- Add self-hosted evaluator configuration and host-level regression coverage.

## 0.2.2

- Add explicit local/remote modes, approval handling, and strict two-hook startup validation.

## 0.2.1

- Require HTTPS endpoints, bound remote responses, and flag all non-blocked local actions.

## 0.2.0

- First independent Python package release.
- Explicit preflight, redaction, telemetry, and fail-mode contract.
