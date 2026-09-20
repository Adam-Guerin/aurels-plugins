# OpenClaw data handling

**Sent to Aurels for enforcement:** tool name, action identifier, arguments, agent/session metadata when provided, and timestamp.

**Sent for telemetry when enabled:** outcome, Aurels trace identifier, tool name, and redacted parameters. Raw tool results are not collected by this package.

**Never send:** the plugin API key itself. Avoid placing credentials in tool arguments; evaluation needs the original arguments before telemetry redaction.

**Optional semantic processing:** depends on the Aurels workspace policy. Confirm any third-party semantic processor and retention setting in your Aurels data-processing documentation before enabling it for sensitive workloads.
