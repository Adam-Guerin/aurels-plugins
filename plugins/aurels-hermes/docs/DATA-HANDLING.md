# Hermes data handling

**Sent to Aurels for enforcement:** action name, action identifier, arguments, optional agent/session metadata, and timestamp.

**Sent for telemetry when enabled:** outcome, trace identifier, action name, and redacted arguments. The package does not send raw action results.

**Never send:** the plugin API key itself. Keep credentials out of action arguments because policy evaluation receives the original arguments.

**Optional semantic processing:** is controlled by the Aurels workspace policy, not the plugin. Confirm enabled processors, retention, and any third-party transfer before using sensitive workloads.
