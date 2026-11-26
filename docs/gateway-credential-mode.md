# Gateway Credential Mode — Contract

`sandbox-credential-mode: gateway` (ConfigMap `lightspeed-agentic-configuration`)
changes how sandbox pods authenticate to spoke clusters. The default
`spoke-sa` mode is unchanged: the operator requests a per-step spoke
ServiceAccount token via TokenRequest and embeds it in the sandbox kubeconfig.

## What changes in gateway mode

For spoke runs (`spec.targetCluster` set), the sandbox's kubeconfig no longer
points at the spoke API server. Instead it targets a **hub-local Praxis policy
gateway** that performs an RFC 8693 token exchange per call:

- The kubeconfig `server` is the gateway URL — `gateway-server-url-template`
  with `{targetCluster}` substituted by the run's immutable target cluster.
  When `gateway-execution-server-url-template` is configured, only the
  execution step uses that template (with the same substitution) and the
  execution gateway; analysis, verification, and escalation continue to use
  the read gateway.
- The kubeconfig CA is the gateway's **serving** CA, mounted read-only from the
  Secret named by `gateway-ca-secret` (key `ca.crt`) at
  `/var/run/secrets/praxis-gateway/`.
- The kubeconfig user has **no embedded token**. Its token file is
  `/var/run/secrets/run-identity/token-a` for analysis, verification,
  escalation, and execution when no execution gateway template is configured.
  With the execution template configured, the execution token file is
  `/var/run/secrets/run-identity/token-execution`.
- Both keys are in the run-scoped Secret `ls-run-token-{run UID}`, written by
  the external A2A adapter. The operator validates the selected key is
  non-empty and validates the run and target-cluster labels before creating
  the pod. Each sandbox projects **only its selected key** (key and file path
  are identical), so non-execution sandboxes cannot see `token-execution`.
  The adapter writes `token-execution` only after execution approval and
  removes it when execution ends.
- The kubeconfig Secret machinery (`ls-sandbox-kubeconfig-{step}-{run UID}`,
  owner refs, `KUBECONFIG` env/mount) is identical to `spoke-sa` mode.
- The sandbox pod carries the trusted-target labels
  `hub.openshift.io/agentic-run` and `hub.openshift.io/spoke-cluster`
  (defense-in-depth, mirroring the spoke SA labels).

Required configuration (ConfigMap load fails loudly when missing):
`gateway-server-url-template` and `gateway-ca-secret`. The optional
`gateway-execution-server-url-template` selects a separate execution gateway
and is substituted with `{targetCluster}` in the same way as the read gateway.
When it is empty or absent, execution uses `gateway-server-url-template` and
`token-a`, preserving the original behavior.

## No spoke management in gateway mode

The sandbox acts as the **requester** (Token A, exchanged per call by the
gateway), so the spoke's own RBAC for that identity decides what it may do.
The operator therefore does **no management on the spoke** for gateway-mode
runs (`spokeManagementAccess` in `controller/agenticrun/gateway.go`):

- the standing `spoke-kubeconfig-{targetCluster}` Secret is **not read** and
  need not exist;
- **no per-step ServiceAccount** is created (not on the spoke, not on the hub);
  the sandbox pod runs as the namespace `default` SA, used only to write its
  Result CR to the hub;
- **no per-run reader ClusterRoleBindings** are created, so the spoke needs no
  `openshift-lightspeed-managed` namespace and no `lightspeed-hub:*` reader
  bindings;
- **execution**: the approved option's RBAC is **not materialized**. Execution
  is bounded by the requester's own permissions on the spoke (logged at Info
  when an approved option carries RBAC);
- failure, release and terminal cleanup skip spoke RBAC cleanup (nothing was
  created) and still delete the hub-side sandbox kubeconfig Secret.

Authorization on the spoke comes from bindings for the requester's identity,
e.g. `cluster-reader` bound to the group the exchanged token carries.

**Why:** the earlier gateway implementation kept the spoke-sa management
path. It created a per-step spoke SA and reader bindings that the sandbox
never used (it never got their token), but still required a standing
admin-capable spoke credential, and left a dormant read-privileged SA per
run. Found live (2026-11-20): the first gateway runs failed cleanup on a
missing `spoke-kubeconfig-hub`.

## What does NOT change

- Hub runs and the stock `spoke-sa` mode are byte-identical when the new keys
  are absent (the default). Spoke-sa mode still reads the standing
  `spoke-kubeconfig-{targetCluster}` Secret, creates the per-step spoke SA and
  per-run reader ClusterRoleBindings, and mints the sandbox token via
  TokenRequest.

## Token renewal

The selected run-token Secret item is mounted **without subPath**, so kubelet
Secret projection replaces the token file in place when the adapter renews it.
Clients in the sandbox must reload the file per request (or reconnect
long-lived transports) rather than caching the token — Secret projection
propagation is eventually consistent.

## Credential pause (`CredentialsExpired` condition)

When the run-token Secret is missing, mislabeled, or lacks the non-empty key
selected for the step (`token-a` or `token-execution`), the controller sets
the `CredentialsExpired` condition (reason `CredentialsExpired`) on the
AgenticRun and does not create the pod.
The external A2A adapter watches this condition to surface `AUTH_REQUIRED` to
the caller and rewrites `ls-run-token-{run UID}`. The controller re-attempts
the paused step once that Secret's resourceVersion changes (the observed
resourceVersion is embedded in the condition message; the token value is
never logged or exposed). The condition also records the selected key and an
opaque hash of the selected gateway endpoint. If configuration changes the
selector while the run is paused, a valid credential for the new selector
resumes the step without requiring an otherwise unnecessary Secret rewrite.
Endpoint URLs and credential values are not included in this metadata. Legacy
condition messages without selector metadata retain resourceVersion-only
resume behavior. The condition does not participate in phase
derivation; the step condition stays `Unknown` (in progress) while paused.

Resume latency: detection of renewal is poll-based — the worst case is one
`credentialPauseRequeueAfter` interval (30s) from the Secret rewrite to the
re-attempted step, plus informer resync latency after an operator restart.
A watch on the run-token Secret (event-driven resume) is a possible
follow-up that would remove the poll.

Condition-writer trust: the resourceVersion-in-message renewal rule trusts
only condition messages written by this controller via the status
subresource. A condition message written by another component — or any
message the controller cannot parse an observed resourceVersion out of —
resumes as soon as the run-token Secret validates with correct labels,
rather than blocking on a resourceVersion comparison.

Mode flip: if `sandbox-credential-mode` is switched back to `spoke-sa` while
a run is paused, the `CredentialsExpired` condition is cleared and the run
resumes unconditionally — the pause reason (a missing run-token Secret) no
longer applies in spoke-sa mode.
