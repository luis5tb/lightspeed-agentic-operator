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
- The kubeconfig CA is the gateway's **serving** CA, mounted read-only from the
  Secret named by `gateway-ca-secret` (key `ca.crt`) at
  `/var/run/secrets/praxis-gateway/`.
- The kubeconfig user has **no embedded token**; it uses
  `tokenFile: /var/run/secrets/run-identity/token-a`, the requester's original
  token (Token A) mounted from the run-scoped Secret `ls-run-token-{run UID}`.
  That Secret is written by the external A2A adapter and is validated (fail
  closed) by the operator before the pod is created: it must exist, carry the
  `token-a` key, and be labeled `hub.openshift.io/agentic-run: {run UID}` and
  `hub.openshift.io/spoke-cluster: {target cluster}`.
- The kubeconfig Secret machinery (`ls-sandbox-kubeconfig-{step}-{run UID}`,
  owner refs, `KUBECONFIG` env/mount) is identical to `spoke-sa` mode.
- The sandbox pod carries the trusted-target labels
  `hub.openshift.io/agentic-run` and `hub.openshift.io/spoke-cluster`
  (defense-in-depth, mirroring the spoke SA labels).

Required configuration (ConfigMap load fails loudly when missing):
`gateway-server-url-template` and `gateway-ca-secret`.

## What does NOT change

- **Management kubeconfigs are not rewritten.** The standing
  `spoke-kubeconfig-{targetCluster}` Secret still drives SA/RBAC creation and
  cleanup on the spoke via the spoke client. Only the sandbox *execution*
  kubeconfig is rewritten to the gateway.
- The per-step spoke SA and per-run reader ClusterRoleBindings are still
  created on the spoke; only the TokenRequest for the sandbox token is
  skipped.
- Hub runs and the stock `spoke-sa` mode are byte-identical when the new keys
  are absent (the default).

## Token renewal

The run-token Secret is mounted **without subPath**, so kubelet Secret
projection replaces the token file in place when the adapter renews it.
Clients in the sandbox must reload the file per request (or reconnect
long-lived transports) rather than caching the token — Secret projection
propagation is eventually consistent.

## Credential pause (`CredentialsExpired` condition)

When the run-token Secret is missing, mislabeled, or its token was
rejected/expired, the controller sets the `CredentialsExpired` condition
(reason `CredentialsExpired`) on the AgenticRun and does not create the pod.
The external A2A adapter watches this condition to surface `AUTH_REQUIRED` to
the caller and rewrites `ls-run-token-{run UID}`. The controller re-attempts
the paused step once that Secret's resourceVersion changes (the observed
resourceVersion is embedded in the condition message; the token value is
never logged or exposed). The condition does not participate in phase
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
