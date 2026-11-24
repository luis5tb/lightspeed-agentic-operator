package agenticrun

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"

	agenticv1alpha1 "github.com/openshift/lightspeed-agentic-operator/api/v1alpha1"
	"github.com/openshift/lightspeed-agentic-operator/pkg/configuration"
)

// Gateway credential mode (sandbox-credential-mode: gateway).
//
// In this mode the sandbox pod does not hold a spoke SA token. Its kubeconfig
// points at a hub-local Praxis policy gateway that performs an RFC 8693 token
// exchange per call: the server is the gateway, the CA is the gateway's
// serving CA, and the bearer token is the requester's original token (Token A)
// mounted from a run-scoped Secret written by an external A2A adapter.
// The operator does NO spoke management in this mode (no standing
// spoke-kubeconfig, no per-step spoke SA, no reader ClusterRoleBindings): the
// sandbox acts as the requester, so the spoke's own RBAC for that identity
// applies. See spokeManagementAccess.

const (
	// runTokenSecretPrefix is the name prefix for run-scoped Secrets holding
	// the requester's original token (Token A).
	runTokenSecretPrefix = "ls-run-token-"

	// runTokenKey is the data key holding Token A in the run-token Secret.
	runTokenKey = "token-a"

	// Mount path for the gateway serving CA (Secret key ca.crt).
	gatewayCAMountPath = "/var/run/secrets/praxis-gateway"
	gatewayCAFileName  = "ca.crt"
	gatewayCAVolume    = "praxis-gateway-ca"

	// Mount path for the run identity (Token A) Secret. Mounted without
	// subPath so kubelet Secret projection replaces the token file in place
	// when the adapter renews it; clients must reload it.
	runIdentityMountPath = "/var/run/secrets/run-identity"
	runIdentityVolume    = "run-identity"

	// observedRVFormat embeds the run-token Secret's resourceVersion in the
	// CredentialsExpired condition message so the controller can detect
	// renewal (a changed resourceVersion) and re-attempt the paused step.
	observedRVFormat = "(observed resourceVersion %q)"

	ErrGetRunTokenSecret = "get run-token Secret"
)

// gatewayCredentialMode reports whether sandbox spoke credentials are routed
// through the hub-local Praxis policy gateway.
func gatewayCredentialMode(cfg *configuration.Config) bool {
	return cfg != nil && cfg.Sandbox.CredentialMode == configuration.CredentialModeGateway
}

// spokeManagementAccess returns the operator's MANAGEMENT access to the run's
// spoke (the standing spoke-kubeconfig-{targetCluster} Secret), or nil when
// none is needed: hub runs, and spoke runs in gateway credential mode.
//
// In gateway mode the sandbox authenticates to the spoke as the requester
// (Token A, exchanged per call by the Praxis gateway) and the spoke's own
// RBAC for that identity applies. The per-step spoke ServiceAccount and
// per-run reader ClusterRoleBindings that spoke-sa mode creates would never
// be used, so gateway mode creates none of them -- and therefore needs no
// standing admin credential for the spoke, no openshift-lightspeed-managed
// namespace and no lightspeed-hub:* reader bindings on it. Spoke-sa mode is
// unchanged.
//
// Callers must not use a nil result to mean "hub run": use isSpokeRun.
func spokeManagementAccess(ctx context.Context, hubClient client.Client, run *agenticv1alpha1.AgenticRun, operatorNS string, cfg *configuration.Config) (*SpokeAccess, error) {
	if !isSpokeRun(run) || gatewayCredentialMode(cfg) {
		return nil, nil
	}
	return spokeAccessForRun(ctx, hubClient, run, operatorNS)
}

// runTokenSecretName returns the hub Secret name holding the requester's
// original token (Token A) for the run.
func runTokenSecretName(runUID string) string {
	return runTokenSecretPrefix + runUID
}

// credentialWaitError signals that a spoke run in gateway credential mode
// cannot proceed because the run-token Secret is missing, mislabeled, or not
// yet renewed. The reconciler pauses the step (CredentialsExpired condition)
// instead of failing it. The token value is never carried here.
type credentialWaitError struct {
	secretName string
	secretRV   string
	reason     string
}

func (e *credentialWaitError) Error() string {
	return fmt.Sprintf("run credential Secret %s not ready: %s", e.secretName, e.reason)
}

// credentialWaitFromError unwraps a credentialWaitError from an error chain,
// returning nil for every other error.
func credentialWaitFromError(err error) *credentialWaitError {
	var wait *credentialWaitError
	stderrors.As(err, &wait)
	return wait
}

// validateRunTokenSecret fetches and validates the run-token Secret for the
// run. Fail closed: the Secret must exist, carry a non-empty token-a key,
// and be
// labeled with the run UID and the run's target cluster (same label
// convention as spoke-created resources) so a wrong-run or wrong-target
// credential can never be mounted into the sandbox pod. Returns the Secret's
// resourceVersion (never its token value) on success.
func validateRunTokenSecret(ctx context.Context, c client.Client, namespace string, run *agenticv1alpha1.AgenticRun) (string, error) {
	secretName := runTokenSecretName(string(run.UID))
	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return "", &credentialWaitError{secretName: secretName, reason: "Secret not found"}
		}
		return "", fmt.Errorf("%s %s: %w", ErrGetRunTokenSecret, secretName, err)
	}

	if token, ok := secret.Data[runTokenKey]; !ok || len(token) == 0 {
		return secret.ResourceVersion, &credentialWaitError{
			secretName: secretName,
			secretRV:   secret.ResourceVersion,
			reason:     fmt.Sprintf("missing or empty key %q", runTokenKey),
		}
	}
	if got, want := secret.Labels[LabelAgenticRun], string(run.UID); got != want {
		return secret.ResourceVersion, &credentialWaitError{
			secretName: secretName,
			secretRV:   secret.ResourceVersion,
			reason:     fmt.Sprintf("label %s = %q, want run UID %q", LabelAgenticRun, got, want),
		}
	}
	if got, want := secret.Labels[LabelSpokeCluster], truncateLabelValue(run.Spec.TargetCluster); got != want {
		return secret.ResourceVersion, &credentialWaitError{
			secretName: secretName,
			secretRV:   secret.ResourceVersion,
			reason:     fmt.Sprintf("label %s = %q, want target cluster %q", LabelSpokeCluster, got, want),
		}
	}
	return secret.ResourceVersion, nil
}

// buildGatewaySandboxKubeconfig builds a kubeconfig YAML for the sandbox pod
// to reach the spoke through the hub-local Praxis policy gateway. The server
// is the gateway (URL template substituted with the run's immutable
// targetCluster), the CA is the gateway's serving CA mounted in the pod, and
// the bearer token is read from the run-identity token file at request time —
// no token is embedded in the kubeconfig.
func buildGatewaySandboxKubeconfig(serverURLTemplate, targetCluster string) ([]byte, error) {
	kc := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"spoke-via-gateway": {
				Server:               strings.ReplaceAll(serverURLTemplate, "{targetCluster}", targetCluster),
				CertificateAuthority: gatewayCAMountPath + "/" + gatewayCAFileName,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"requester": {TokenFile: runIdentityMountPath + "/" + runTokenKey},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"spoke": {
				Cluster:  "spoke-via-gateway",
				AuthInfo: "requester",
			},
		},
		CurrentContext: "spoke",
	}

	data, err := clientcmd.Write(kc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrBuildSandboxKubeconfig, err)
	}
	return data, nil
}

// mountGatewayCredentials mounts the Praxis gateway serving CA Secret and the
// run-identity token Secret into the sandbox pod spec. Both are read-only.
// The token Secret is mounted WITHOUT subPath so kubelet Secret projection
// replaces the token file in place when the adapter renews it; clients must
// reload the file rather than caching the token.
func mountGatewayCredentials(podSpec *corev1.PodSpec, caSecretName, tokenSecretName string) {
	podSpec.Volumes = append(podSpec.Volumes,
		corev1.Volume{
			Name: gatewayCAVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: caSecretName},
			},
		},
		corev1.Volume{
			Name: runIdentityVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: tokenSecretName},
			},
		},
	)
	for i := range podSpec.Containers {
		podSpec.Containers[i].VolumeMounts = append(podSpec.Containers[i].VolumeMounts,
			corev1.VolumeMount{
				Name:      gatewayCAVolume,
				MountPath: gatewayCAMountPath,
				ReadOnly:  true,
			},
			corev1.VolumeMount{
				Name:      runIdentityVolume,
				MountPath: runIdentityMountPath,
				ReadOnly:  true,
			},
		)
	}
}

// trustedTargetLabels returns the defense-in-depth spoke binding labels for
// the sandbox pod in gateway credential mode (mirrors the spoke SA labels).
// Returns nil for hub runs and for the default spoke-sa mode.
func trustedTargetLabels(cfg *configuration.Config, run *agenticv1alpha1.AgenticRun) map[string]string {
	if run.Spec.TargetCluster == "" || !gatewayCredentialMode(cfg) {
		return nil
	}
	return map[string]string{
		LabelSpokeCluster: truncateLabelValue(run.Spec.TargetCluster),
		LabelAgenticRun:   string(run.UID),
	}
}

// credentialPauseMessage renders a CredentialsExpired condition message that
// embeds the observed run-token Secret resourceVersion for renewal detection.
func credentialPauseMessage(err *credentialWaitError) string {
	return fmt.Sprintf("%s "+observedRVFormat, err.Error(), err.secretRV)
}

// observedRVFromMessage extracts the resourceVersion embedded by
// credentialPauseMessage. Returns "" when absent (e.g. a condition written by
// another component), in which case any valid run-token Secret resumes.
func observedRVFromMessage(message string) string {
	idx := strings.LastIndex(message, "(observed resourceVersion \"")
	if idx < 0 {
		return ""
	}
	rest := message[idx+len("(observed resourceVersion \""):]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// credentialPauseActive reports whether the run is paused waiting for a
// renewed run credential.
func credentialPauseActive(run *agenticv1alpha1.AgenticRun) bool {
	cond := meta.FindStatusCondition(run.Status.Conditions, agenticv1alpha1.AgenticRunConditionCredentialsExpired)
	return cond != nil && cond.Status == metav1.ConditionTrue
}
