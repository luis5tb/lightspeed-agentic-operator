package agenticrun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	agenticv1alpha1 "github.com/openshift/lightspeed-agentic-operator/api/v1alpha1"
	"github.com/openshift/lightspeed-agentic-operator/pkg/configuration"
)

func testGatewayCache(t *testing.T) *configuration.Cache {
	t.Helper()
	c := &configuration.Cache{}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: configuration.ConfigMapName},
		Data: map[string]string{
			configuration.KeySandboxMode:              "bare-pod",
			configuration.KeySandboxCredentialMode:    configuration.CredentialModeGateway,
			configuration.KeyGatewayServerURLTemplate: "https://praxis-spoke-{targetCluster}.praxis-proxy.svc.cluster.local:8443",
			configuration.KeyGatewayCASecret:          "praxis-serving-ca",
			configuration.KeySandboxPodSpec:           `{"containers":[{"name":"agent","image":"registry.example.com/agent:latest","ports":[{"containerPort":8080}]}]}`,
		},
	}
	if err := c.OnConfigMapChange(context.Background(), cm); err != nil {
		t.Fatalf("testGatewayCache: OnConfigMapChange failed: %v", err)
	}
	return c
}

func testRunTokenSecret(run *agenticv1alpha1.AgenticRun, resourceVersion string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            runTokenSecretName(string(run.UID)),
			Namespace:       "test-ns",
			ResourceVersion: resourceVersion,
			Labels: map[string]string{
				LabelAgenticRun:   string(run.UID),
				LabelSpokeCluster: run.Spec.TargetCluster,
			},
		},
		Data: map[string][]byte{
			runTokenKey: []byte("token-a-value"),
		},
	}
}

// --- buildGatewaySandboxKubeconfig ---

func TestBuildGatewaySandboxKubeconfig(t *testing.T) {
	data, err := buildGatewaySandboxKubeconfig(
		"https://praxis-spoke-{targetCluster}.praxis-proxy.svc.cluster.local:8443", "east-spoke")
	if err != nil {
		t.Fatalf("buildGatewaySandboxKubeconfig failed: %v", err)
	}

	parsed, err := clientcmd.Load(data)
	if err != nil {
		t.Fatalf("failed to parse gateway kubeconfig: %v", err)
	}

	if parsed.CurrentContext != "spoke" {
		t.Errorf("current context = %q, want %q", parsed.CurrentContext, "spoke")
	}
	kcCtx, ok := parsed.Contexts["spoke"]
	if !ok {
		t.Fatal("context \"spoke\" not found")
	}
	if kcCtx.Cluster != "spoke-via-gateway" || kcCtx.AuthInfo != "requester" {
		t.Errorf("context = cluster %q user %q, want spoke-via-gateway/requester", kcCtx.Cluster, kcCtx.AuthInfo)
	}

	cluster, ok := parsed.Clusters["spoke-via-gateway"]
	if !ok {
		t.Fatal("cluster \"spoke-via-gateway\" not found")
	}
	wantServer := "https://praxis-spoke-east-spoke.praxis-proxy.svc.cluster.local:8443"
	if cluster.Server != wantServer {
		t.Errorf("server = %q, want %q", cluster.Server, wantServer)
	}
	if cluster.CertificateAuthority != gatewayCAMountPath+"/"+gatewayCAFileName {
		t.Errorf("certificate-authority = %q, want %q", cluster.CertificateAuthority, gatewayCAMountPath+"/"+gatewayCAFileName)
	}
	if cluster.CertificateAuthorityData != nil {
		t.Error("certificate-authority-data should not be embedded in gateway kubeconfig")
	}
	if cluster.InsecureSkipTLSVerify {
		t.Error("insecure-skip-tls-verify must never be set")
	}

	authInfo, ok := parsed.AuthInfos["requester"]
	if !ok {
		t.Fatal("auth info \"requester\" not found")
	}
	if authInfo.Token != "" {
		t.Error("gateway kubeconfig must not embed a token")
	}
	if authInfo.TokenFile != runIdentityMountPath+"/"+runTokenKey {
		t.Errorf("tokenFile = %q, want %q", authInfo.TokenFile, runIdentityMountPath+"/"+runTokenKey)
	}
}

// --- validateRunTokenSecret ---

func TestValidateRunTokenSecret_HappyPath(t *testing.T) {
	run := testSpokeRun()
	fc := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(testRunTokenSecret(run, "101")).
		Build()

	rv, err := validateRunTokenSecret(context.Background(), fc, "test-ns", run)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rv != "101" {
		t.Errorf("resourceVersion = %q, want %q", rv, "101")
	}
}

func TestValidateRunTokenSecret_Missing(t *testing.T) {
	run := testSpokeRun()
	fc := fake.NewClientBuilder().WithScheme(testScheme()).Build()

	_, err := validateRunTokenSecret(context.Background(), fc, "test-ns", run)
	if err == nil {
		t.Fatal("expected error for missing Secret")
	}
	var wait *credentialWaitError
	if !errors.As(err, &wait) {
		t.Fatalf("expected credentialWaitError, got %T: %v", err, err)
	}
}

func TestValidateRunTokenSecret_MissingKey(t *testing.T) {
	run := testSpokeRun()
	secret := testRunTokenSecret(run, "1")
	delete(secret.Data, runTokenKey)
	fc := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(secret).Build()

	_, err := validateRunTokenSecret(context.Background(), fc, "test-ns", run)
	var wait *credentialWaitError
	if !errors.As(err, &wait) {
		t.Fatalf("expected credentialWaitError, got %T: %v", err, err)
	}
	if !strings.Contains(wait.Error(), runTokenKey) {
		t.Errorf("error should mention the missing key %q, got %q", runTokenKey, wait.Error())
	}
}

// TestValidateRunTokenSecret_EmptyTokenValue verifies fail-closed behavior
// when the token-a key is present but zero-length: an empty value must not
// validate (a Secret created with an empty token must pause the run, not
// mount an empty credential into the sandbox).
func TestValidateRunTokenSecret_EmptyTokenValue(t *testing.T) {
	run := testSpokeRun()
	secret := testRunTokenSecret(run, "1")
	secret.Data[runTokenKey] = []byte{}
	fc := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(secret).Build()

	_, err := validateRunTokenSecret(context.Background(), fc, "test-ns", run)
	var wait *credentialWaitError
	if !errors.As(err, &wait) {
		t.Fatalf("expected credentialWaitError, got %T: %v", err, err)
	}
	if !strings.Contains(wait.Error(), runTokenKey) {
		t.Errorf("error should mention the key %q, got %q", runTokenKey, wait.Error())
	}
}

func TestValidateRunTokenSecret_LabelMismatch(t *testing.T) {
	run := testSpokeRun()

	tests := []struct {
		name   string
		mutate func(secret *corev1.Secret)
	}{
		{
			name: "wrong run UID",
			mutate: func(secret *corev1.Secret) {
				secret.Labels[LabelAgenticRun] = "another-run-uid"
			},
		},
		{
			name: "wrong target cluster",
			mutate: func(secret *corev1.Secret) {
				secret.Labels[LabelSpokeCluster] = "other-spoke"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := testRunTokenSecret(run, "1")
			tt.mutate(secret)
			fc := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(secret).Build()

			_, err := validateRunTokenSecret(context.Background(), fc, "test-ns", run)
			var wait *credentialWaitError
			if !errors.As(err, &wait) {
				t.Fatalf("expected credentialWaitError, got %T: %v", err, err)
			}
		})
	}
}

// --- mountGatewayCredentials ---

func TestMountGatewayCredentials(t *testing.T) {
	podSpec := &corev1.PodSpec{Containers: []corev1.Container{{Name: "agent"}}}

	mountGatewayCredentials(podSpec, "praxis-serving-ca", "ls-run-token-uid")

	volumes := map[string]corev1.Volume{}
	for _, v := range podSpec.Volumes {
		volumes[v.Name] = v
	}
	caVol, ok := volumes[gatewayCAVolume]
	if !ok {
		t.Fatalf("missing %s volume", gatewayCAVolume)
	}
	if caVol.Secret == nil || caVol.Secret.SecretName != "praxis-serving-ca" {
		t.Errorf("CA volume source = %v", caVol.VolumeSource)
	}
	tokenVol, ok := volumes[runIdentityVolume]
	if !ok {
		t.Fatalf("missing %s volume", runIdentityVolume)
	}
	if tokenVol.Secret == nil || tokenVol.Secret.SecretName != "ls-run-token-uid" {
		t.Errorf("run-identity volume source = %v", tokenVol.VolumeSource)
	}

	mounts := map[string]corev1.VolumeMount{}
	for _, m := range podSpec.Containers[0].VolumeMounts {
		mounts[m.Name] = m
	}
	for volumeName, wantPath := range map[string]string{
		gatewayCAVolume:   gatewayCAMountPath,
		runIdentityVolume: runIdentityMountPath,
	} {
		m, ok := mounts[volumeName]
		if !ok {
			t.Fatalf("container missing %s mount", volumeName)
		}
		if m.MountPath != wantPath {
			t.Errorf("%s mount path = %q, want %q", volumeName, m.MountPath, wantPath)
		}
		if !m.ReadOnly {
			t.Errorf("%s mount should be read-only", volumeName)
		}
		if m.SubPath != "" {
			t.Errorf("%s mount must not use subPath — the token file must be replaceable via Secret projection", volumeName)
		}
	}
}

// --- trustedTargetLabels ---

func TestTrustedTargetLabels(t *testing.T) {
	run := testSpokeRun()
	gatewayCfg := testGatewayCache(t).Get()
	spokeSACfg := testCache(t, "bare-pod").Get()

	labels := trustedTargetLabels(gatewayCfg, run)
	if labels == nil {
		t.Fatal("expected labels in gateway mode for a spoke run")
	}
	if labels[LabelSpokeCluster] != "test-spoke" {
		t.Errorf("%s = %q, want %q", LabelSpokeCluster, labels[LabelSpokeCluster], "test-spoke")
	}
	if labels[LabelAgenticRun] != string(run.UID) {
		t.Errorf("%s = %q, want run UID %q", LabelAgenticRun, labels[LabelAgenticRun], run.UID)
	}

	if trustedTargetLabels(spokeSACfg, run) != nil {
		t.Error("spoke-sa mode must not add trusted-target labels")
	}
	hubRun := testSMRun()
	if trustedTargetLabels(gatewayCfg, hubRun) != nil {
		t.Error("hub runs must not get trusted-target labels")
	}
}

// --- SandboxManager.Create in gateway mode ---

// TestCreate_GatewaySpokeRun verifies the full gateway credential path: no
// spoke SA token is requested, the kubeconfig Secret points at the gateway
// with a tokenFile (no embedded token), and the pod mounts the gateway CA and
// run-identity Secrets with trusted-target labels.
func TestCreate_GatewaySpokeRun(t *testing.T) {
	origClient := NewClientFromConfig
	origClientset := NewClientsetFromConfig

	// Gateway mode does NO spoke management: no spoke client is ever built
	// and the spoke TokenRequest API is never called.
	NewClientFromConfig = func(cfg *rest.Config) (client.Client, error) {
		t.Error("no spoke management client may be built in gateway credential mode")
		return nil, fmt.Errorf("unexpected spoke client in gateway mode")
	}
	NewClientsetFromConfig = func(cfg *rest.Config) (kubernetes.Interface, error) {
		t.Error("requestSpokeToken must not be called in gateway credential mode")
		return nil, fmt.Errorf("unexpected TokenRequest in gateway mode")
	}
	t.Cleanup(func() {
		NewClientFromConfig = origClient
		NewClientsetFromConfig = origClientset
	})

	cache := testGatewayCache(t)
	run := testSpokeRun()
	// Deliberately NO spoke-kubeconfig-{targetCluster} Secret: gateway mode
	// needs no standing management credential for the spoke.
	hubFC := fake.NewClientBuilder().WithScheme(testScheme()).
		WithObjects(testReaderCRB(), testRunTokenSecret(run, "101")).
		Build()
	mgr := newTestSandboxManager(hubFC, cache)

	name, err := mgr.Create(context.Background(), seedSandboxRun(t, mgr, run), "analysis", testSMAgent(), testLLMForManager(), nil, 15*time.Minute, nil)
	if err != nil {
		t.Fatalf("Create gateway spoke run failed: %v", err)
	}

	// No per-step ServiceAccount anywhere (not even on the hub).
	saName := sandboxSAName(run, "analysis")
	var sa corev1.ServiceAccount
	if err := hubFC.Get(context.Background(), types.NamespacedName{Name: saName, Namespace: "test-ns"}, &sa); !apierrors.IsNotFound(err) {
		t.Errorf("gateway mode must not create a per-step SA on the hub, got err=%v", err)
	}
	// The shared hub reader CRB was not extended with a gateway-run subject.
	var crb rbacv1.ClusterRoleBinding
	if err := hubFC.Get(context.Background(), types.NamespacedName{Name: testReaderCRB().Name}, &crb); err != nil {
		t.Fatalf("reader CRB: %v", err)
	}
	for _, s := range crb.Subjects {
		if s.Name == saName {
			t.Errorf("gateway run SA %q added to reader CRB %q", saName, crb.Name)
		}
	}

	// Kubeconfig Secret exists, points at the gateway, embeds no token.
	kcSecretName := sandboxKubeconfigSecretName(string(run.UID), "analysis")
	var kcSecret corev1.Secret
	if err := hubFC.Get(context.Background(), types.NamespacedName{Name: kcSecretName, Namespace: "test-ns"}, &kcSecret); err != nil {
		t.Fatalf("sandbox kubeconfig Secret not found: %v", err)
	}
	parsedKC, kcErr := clientcmd.Load(kcSecret.Data[spokeKubeconfigFileName])
	if kcErr != nil {
		t.Fatalf("failed to parse gateway kubeconfig: %v", kcErr)
	}
	cluster := parsedKC.Clusters[parsedKC.Contexts[parsedKC.CurrentContext].Cluster]
	if cluster.Server != "https://praxis-spoke-test-spoke.praxis-proxy.svc.cluster.local:8443" {
		t.Errorf("gateway kubeconfig server = %q", cluster.Server)
	}
	authInfo := parsedKC.AuthInfos[parsedKC.Contexts[parsedKC.CurrentContext].AuthInfo]
	if authInfo.Token != "" || authInfo.TokenFile != runIdentityMountPath+"/"+runTokenKey {
		t.Errorf("gateway kubeconfig auth = token %q tokenFile %q", authInfo.Token, authInfo.TokenFile)
	}
	if kcSecret.Labels[LabelRun] != string(run.UID) {
		t.Errorf("kubeconfig Secret run label = %q", kcSecret.Labels[LabelRun])
	}

	// Pod: kubeconfig + gateway CA + run-identity mounts, KUBECONFIG env,
	// trusted-target labels.
	var pod corev1.Pod
	if err := hubFC.Get(context.Background(), types.NamespacedName{Name: name, Namespace: "test-ns"}, &pod); err != nil {
		t.Fatalf("pod not found: %v", err)
	}
	if pod.Labels[LabelSpokeCluster] != "test-spoke" || pod.Labels[LabelAgenticRun] != string(run.UID) {
		t.Errorf("pod trusted-target labels = %v", pod.Labels)
	}
	volumes := map[string]corev1.Volume{}
	for _, v := range pod.Spec.Volumes {
		volumes[v.Name] = v
	}
	for _, volumeName := range []string{spokeKubeconfigVolume, gatewayCAVolume, runIdentityVolume} {
		if _, ok := volumes[volumeName]; !ok {
			t.Errorf("pod missing %s volume", volumeName)
		}
	}
	if got := volumes[runIdentityVolume].Secret.SecretName; got != runTokenSecretName(string(run.UID)) {
		t.Errorf("run-identity volume secret = %q, want %q", got, runTokenSecretName(string(run.UID)))
	}
	mounts := map[string]corev1.VolumeMount{}
	for _, m := range pod.Spec.Containers[0].VolumeMounts {
		mounts[m.Name] = m
	}
	for _, volumeName := range []string{spokeKubeconfigVolume, gatewayCAVolume, runIdentityVolume} {
		if _, ok := mounts[volumeName]; !ok {
			t.Errorf("container missing %s mount", volumeName)
		}
	}
	foundEnv := false
	for _, e := range pod.Spec.Containers[0].Env {
		if e.Name == "KUBECONFIG" {
			foundEnv = true
		}
	}
	if !foundEnv {
		t.Error("pod missing KUBECONFIG env var")
	}
}

// TestCreate_GatewaySpokeRun_MissingRunToken verifies fail-closed behavior:
// a missing run-token Secret pauses the run (credentialWaitError) before any
// resources are created — no pod, no spoke SA.
func TestCreate_GatewaySpokeRun_MissingRunToken(t *testing.T) {
	origClient := NewClientFromConfig
	spokeFC := fake.NewClientBuilder().WithScheme(testScheme()).Build()
	NewClientFromConfig = func(cfg *rest.Config) (client.Client, error) {
		return spokeFC, nil
	}
	t.Cleanup(func() { NewClientFromConfig = origClient })

	cache := testGatewayCache(t)
	run := testSpokeRun()
	hubFC := fake.NewClientBuilder().WithScheme(testScheme()).
		WithObjects(testReaderCRB(), testSpokeKubeconfigSecret()).
		Build()
	mgr := newTestSandboxManager(hubFC, cache)

	_, err := mgr.Create(context.Background(), seedSandboxRun(t, mgr, run), "analysis", testSMAgent(), testLLMForManager(), nil, 15*time.Minute, nil)
	var wait *credentialWaitError
	if !errors.As(err, &wait) {
		t.Fatalf("expected credentialWaitError, got %T: %v", err, err)
	}

	var pods corev1.PodList
	if err := hubFC.List(context.Background(), &pods); err != nil {
		t.Fatalf("list pods: %v", err)
	}
	if len(pods.Items) != 0 {
		t.Errorf("no pod should be created while credentials are missing, found %d", len(pods.Items))
	}
	saName := sandboxSAName(run, "analysis")
	var sa corev1.ServiceAccount
	if err := spokeFC.Get(context.Background(), types.NamespacedName{Name: saName, Namespace: spokeManagedNamespace}, &sa); err == nil {
		t.Error("no spoke SA should be created while credentials are missing")
	}
}
