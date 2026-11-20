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

// --- credential pause / resume ---

func newCredentialPauseReconciler(t *testing.T, run *agenticv1alpha1.AgenticRun, objs ...client.Object) (*AgenticRunReconciler, client.Client) {
	t.Helper()
	builder := fake.NewClientBuilder().WithScheme(testScheme()).
		WithStatusSubresource(&agenticv1alpha1.AgenticRun{}).
		WithObjects(run)
	if len(objs) > 0 {
		builder = builder.WithObjects(objs...)
	}
	fc := builder.Build()
	return &AgenticRunReconciler{Client: fc, Namespace: "test-ns"}, fc
}

func TestPauseForCredentials_SetsCondition(t *testing.T) {
	run := testSpokeRun()
	r, fc := newCredentialPauseReconciler(t, run)

	waitErr := &credentialWaitError{
		secretName: runTokenSecretName(string(run.UID)),
		secretRV:   "42",
		reason:     "Secret not found",
	}
	result, err := r.pauseForCredentials(context.Background(), run, waitErr)
	if err != nil {
		t.Fatalf("pauseForCredentials failed: %v", err)
	}
	if result.RequeueAfter != credentialPauseRequeueAfter {
		t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, credentialPauseRequeueAfter)
	}

	stored := &agenticv1alpha1.AgenticRun{}
	if err := fc.Get(context.Background(), client.ObjectKeyFromObject(run), stored); err != nil {
		t.Fatalf("get run: %v", err)
	}
	cond := findCondition(stored, agenticv1alpha1.AgenticRunConditionCredentialsExpired)
	if cond == nil {
		t.Fatal("CredentialsExpired condition not set")
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("condition status = %q", cond.Status)
	}
	if cond.Reason != agenticv1alpha1.ReasonCredentialsExpired {
		t.Errorf("condition reason = %q, want %q", cond.Reason, agenticv1alpha1.ReasonCredentialsExpired)
	}
	if observedRVFromMessage(cond.Message) != "42" {
		t.Errorf("message should embed observed resourceVersion 42, got %q", cond.Message)
	}
	if strings.Contains(cond.Message, "token-a-value") {
		t.Error("condition message must never contain the token value")
	}
}

func TestResumeFromCredentialPause(t *testing.T) {
	run := testSpokeRun()

	tests := []struct {
		name        string
		secretRV    string // run-token Secret resourceVersion; "" = absent
		pausedRV    string // resourceVersion embedded in the pause condition
		wantResumed bool
	}{
		{name: "secret still missing", secretRV: "", pausedRV: "", wantResumed: false},
		{name: "secret unchanged", secretRV: "42", pausedRV: "42", wantResumed: false},
		{name: "secret renewed", secretRV: "43", pausedRV: "42", wantResumed: true},
		{name: "no recorded RV resumes on valid secret", secretRV: "43", pausedRV: "", wantResumed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []client.Object
			if tt.secretRV != "" {
				objs = append(objs, testRunTokenSecret(run, tt.secretRV))
			}
			paused := run.DeepCopy()
			stampCredentialsExpired(t, paused, tt.pausedRV)
			r, fc := newCredentialPauseReconciler(t, paused, objs...)

			resumed, err := r.resumeFromCredentialPause(context.Background(), paused)
			if err != nil {
				t.Fatalf("resumeFromCredentialPause failed: %v", err)
			}
			if resumed != tt.wantResumed {
				t.Fatalf("resumed = %v, want %v", resumed, tt.wantResumed)
			}

			stored := &agenticv1alpha1.AgenticRun{}
			if err := fc.Get(context.Background(), client.ObjectKeyFromObject(run), stored); err != nil {
				t.Fatalf("get run: %v", err)
			}
			cond := findCondition(stored, agenticv1alpha1.AgenticRunConditionCredentialsExpired)
			if tt.wantResumed && cond != nil {
				t.Error("condition should be cleared after resume")
			}
			if !tt.wantResumed && cond == nil {
				t.Error("condition should remain while paused")
			}
		})
	}
}

func TestCredentialPauseMessage_RoundTrip(t *testing.T) {
	waitErr := &credentialWaitError{secretName: "ls-run-token-x", secretRV: "77", reason: "missing key"}
	msg := credentialPauseMessage(waitErr)
	if got := observedRVFromMessage(msg); got != "77" {
		t.Errorf("observedRVFromMessage = %q, want 77 (message %q)", got, msg)
	}
	if got := observedRVFromMessage("externally written message"); got != "" {
		t.Errorf("unparseable message should yield %q, got %q", "", got)
	}
}

// TestResumeFromCredentialPause_ModeFlipToSpokeSA verifies that a run paused
// in gateway credential mode resumes unconditionally when the configuration
// flips back to spoke-sa mid-pause. Without this, the run would requeue
// forever waiting for a run-token Secret it no longer needs, with no sandbox
// pod for the timeout handler to observe.
func TestResumeFromCredentialPause_ModeFlipToSpokeSA(t *testing.T) {
	run := testSpokeRun()

	tests := []struct {
		name        string
		config      *configuration.Cache
		wantResumed bool
	}{
		{
			name:        "still gateway mode keeps waiting without secret",
			config:      testGatewayCache(t),
			wantResumed: false,
		},
		{
			name:        "mode flipped to spoke-sa resumes without secret",
			config:      testCache(t, "bare-pod"),
			wantResumed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paused := run.DeepCopy()
			stampCredentialsExpired(t, paused, "42")
			r, fc := newCredentialPauseReconciler(t, paused)
			r.Config = tt.config

			resumed, err := r.resumeFromCredentialPause(context.Background(), paused)
			if err != nil {
				t.Fatalf("resumeFromCredentialPause failed: %v", err)
			}
			if resumed != tt.wantResumed {
				t.Fatalf("resumed = %v, want %v", resumed, tt.wantResumed)
			}

			stored := &agenticv1alpha1.AgenticRun{}
			if err := fc.Get(context.Background(), client.ObjectKeyFromObject(run), stored); err != nil {
				t.Fatalf("get run: %v", err)
			}
			cond := findCondition(stored, agenticv1alpha1.AgenticRunConditionCredentialsExpired)
			if tt.wantResumed && cond != nil {
				t.Error("condition should be cleared after mode-flip resume")
			}
			if !tt.wantResumed && cond == nil {
				t.Error("condition should remain while still gateway-paused")
			}
		})
	}
}

// --- handler-level pause → resume → relaunch ---

// countingAgentCaller wraps an AgentCaller and counts Analyze invocations,
// distinguishing successful relaunches from attempts that paused waiting for
// credentials (the pause happens inside Sandbox.Create, after Analyze was
// entered).
type countingAgentCaller struct {
	AgentCaller
	analyzeCalls       int
	analyzeCompletions int
}

func (c *countingAgentCaller) Analyze(ctx context.Context, run *agenticv1alpha1.AgenticRun, step resolvedStep) error {
	c.analyzeCalls++
	err := c.AgentCaller.Analyze(ctx, run, step)
	if err == nil {
		c.analyzeCompletions++
	}
	return err
}

// TestHandleAnalysis_CredentialPauseResumeRelaunch exercises the handler-level
// pause → resume → relaunch path in gateway credential mode: a missing
// run-token Secret pauses analysis (Analyzed=Unknown, CredentialsExpired=True,
// no pod); the adapter then writes a renewed, valid-labeled run-token Secret;
// the next handler pass resumes and relaunches the agent exactly once; and a
// further pass must not double-create the sandbox pod.
func TestHandleAnalysis_CredentialPauseResumeRelaunch(t *testing.T) {
	origClient := NewClientFromConfig
	origClientset := NewClientsetFromConfig

	srcBindings := spokeReaderBindings()
	spokeFC := fake.NewClientBuilder().WithScheme(testScheme()).
		WithObjects(srcBindings[0], srcBindings[1]).Build()
	NewClientFromConfig = func(cfg *rest.Config) (client.Client, error) {
		return spokeFC, nil
	}
	// The spoke TokenRequest API must never be called in gateway mode.
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
	hubFC := fake.NewClientBuilder().WithScheme(testScheme()).
		WithStatusSubresource(&agenticv1alpha1.AgenticRun{}).
		WithObjects(run, testReaderCRB(), testSpokeKubeconfigSecret()).
		Build()
	mgr := newTestSandboxManager(hubFC, cache)
	agent := &countingAgentCaller{AgentCaller: &SandboxAgentCaller{
		Sandbox:   mgr,
		K8sClient: hubFC,
		APIReader: hubFC,
		Namespace: "test-ns",
	}}
	r := &AgenticRunReconciler{
		Client:    hubFC,
		APIReader: hubFC,
		Agent:     agent,
		Config:    cache,
		Namespace: "test-ns",
	}
	resolved := &resolvedWorkflow{Analysis: resolvedStep{
		Agent: testSMAgent(),
		LLM:   testLLMForManager(),
	}}
	policy := testAutoApprovePolicy()

	countPods := func() int {
		t.Helper()
		var pods corev1.PodList
		if err := hubFC.List(context.Background(), &pods); err != nil {
			t.Fatalf("list pods: %v", err)
		}
		return len(pods.Items)
	}
	currentRun := func() *agenticv1alpha1.AgenticRun {
		t.Helper()
		stored := &agenticv1alpha1.AgenticRun{}
		if err := hubFC.Get(context.Background(), client.ObjectKeyFromObject(run), stored); err != nil {
			t.Fatalf("get run: %v", err)
		}
		return stored
	}

	// Pass 1: no run-token Secret yet — the step pauses before any pod or
	// spoke resource is created.
	result, err := r.handleAnalysis(context.Background(), currentRun(), resolved, nil, policy)
	if err != nil {
		t.Fatalf("pass 1 handleAnalysis: %v", err)
	}
	if result.RequeueAfter != credentialPauseRequeueAfter {
		t.Fatalf("pass 1 RequeueAfter = %v, want %v", result.RequeueAfter, credentialPauseRequeueAfter)
	}
	if agent.analyzeCalls != 1 || agent.analyzeCompletions != 0 {
		t.Fatalf("agent Analyze calls during pause = %d (completed %d), want 1 entered / 0 completed (paused before pod creation)", agent.analyzeCalls, agent.analyzeCompletions)
	}
	if got := countPods(); got != 0 {
		t.Fatalf("pods during pause = %d, want 0", got)
	}
	if !credentialPauseActive(currentRun()) {
		t.Fatal("run should carry an active CredentialsExpired condition while paused")
	}

	// The adapter renews the credential: a new, valid-labeled run-token
	// Secret (the fake client assigns it resourceVersion "1" on create,
	// which differs from the RV observed at pause time for the missing
	// Secret, exercising the resourceVersion-changed resume path).
	renewed := testRunTokenSecret(run, "43")
	renewed.ResourceVersion = ""
	if err := hubFC.Create(context.Background(), renewed); err != nil {
		t.Fatalf("create renewed run-token Secret: %v", err)
	}

	// Pass 2: renewed Secret — the pause clears and the agent relaunches
	// exactly once, creating the sandbox pod exactly once.
	result, err = r.handleAnalysis(context.Background(), currentRun(), resolved, nil, policy)
	if err != nil {
		t.Fatalf("pass 2 handleAnalysis: %v", err)
	}
	if result.Requeue || result.RequeueAfter != 0 {
		t.Fatalf("pass 2 should proceed without requeue, got %+v", result)
	}
	if agent.analyzeCalls != 2 || agent.analyzeCompletions != 1 {
		t.Fatalf("agent Analyze calls after resume = %d (completed %d), want 2 entered / 1 completed relaunch", agent.analyzeCalls, agent.analyzeCompletions)
	}
	if got := countPods(); got != 1 {
		t.Fatalf("pods after resume = %d, want 1", got)
	}
	resumed := currentRun()
	if credentialPauseActive(resumed) {
		t.Fatal("CredentialsExpired condition should be cleared after resume")
	}
	if resumed.Status.Steps.Analysis.Sandbox.ClaimName == "" {
		t.Fatal("analysis sandbox info should be recorded after relaunch")
	}

	// Pass 3: Analyzed=Unknown with no active pause — the in-progress guard
	// must hold: no second agent call, no double pod creation.
	if _, err := r.handleAnalysis(context.Background(), currentRun(), resolved, nil, policy); err != nil {
		t.Fatalf("pass 3 handleAnalysis: %v", err)
	}
	if agent.analyzeCalls != 2 || agent.analyzeCompletions != 1 {
		t.Fatalf("agent Analyze calls after third pass = %d (completed %d), want 2 entered / 1 completed (no double-create)", agent.analyzeCalls, agent.analyzeCompletions)
	}
	if got := countPods(); got != 1 {
		t.Fatalf("pods after third pass = %d, want 1 (no double-create)", got)
	}
}

func findCondition(run *agenticv1alpha1.AgenticRun, condType string) *metav1.Condition {
	for i := range run.Status.Conditions {
		if run.Status.Conditions[i].Type == condType {
			return &run.Status.Conditions[i]
		}
	}
	return nil
}

// stampCredentialsExpired stamps a CredentialsExpired=True condition with
// the given observed resourceVersion embedded in the message.
func stampCredentialsExpired(t *testing.T, run *agenticv1alpha1.AgenticRun, rv string) {
	t.Helper()
	run.Status.Conditions = append(run.Status.Conditions, metav1.Condition{
		Type:    agenticv1alpha1.AgenticRunConditionCredentialsExpired,
		Status:  metav1.ConditionTrue,
		Reason:  agenticv1alpha1.ReasonCredentialsExpired,
		Message: fmt.Sprintf("run credential Secret not ready (observed resourceVersion %q)", rv),
	})
}

// Gateway mode needs no spoke management credential on teardown either:
// releasing a gateway spoke run's sandbox must succeed without the
// spoke-kubeconfig-{targetCluster} Secret (it created nothing on the spoke),
// while spoke-sa mode still reports the missing management credential.
// Live finding (2026-11-20): before this, failure/terminal cleanup of every
// gateway run logged `get spoke kubeconfig Secret spoke-kubeconfig-hub:
// not found`, and ReleaseSandbox returned that error.
func TestRelease_GatewaySpokeRun_NoSpokeKubeconfig(t *testing.T) {
	origClient := NewClientFromConfig
	NewClientFromConfig = func(cfg *rest.Config) (client.Client, error) {
		t.Error("no spoke management client may be built in gateway credential mode")
		return nil, fmt.Errorf("unexpected spoke client in gateway mode")
	}
	t.Cleanup(func() { NewClientFromConfig = origClient })

	run := testSpokeRun()
	run.Status.Steps.Analysis.Sandbox.ClaimName = "ls-analysis-gateway-release"
	fc := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(run).Build()
	sandbox := &mockSandboxProvider{}
	caller := &SandboxAgentCaller{
		Sandbox: sandbox, K8sClient: fc, APIReader: fc, Namespace: "test-ns",
		Config: testGatewayCache(t),
	}

	if err := caller.ReleaseSandbox(context.Background(), run, "analysis"); err != nil {
		t.Fatalf("gateway ReleaseSandbox without spoke kubeconfig: %v", err)
	}
	if err := caller.ReleaseSandboxes(context.Background(), run, false); err != nil {
		t.Fatalf("gateway ReleaseSandboxes without spoke kubeconfig: %v", err)
	}
	if sandbox.releaseCalls == 0 {
		t.Error("sandbox Release was not called")
	}

	// spoke-sa mode (nil config) still needs and reports the management credential.
	NewClientFromConfig = origClient
	caller.Config = nil
	if err := caller.ReleaseSandbox(context.Background(), run, "analysis"); err == nil {
		t.Error("spoke-sa ReleaseSandbox must report the missing spoke kubeconfig")
	}
}
