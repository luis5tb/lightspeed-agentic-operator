package agenticrun

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	agenticv1alpha1 "github.com/openshift/lightspeed-agentic-operator/api/v1alpha1"
)

const (
	ErrPauseForCredentials = "pause run for credential renewal"

	// credentialPauseRequeueAfter is the poll interval while a run waits for
	// the external A2A adapter to (re)write the run-token Secret.
	credentialPauseRequeueAfter = 30 * time.Second
)

// pauseForCredentials records a CredentialsExpired condition and requeues.
// The step condition stays Unknown (in progress); the run waits for the
// run-token Secret to be (re)written by the external A2A adapter, which
// watches the condition to surface AUTH_REQUIRED to the caller. The message
// carries the Secret name and its observed resourceVersion — never the token
// value.
func (r *AgenticRunReconciler) pauseForCredentials(ctx context.Context, run *agenticv1alpha1.AgenticRun, waitErr *credentialWaitError) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("pausing run for credential renewal", LogKeyName, waitErr.secretName, "reason", waitErr.reason)

	base := run.DeepCopy()
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type:               agenticv1alpha1.AgenticRunConditionCredentialsExpired,
		Status:             metav1.ConditionTrue,
		Reason:             agenticv1alpha1.ReasonCredentialsExpired,
		Message:            credentialPauseMessage(waitErr),
		ObservedGeneration: run.Generation,
	})
	if err := r.statusPatch(ctx, run, base); err != nil {
		return ctrl.Result{}, fmt.Errorf("%s: %w", ErrPauseForCredentials, err)
	}
	return ctrl.Result{RequeueAfter: credentialPauseRequeueAfter}, nil
}

// resumeFromCredentialPause checks whether the run-token Secret backing a
// CredentialsExpired pause has been renewed. It returns true (and clears the
// condition) when the Secret validates and its resourceVersion differs from
// the one recorded at pause time — the controller then re-attempts the paused
// step. Returns false while the Secret is still missing, mislabeled, or
// unchanged. A condition message without a recorded resourceVersion (e.g.
// written by another component) resumes as soon as the Secret validates.
//
// When the current configuration is no longer gateway credential mode (the
// mode was flipped back to spoke-sa mid-pause), the pause reason no longer
// applies: the condition is cleared and the run resumes unconditionally.
// Without this, a mode flip would leave the run requeueing forever on a
// credential it no longer needs, with no sandbox pod for the timeout
// handler to observe.
func (r *AgenticRunReconciler) resumeFromCredentialPause(ctx context.Context, run *agenticv1alpha1.AgenticRun, step string) (bool, error) {
	cond := meta.FindStatusCondition(run.Status.Conditions, agenticv1alpha1.AgenticRunConditionCredentialsExpired)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		return true, nil
	}

	// A nil Config cache means configuration has not been observed; keep
	// waiting in that case rather than resuming on an unknown mode.
	if r.Config != nil && !gatewayCredentialMode(r.Config.Get()) {
		logf.FromContext(ctx).Info("credential mode no longer gateway, resuming paused run")
		base := run.DeepCopy()
		meta.RemoveStatusCondition(&run.Status.Conditions, agenticv1alpha1.AgenticRunConditionCredentialsExpired)
		if err := r.statusPatch(ctx, run, base); err != nil {
			return false, fmt.Errorf("clear %s condition: %w", agenticv1alpha1.AgenticRunConditionCredentialsExpired, err)
		}
		return true, nil
	}

	rv, err := validateRunTokenSecret(ctx, r.Client, r.Namespace, run, step, configFrom(r.Config))
	if err != nil {
		// Still missing or mislabeled — keep waiting. The error never
		// carries the token value.
		logf.FromContext(ctx).V(1).Info("run credential still not ready", "error", err.Error())
		return false, nil
	}
	selectorChanged := false
	if recorded := selectorFromMessage(cond.Message); recorded != "" {
		selectorChanged = recorded != credentialSelectorIdentity(step, configFrom(r.Config))
	}
	if !selectorChanged && rv == observedRVFromMessage(cond.Message) {
		// Secret unchanged since the pause was recorded — the renewed
		// credential has not landed yet. A changed selector is an
		// independent resume signal: validation above checked the newly
		// selected key and labels, even when the Secret RV did not change.
		return false, nil
	}

	base := run.DeepCopy()
	meta.RemoveStatusCondition(&run.Status.Conditions, agenticv1alpha1.AgenticRunConditionCredentialsExpired)
	if err := r.statusPatch(ctx, run, base); err != nil {
		return false, fmt.Errorf("clear %s condition: %w", agenticv1alpha1.AgenticRunConditionCredentialsExpired, err)
	}
	return true, nil
}
