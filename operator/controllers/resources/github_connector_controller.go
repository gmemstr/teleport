package resources

import (
	"context"
	"github.com/gravitational/teleport/api/types"
	resourcesv3 "github.com/gravitational/teleport/operator/apis/resources/v3"
	"github.com/gravitational/teleport/operator/sidecar"
	"github.com/gravitational/trace"
	ctrl "sigs.k8s.io/controller-runtime"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type GithubConnectorReconciler struct {
	*TeleportResourceReconciler[types.GithubConnector, *resourcesv3.TeleportGithubConnector]
	TeleportClientAccessor sidecar.ClientAccessor
}

func NewGithubConnectorReconciler(client kclient.Client, accessor sidecar.ClientAccessor) *GithubConnectorReconciler {
	oidcReconciler := &GithubConnectorReconciler{
		TeleportResourceReconciler: nil,
		TeleportClientAccessor:     accessor,
	}

	resourceReconciler := NewTeleportResourceReconciler[types.GithubConnector, *resourcesv3.TeleportGithubConnector](
		client,
		oidcReconciler.GetGithubConnector,
		oidcReconciler.UpsertGithubConnector,
		oidcReconciler.UpsertGithubConnector,
		oidcReconciler.DeleteGithubConnector)

	oidcReconciler.TeleportResourceReconciler = resourceReconciler

	return oidcReconciler
}

func (r GithubConnectorReconciler) GetGithubConnector(ctx context.Context, name string) (types.GithubConnector, error) {
	teleportClient, err := r.TeleportClientAccessor(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return teleportClient.GetGithubConnector(ctx, name, false /* with secrets*/)
}

func (r GithubConnectorReconciler) UpsertGithubConnector(ctx context.Context, oidc types.GithubConnector) error {
	teleportClient, err := r.TeleportClientAccessor(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	return teleportClient.UpsertGithubConnector(ctx, oidc)
}

func (r GithubConnectorReconciler) DeleteGithubConnector(ctx context.Context, name string) error {
	teleportClient, err := r.TeleportClientAccessor(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	return teleportClient.DeleteGithubConnector(ctx, name)
}

func (r GithubConnectorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return r.Do(ctx, req, &resourcesv3.TeleportGithubConnector{})
}

func (r GithubConnectorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&resourcesv3.TeleportGithubConnector{}).Complete(r)
}
