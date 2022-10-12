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

type OIDCConnectorReconciler struct {
	*TeleportResourceReconciler[types.OIDCConnector, *resourcesv3.TeleportOIDCConnector]
	TeleportClientAccessor sidecar.ClientAccessor
}

func NewOIDCConnectorReconciler(client kclient.Client, accessor sidecar.ClientAccessor) *OIDCConnectorReconciler {
	oidcReconciler := &OIDCConnectorReconciler{
		TeleportResourceReconciler: nil,
		TeleportClientAccessor:     accessor,
	}

	resourceReconciler := NewTeleportResourceReconciler[types.OIDCConnector, *resourcesv3.TeleportOIDCConnector](
		client,
		oidcReconciler.GetOIDCConnector,
		oidcReconciler.UpsertOIDCConnector,
		oidcReconciler.UpsertOIDCConnector,
		oidcReconciler.DeleteOIDCConnector)

	oidcReconciler.TeleportResourceReconciler = resourceReconciler

	return oidcReconciler
}

func (r OIDCConnectorReconciler) GetOIDCConnector(ctx context.Context, name string) (types.OIDCConnector, error) {
	teleportClient, err := r.TeleportClientAccessor(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return teleportClient.GetOIDCConnector(ctx, name, false /* with secrets*/)
}

func (r OIDCConnectorReconciler) UpsertOIDCConnector(ctx context.Context, oidc types.OIDCConnector) error {
	teleportClient, err := r.TeleportClientAccessor(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	return teleportClient.UpsertOIDCConnector(ctx, oidc)
}

func (r OIDCConnectorReconciler) DeleteOIDCConnector(ctx context.Context, name string) error {
	teleportClient, err := r.TeleportClientAccessor(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	return teleportClient.DeleteOIDCConnector(ctx, name)
}

func (r OIDCConnectorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return r.Do(ctx, req, &resourcesv3.TeleportOIDCConnector{})
}

func (r OIDCConnectorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&resourcesv3.TeleportOIDCConnector{}).Complete(r)
}
