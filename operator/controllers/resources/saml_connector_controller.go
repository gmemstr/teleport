package resources

import (
	"context"
	"github.com/gravitational/teleport/api/types"
	resourcesv2 "github.com/gravitational/teleport/operator/apis/resources/v2"
	"github.com/gravitational/teleport/operator/sidecar"
	"github.com/gravitational/trace"
	ctrl "sigs.k8s.io/controller-runtime"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type SAMLConnectorReconciler struct {
	*TeleportResourceReconciler[types.SAMLConnector, *resourcesv2.TeleportSAMLConnector]
	TeleportClientAccessor sidecar.ClientAccessor
}

func NewSAMLConnectorReconciler(client kclient.Client, accessor sidecar.ClientAccessor) *SAMLConnectorReconciler {
	oidcReconciler := &SAMLConnectorReconciler{
		TeleportResourceReconciler: nil,
		TeleportClientAccessor:     accessor,
	}

	resourceReconciler := NewTeleportResourceReconciler[types.SAMLConnector, *resourcesv2.TeleportSAMLConnector](
		client,
		oidcReconciler.GetSAMLConnector,
		oidcReconciler.UpsertSAMLConnector,
		oidcReconciler.UpsertSAMLConnector,
		oidcReconciler.DeleteSAMLConnector)

	oidcReconciler.TeleportResourceReconciler = resourceReconciler

	return oidcReconciler
}

func (r SAMLConnectorReconciler) GetSAMLConnector(ctx context.Context, name string) (types.SAMLConnector, error) {
	teleportClient, err := r.TeleportClientAccessor(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return teleportClient.GetSAMLConnector(ctx, name, false /* with secrets*/)
}

func (r SAMLConnectorReconciler) UpsertSAMLConnector(ctx context.Context, oidc types.SAMLConnector) error {
	teleportClient, err := r.TeleportClientAccessor(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	return teleportClient.UpsertSAMLConnector(ctx, oidc)
}

func (r SAMLConnectorReconciler) DeleteSAMLConnector(ctx context.Context, name string) error {
	teleportClient, err := r.TeleportClientAccessor(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	return teleportClient.DeleteSAMLConnector(ctx, name)
}

func (r SAMLConnectorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return r.Do(ctx, req, &resourcesv2.TeleportSAMLConnector{})
}

func (r SAMLConnectorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&resourcesv2.TeleportSAMLConnector{}).Complete(r)
}
