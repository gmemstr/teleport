package resources

import (
	"context"
	"fmt"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type TeleportKubernetesResource[T types.Resource] interface {
	kclient.Object
	ToTeleport() T
	StatusConditions() *[]v1.Condition
}

type TeleportResourceReconciler[T types.ResourceWithOrigin, K TeleportKubernetesResource[T]] struct {
	ResourceBaseReconciler
	GetTeleportResource    GetTeleportResource[T]
	UpdateTeleportResource UpdateTeleportResource[T]
	CreateTeleportResource CreateTeleportResource[T]
	DeleteTeleportResource DeleteTeleportResource
}

type GetTeleportResource[T types.Resource] func(context.Context, string) (T, error)
type CreateTeleportResource[T types.Resource] func(context.Context, T) error
type UpdateTeleportResource[T types.Resource] func(context.Context, T) error
type DeleteTeleportResource func(context.Context, string) error

func NewTeleportResourceReconciler[T types.ResourceWithOrigin, K TeleportKubernetesResource[T]](
	client kclient.Client,
	get GetTeleportResource[T],
	update UpdateTeleportResource[T],
	create CreateTeleportResource[T],
	delete DeleteTeleportResource) *TeleportResourceReconciler[T, K] {

	reconciler := &TeleportResourceReconciler[T, K]{
		ResourceBaseReconciler: ResourceBaseReconciler{Client: client},
		GetTeleportResource:    get,
		UpdateTeleportResource: update,
		CreateTeleportResource: create,
		DeleteTeleportResource: delete,
	}
	reconciler.ResourceBaseReconciler.UpsertExternal = reconciler.Upsert
	reconciler.ResourceBaseReconciler.DeleteExternal = reconciler.Delete
	return reconciler
}

func (r TeleportResourceReconciler[T, K]) Upsert(ctx context.Context, obj kclient.Object) error {
	k8sResource, ok := obj.(K)
	if !ok {
		return fmt.Errorf("failed to convert Object into resource object: %T", obj)
	}
	teleportResource := k8sResource.ToTeleport()

	existingResource, err := r.GetTeleportResource(ctx, teleportResource.GetName())
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	exists := !trace.IsNotFound(err)

	newOwnershipCondition, err := checkOwnership(existingResource)
	// Setting the condition before returning a potential ownership error
	meta.SetStatusCondition(k8sResource.StatusConditions(), newOwnershipCondition)
	if err != nil {
		silentUpdateStatus(ctx, r.Client, k8sResource)
		return trace.Wrap(err)
	}

	if err != nil {
		return trace.Wrap(err)
	}

	teleportResource.SetOrigin(types.OriginKubernetes)

	if !exists {
		err = r.CreateTeleportResource(ctx, teleportResource)
	} else {
		/* TODO: handle modifier logic like CreatedBy for users,
		we can add mutate logic, diffing could also happen here */
		err = r.UpdateTeleportResource(ctx, teleportResource)
	}
	// If an error happens we want to put it in status.conditions before returning.
	newReconciliationCondition := getReconciliationConditionFromError(err)
	meta.SetStatusCondition(k8sResource.StatusConditions(), newReconciliationCondition)
	if err != nil {
		silentUpdateStatus(ctx, r.Client, k8sResource)
		return trace.Wrap(err)
	}

	// We update the status conditions on exit
	return trace.Wrap(r.Status().Update(ctx, k8sResource))
}
func (r TeleportResourceReconciler[T, K]) Delete(ctx context.Context, obj kclient.Object) error {
	return r.DeleteTeleportResource(ctx, obj.GetName())
}
