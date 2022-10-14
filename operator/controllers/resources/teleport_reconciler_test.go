package resources

import (
	"context"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"testing"
)

type resourceTestingPrimitives[T types.ResourceWithOrigin, K TeleportKubernetesResource[T]] interface {
	init(setup *testSetup)
	setupTeleportFixtures(context.Context) error
	// Interacting with the Teleport Resource
	createTeleportResource(context.Context, string) error
	getTeleportResource(context.Context, string) (T, error)
	deleteTeleportResource(context.Context, string) error
	// Interacting with the Kubernetes Resource
	createKubernetesResource(context.Context, string) error
	deleteKubernetesResource(context.Context, string) error
	getKubernetesResource(context.Context, string) (K, error)
	modifyKubernetesResource(context.Context, string) error
	// Comparing both
	compareTeleportAndKubernetesResource(T, K) bool
}

func testResourceCreation[T types.ResourceWithOrigin, K TeleportKubernetesResource[T]](t *testing.T, test resourceTestingPrimitives[T, K]) {
	ctx := context.Background()
	setup := setupTestEnv(t)
	test.init(setup)
	resourceName := validRandomResourceName("resource-")

	err := test.setupTeleportFixtures(ctx)
	require.NoError(t, err)

	err = test.createKubernetesResource(ctx, resourceName)
	require.NoError(t, err)

	fastEventually(t, func() bool {
		tResource, err := test.getTeleportResource(ctx, resourceName)
		if trace.IsNotFound(err) {
			return false
		}
		require.NoError(t, err)

		require.Equal(t, tResource.GetName(), resourceName)

		require.Contains(t, tResource.GetMetadata().Labels, types.OriginLabel)
		require.Equal(t, tResource.GetMetadata().Labels[types.OriginLabel], types.OriginKubernetes)

		return true
	})

	err = test.deleteKubernetesResource(ctx, resourceName)
	require.NoError(t, err)

	fastEventually(t, func() bool {
		_, err = test.getTeleportResource(ctx, resourceName)
		return trace.IsNotFound(err)
	})
}

func testResourceDeletionDrift[T types.ResourceWithOrigin, K TeleportKubernetesResource[T]](t *testing.T, test resourceTestingPrimitives[T, K]) {
	ctx := context.Background()
	setup := setupTestEnv(t)
	test.init(setup)
	resourceName := validRandomResourceName("user-")

	err := test.setupTeleportFixtures(ctx)
	require.NoError(t, err)

	err = test.createKubernetesResource(ctx, resourceName)
	require.NoError(t, err)

	fastEventually(t, func() bool {
		tResource, err := test.getTeleportResource(ctx, resourceName)
		if trace.IsNotFound(err) {
			return false
		}
		require.NoError(t, err)

		require.Equal(t, tResource.GetName(), resourceName)

		require.Contains(t, tResource.GetMetadata().Labels, types.OriginLabel)
		require.Equal(t, tResource.GetMetadata().Labels[types.OriginLabel], types.OriginKubernetes)

		return true
	})
	// We cause a drift by altering the Teleport resource.
	// To make sure the operator does not reconcile while we're finished we suspend the operator
	setup.stopKubernetesOperator()

	err = test.deleteTeleportResource(ctx, resourceName)
	require.NoError(t, err)
	fastEventually(t, func() bool {
		_, err = test.getTeleportResource(ctx, resourceName)
		return trace.IsNotFound(err)
	})

	// We flag the rresource for deletion in Kubernetes (it won't be fully removed until the operator has processed it and removed the finalizer)
	err = test.deleteKubernetesResource(ctx, resourceName)
	require.NoError(t, err)

	// Test section: We resume the operator, it should reconcile and recover from the drift
	setup.startKubernetesOperator(t)

	// The operator should handle the failed Teleport deletion gracefully and unlock the Kubernetes resource deletion
	fastEventually(t, func() bool {
		_, err = test.getKubernetesResource(ctx, resourceName)
		return kerrors.IsNotFound(err)
	})
}

func testResourceUpdate[T types.ResourceWithOrigin, K TeleportKubernetesResource[T]](t *testing.T, test resourceTestingPrimitives[T, K]) {
	ctx := context.Background()
	setup := setupTestEnv(t)
	test.init(setup)
	resourceName := validRandomResourceName("user-")

	err := test.setupTeleportFixtures(ctx)
	require.NoError(t, err)

	// The resource is created in Teleport
	err = test.createTeleportResource(ctx, resourceName)
	require.NoError(t, err)

	// The resource is created in Kubernetes, with at least a field altered
	err = test.createKubernetesResource(ctx, resourceName)
	require.NoError(t, err)

	// Check the resource was updated in Teleport
	fastEventually(t, func() bool {
		tResource, err := test.getTeleportResource(ctx, resourceName)
		require.NoError(t, err)

		kResource, err := test.getKubernetesResource(ctx, resourceName)
		require.NoError(t, err)

		// Kubernetes and Teleport resources are in-sync
		return test.compareTeleportAndKubernetesResource(tResource, kResource)
	})

	// Updating the resource in Kubernetes
	err = test.modifyKubernetesResource(ctx, resourceName)
	require.NoError(t, err)

	// Check the resource was updated in Teleport
	fastEventually(t, func() bool {
		kResource, err := test.getKubernetesResource(ctx, resourceName)
		require.NoError(t, err)

		tResource, err := test.getTeleportResource(ctx, resourceName)
		require.NoError(t, err)

		// Kubernetes and Teleport resources are in-sync
		return test.compareTeleportAndKubernetesResource(tResource, kResource)
	})
}
