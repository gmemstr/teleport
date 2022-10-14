package resources

import (
	"context"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/gravitational/trace"
	"testing"

	"github.com/gravitational/teleport/api/types"
	resourcesv3 "github.com/gravitational/teleport/operator/apis/resources/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var oidcSpec = types.OIDCConnectorSpecV3{
	IssuerURL:    "https://issuer",
	ClientID:     "client id",
	ClientSecret: "client secret",
	ClaimsToRoles: []types.ClaimMapping{{
		Claim: "claim",
		Value: "value",
		Roles: []string{"roleA"},
	}},
	RedirectURLs: []string{"https://redirect"},
}

type oidcTestingPrimitives struct {
	setup *testSetup
}

func (g *oidcTestingPrimitives) init(setup *testSetup) {
	g.setup = setup
}

func (g *oidcTestingPrimitives) setupTeleportFixtures(ctx context.Context) error {
	return nil
}

func (g *oidcTestingPrimitives) createTeleportResource(ctx context.Context, name string) error {
	oidc, err := types.NewOIDCConnector(name, oidcSpec)
	if err != nil {
		return trace.Wrap(err)
	}
	oidc.SetOrigin(types.OriginKubernetes)
	return trace.Wrap(g.setup.tClient.UpsertOIDCConnector(ctx, oidc))
}

func (g *oidcTestingPrimitives) getTeleportResource(ctx context.Context, name string) (types.OIDCConnector, error) {
	return g.setup.tClient.GetOIDCConnector(ctx, name, true)
}

func (g *oidcTestingPrimitives) deleteTeleportResource(ctx context.Context, name string) error {
	return trace.Wrap(g.setup.tClient.DeleteOIDCConnector(ctx, name))
}

func (g *oidcTestingPrimitives) createKubernetesResource(ctx context.Context, name string) error {
	oidc := &resourcesv3.TeleportOIDCConnector{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: g.setup.namespace.Name,
		},
		Spec: resourcesv3.TeleportOIDCConnectorSpec(oidcSpec),
	}
	return trace.Wrap(g.setup.k8sClient.Create(ctx, oidc))
}

func (g *oidcTestingPrimitives) deleteKubernetesResource(ctx context.Context, name string) error {
	oidc := &resourcesv3.TeleportOIDCConnector{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: g.setup.namespace.Name,
		},
	}
	return trace.Wrap(g.setup.k8sClient.Delete(ctx, oidc))
}

func (g *oidcTestingPrimitives) getKubernetesResource(ctx context.Context, name string) (*resourcesv3.TeleportOIDCConnector, error) {
	oidc := &resourcesv3.TeleportOIDCConnector{}
	obj := kclient.ObjectKey{
		Name:      name,
		Namespace: g.setup.namespace.Name,
	}
	err := g.setup.k8sClient.Get(ctx, obj, oidc)
	return oidc, trace.Wrap(err)
}

func (g *oidcTestingPrimitives) modifyKubernetesResource(ctx context.Context, name string) error {
	oidc, err := g.getKubernetesResource(ctx, name)
	if err != nil {
		return trace.Wrap(err)
	}
	oidc.Spec.RedirectURLs = []string{"https://redirect1", "https://redirect2"}
	return g.setup.k8sClient.Update(ctx, oidc)
}

func (g *oidcTestingPrimitives) compareTeleportAndKubernetesResource(tResource types.OIDCConnector, kResource *resourcesv3.TeleportOIDCConnector) bool {
	teleportMap, _ := teleportResourceToMap(tResource)
	kubernetesMap, _ := teleportResourceToMap(kResource.ToTeleport())

	equal := cmp.Equal(teleportMap["spec"], kubernetesMap["spec"])
	if !equal {
		fmt.Println(cmp.Diff(teleportMap["spec"], kubernetesMap["spec"]))
	}

	return equal
}

func (g *oidcTestingPrimitives) Resource(ctx context.Context, name string) error {
	return trace.Wrap(g.setup.tClient.DeleteOIDCConnector(ctx, name))
}

func TestOIDCConnectorCreation(t *testing.T) {
	test := &oidcTestingPrimitives{}
	testResourceCreation[types.OIDCConnector, *resourcesv3.TeleportOIDCConnector](t, test)
}

func TestOIDCConnectorDeletionDrift(t *testing.T) {
	test := &oidcTestingPrimitives{}
	testResourceDeletionDrift[types.OIDCConnector, *resourcesv3.TeleportOIDCConnector](t, test)
}

func TestOIDCConnectorUpdate(t *testing.T) {
	test := &oidcTestingPrimitives{}
	testResourceUpdate[types.OIDCConnector, *resourcesv3.TeleportOIDCConnector](t, test)
}
