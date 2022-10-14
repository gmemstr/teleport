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

var githubSpec = types.GithubConnectorSpecV3{
	ClientID:      "client id",
	ClientSecret:  "client secret",
	RedirectURL:   "https://redirect",
	TeamsToLogins: nil,
	Display:       "",
	TeamsToRoles: []types.TeamRolesMapping{{
		Organization: "test",
		Team:         "test",
		Roles:        []string{"test"},
	}},
}

type githubTestingPrimitives struct {
	setup *testSetup
}

func (g *githubTestingPrimitives) init(setup *testSetup) {
	g.setup = setup
}

func (g *githubTestingPrimitives) setupTeleportFixtures(ctx context.Context) error {
	return nil
}

func (g *githubTestingPrimitives) createTeleportResource(ctx context.Context, name string) error {
	github, err := types.NewGithubConnector(name, githubSpec)
	if err != nil {
		return trace.Wrap(err)
	}
	github.SetOrigin(types.OriginKubernetes)
	return trace.Wrap(g.setup.tClient.UpsertGithubConnector(ctx, github))
}

func (g *githubTestingPrimitives) getTeleportResource(ctx context.Context, name string) (types.GithubConnector, error) {
	return g.setup.tClient.GetGithubConnector(ctx, name, true)
}

func (g *githubTestingPrimitives) deleteTeleportResource(ctx context.Context, name string) error {
	return trace.Wrap(g.setup.tClient.DeleteGithubConnector(ctx, name))
}

func (g *githubTestingPrimitives) createKubernetesResource(ctx context.Context, name string) error {
	github := &resourcesv3.TeleportGithubConnector{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: g.setup.namespace.Name,
		},
		Spec: resourcesv3.TeleportGithubConnectorSpec(githubSpec),
	}
	return trace.Wrap(g.setup.k8sClient.Create(ctx, github))
}

func (g *githubTestingPrimitives) deleteKubernetesResource(ctx context.Context, name string) error {
	github := &resourcesv3.TeleportGithubConnector{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: g.setup.namespace.Name,
		},
	}
	return trace.Wrap(g.setup.k8sClient.Delete(ctx, github))
}

func (g *githubTestingPrimitives) getKubernetesResource(ctx context.Context, name string) (*resourcesv3.TeleportGithubConnector, error) {
	github := &resourcesv3.TeleportGithubConnector{}
	obj := kclient.ObjectKey{
		Name:      name,
		Namespace: g.setup.namespace.Name,
	}
	err := g.setup.k8sClient.Get(ctx, obj, github)
	return github, trace.Wrap(err)
}

func (g *githubTestingPrimitives) modifyKubernetesResource(ctx context.Context, name string) error {
	github, err := g.getKubernetesResource(ctx, name)
	if err != nil {
		return trace.Wrap(err)
	}
	github.Spec.TeamsToRoles[0].Roles = []string{"foo", "bar"}
	return trace.Wrap(g.setup.k8sClient.Update(ctx, github))
}

func (g *githubTestingPrimitives) compareTeleportAndKubernetesResource(tResource types.GithubConnector, kResource *resourcesv3.TeleportGithubConnector) bool {
	teleportMap, _ := teleportResourceToMap(tResource)
	kubernetesMap, _ := teleportResourceToMap(kResource.ToTeleport())

	equal := cmp.Equal(teleportMap["spec"], kubernetesMap["spec"])
	if !equal {
		fmt.Println(cmp.Diff(teleportMap["spec"], kubernetesMap["spec"]))
	}

	return equal
}

func (g *githubTestingPrimitives) Resource(ctx context.Context, name string) error {
	return trace.Wrap(g.setup.tClient.DeleteGithubConnector(ctx, name))
}

func TestGithubConnectorCreation(t *testing.T) {
	test := &githubTestingPrimitives{}
	testResourceCreation[types.GithubConnector, *resourcesv3.TeleportGithubConnector](t, test)
}

func TestGithubConnectorDeletionDrift(t *testing.T) {
	test := &githubTestingPrimitives{}
	testResourceDeletionDrift[types.GithubConnector, *resourcesv3.TeleportGithubConnector](t, test)
}

func TestGithubConnectorUpdate(t *testing.T) {
	test := &githubTestingPrimitives{}
	testResourceUpdate[types.GithubConnector, *resourcesv3.TeleportGithubConnector](t, test)
}
