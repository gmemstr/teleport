package v3

import (
	"encoding/json"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/stretchr/testify/require"
	"testing"
)

// This tests that `redirect_url` is consistently marshalled as a list of string
// This is not the case of wrappers.Strings which marshalls as a string if it contains a single element
func TestTeleportOIDCConnectorSpec_MarshalJSON(t *testing.T) {
	tests := []struct {
		name         string
		spec         TeleportOIDCConnectorSpec
		expectedJSON string
	}{
		{
			"Empty string",
			TeleportOIDCConnectorSpec{RedirectURLs: wrappers.Strings{""}},
			`{"redirect_url":[""],"issuer_url":"","client_id":"","client_secret":""}`,
		},
		{
			"Single string",
			TeleportOIDCConnectorSpec{RedirectURLs: wrappers.Strings{"foo"}},
			`{"redirect_url":["foo"],"issuer_url":"","client_id":"","client_secret":""}`,
		},
		{
			"Multiple strings",
			TeleportOIDCConnectorSpec{RedirectURLs: wrappers.Strings{"foo", "bar"}},
			`{"redirect_url":["foo","bar"],"issuer_url":"","client_id":"","client_secret":""}`,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result, err := json.Marshal(tc.spec)
			require.NoError(t, err)
			require.Equal(t, string(result), tc.expectedJSON)
		})
	}
}
