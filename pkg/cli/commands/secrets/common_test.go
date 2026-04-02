package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/superplanehq/superplane/pkg/openapi_client"
)

func writeManifest(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

func TestParseSecretFile_ValidManifest(t *testing.T) {
	path := writeManifest(t, `
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
spec:
  provider: PROVIDER_LOCAL
  local:
    data:
      API_KEY: my-api-key
`)
	resource, err := parseSecretFile(path)
	require.NoError(t, err)
	require.NotNil(t, resource)
	assert.Equal(t, "my-secret", resource.Metadata.GetName())
	assert.Equal(t, openapi_client.SECRETPROVIDER_PROVIDER_LOCAL, resource.Spec.GetProvider())
}

func TestParseSecretFile_ProviderAlias(t *testing.T) {
	path := writeManifest(t, `
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
spec:
  provider: local
  local:
    data:
      API_KEY: my-api-key
`)
	resource, err := parseSecretFile(path)
	require.NoError(t, err)
	require.NotNil(t, resource)
	assert.Equal(t, openapi_client.SECRETPROVIDER_PROVIDER_LOCAL, resource.Spec.GetProvider())
}

func TestParseSecretFile_InvalidProvider(t *testing.T) {
	path := writeManifest(t, `
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
spec:
  provider: vault
  local:
    data:
      API_KEY: my-api-key
`)
	_, err := parseSecretFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault is not a valid SecretProvider")
}

func TestParseSecretFile_MissingName(t *testing.T) {
	path := writeManifest(t, `
apiVersion: v1
kind: Secret
metadata: {}
spec:
  provider: local
  local:
    data:
      API_KEY: my-api-key
`)
	_, err := parseSecretFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata.name is required")
}

func TestParseSecretFile_MissingSpec(t *testing.T) {
	path := writeManifest(t, `
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
`)
	_, err := parseSecretFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec is required")
}

func TestParseSecretFile_MissingProvider(t *testing.T) {
	path := writeManifest(t, `
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
spec:
  local:
    data:
      API_KEY: my-api-key
`)
	_, err := parseSecretFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec.provider is required")
}

func TestParseSecretFile_MissingData(t *testing.T) {
	path := writeManifest(t, `
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
spec:
  provider: local
`)
	_, err := parseSecretFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec.local.data is required")
}

func TestParseSecretFile_EmptyData(t *testing.T) {
	path := writeManifest(t, `
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
spec:
  provider: local
  local:
    data: {}
`)
	_, err := parseSecretFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec.local.data is required")
}

func TestParseSecretFile_WrongKind(t *testing.T) {
	path := writeManifest(t, `
apiVersion: v1
kind: Canvas
metadata:
  name: my-secret
spec:
  provider: local
  local:
    data:
      KEY: value
`)
	_, err := parseSecretFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported resource kind")
}

func TestParseSecretFile_WrongAPIVersion(t *testing.T) {
	path := writeManifest(t, `
apiVersion: v2
kind: Secret
metadata:
  name: my-secret
spec:
  provider: local
  local:
    data:
      KEY: value
`)
	_, err := parseSecretFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported apiVersion")
}
