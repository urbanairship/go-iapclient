package iapclient

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/google"
	iam "google.golang.org/api/iam/v1"
)

type MockedTransport struct {
	mock.Mock
}

func (m *MockedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	log.Printf("shit: %v", args)
	//return args.Bool(0), args.Error(1)
	return nil, fmt.Errorf("MockedTransport")
	return nil, args.Error(1)
}

func googleFindDefaultCredentialsAppDefaultMock(ctx context.Context, scope ...string) (*google.Credentials, error) {
	creds := google.Credentials{}
	creds.JSON = []byte(`{}`)
	return &creds, nil
}

func googleFindDefaultCredentialsAuthorizedUserJSONMock(ctx context.Context, scope ...string) (*google.Credentials, error) {
	creds := google.Credentials{}
	creds.JSON = []byte(`{
  "client_id": "some-client-id.apps.googleusercontent.com",
  "client_secret": "ffffffffffffffffffffffff",
  "refresh_token": "fffffffffffffffffffffffffffffffffffffffffffff",
  "type": "authorized_user"
}`)
	return &creds, nil
}
func googleFindDefaultCredentialsServiceAccountJSONMock(ctx context.Context, scope ...string) (*google.Credentials, error) {
	creds := google.Credentials{}
	creds.JSON = []byte(`{
  "type": "service_account",
  "project_id": "some-project",
  "private_key_id": "ffffffffffffffffffffffffffffffffffffffff",
  "private_key": "-----BEGIN PRIVATE KEY-----\nbm9wZQ==\n-----END PRIVATE KEY-----\n",
  "client_email": "some-email@some-project.iam.gserviceaccount.com",
  "client_id": "000000000000000000000",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://accounts.google.com/o/oauth2/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/some-email%40some-project.iam.gserviceaccount.com"
}`)
	return &creds, nil
}

func metadataGetMock(path string) (string, error) {
	return "example@example.com", nil
}

func metadataGetFailMock(path string) (string, error) {
	return "", fmt.Errorf("Synthesized metadata.Get failure")
}

func signJwtMock(ctx context.Context, name string, request *iam.SignJwtRequest) (string, error) {
	return "fake signed jwt", nil
}

func getOAuthTokenMock(ctx context.Context, assertion string) (string, error) {
	return "fake oauth token", nil
}

func TestNewIAP(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)
	assert.Equal("client-id", iap.ClientID)
}

func TestGetTokenWithAppDefault(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)

	googleFindDefaultCredentials = googleFindDefaultCredentialsAppDefaultMock
	metadataGet = metadataGetMock
	signJwt = signJwtMock
	getOAuthToken = getOAuthTokenMock

	token, err := iap.GetToken(context.Background())
	assert.Nil(err)
	assert.Equal(token, "fake oauth token")

	err = iap.refresh(context.Background())
	assert.Nil(err)
}

func TestGetTokenWithServiceAccountJSON(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)

	googleFindDefaultCredentials = googleFindDefaultCredentialsServiceAccountJSONMock
	metadataGet = metadataGetMock
	signJwt = signJwtMock
	getOAuthToken = getOAuthTokenMock

	token, err := iap.GetToken(context.Background())
	assert.Nil(err)
	assert.Equal(token, "fake oauth token")
}

func TestGetTokenWithAuthorizedUserJSON(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)

	googleFindDefaultCredentials = googleFindDefaultCredentialsAuthorizedUserJSONMock
	metadataGet = metadataGetMock
	signJwt = signJwtMock
	getOAuthToken = getOAuthTokenMock

	token, err := iap.GetToken(context.Background())
	assert.NotNil(err)
	assert.Equal(token, "")
}

func TestGetTokenWithBadMetadataGet(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)

	googleFindDefaultCredentials = googleFindDefaultCredentialsAppDefaultMock
	metadataGet = metadataGetFailMock
	signJwt = signJwtMock
	getOAuthToken = getOAuthTokenMock

	token, err := iap.GetToken(context.Background())
	assert.NotNil(err)
	assert.Equal(token, "")
}

func TestRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)

	iap.Transport = new(MockedTransport)

	googleFindDefaultCredentials = googleFindDefaultCredentialsAppDefaultMock
	metadataGet = metadataGetMock
	signJwt = signJwtMock
	getOAuthToken = getOAuthTokenMock

	req, err := http.NewRequest("GET", "http://localhost:65535/", nil)
	require.Nil(err)

	resp, err := iap.RoundTrip(req)
	assert.Nil(err)
	assert.NotNil(resp)

}
