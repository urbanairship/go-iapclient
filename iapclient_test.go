package iapclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/google"
	iam "google.golang.org/api/iam/v1"
)

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error { return nil }

type HttpClientMock struct{}

func (c *HttpClientMock) Do(req *http.Request) (*http.Response, error) {
	resp := &http.Response{}
	switch req.URL.String() {
	case "https://www.googleapis.com/oauth2/v4/token":
		resp.Body = nopCloser{bytes.NewBufferString("{\"id_token\": \"fake_id_token\"}")}
	default:
		return nil, fmt.Errorf("Unhandled testing URL: %v", req.URL)
	}
	return resp, nil
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
	return "some-email@some-project.iam.gserviceaccount.com", nil
}

func metadataGetFailMock(path string) (string, error) {
	return "", fmt.Errorf("Synthesized metadata.Get failure")
}

func signJwtMock(httpClient Doer, name string, request *iam.SignJwtRequest) (string, error) {
	return string(request.Payload), nil
}

func TestNewIAP(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)
	assert.Equal("client-id", iap.ClientID)
}

func TestRefreshWithAppDefault(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)

	iap.HttpClient = &HttpClientMock{}

	googleFindDefaultCredentials = googleFindDefaultCredentialsAppDefaultMock
	metadataGet = metadataGetMock
	signJwt = signJwtMock

	iap.Context = context.Background()

	t.Run("refresh", func(t *testing.T) {
		err = iap.refresh(iap.Context)
		assert.Nil(err)
	})

	t.Run("getSignerEmail", func(t *testing.T) {
		assert.Equal("some-email@some-project.iam.gserviceaccount.com", iap.SignerEmail)
	})

	t.Run("refreshJwt", func(t *testing.T) {
		assert.NotNil(iap.SignedJwt)
		// In testing context iap.SignedJwt is actually the claimSet that was
		// sent to be signed
		var cs claimSet
		err = json.Unmarshal([]byte(iap.SignedJwt), &cs)
		assert.Nil(err)

		assert.Equal("https://www.googleapis.com/oauth2/v4/token", cs.Aud)
		assert.Equal("some-email@some-project.iam.gserviceaccount.com", cs.Iss)
		assert.Equal("client-id", cs.TargetAudience)
	})

	t.Run("refreshJwt", func(t *testing.T) {
		assert.NotNil(iap.OIDC)
		assert.Equal("fake_id_token", iap.OIDC)
	})

	t.Run("refresh", func(t *testing.T) {
		err = iap.refresh(iap.Context)
		assert.Nil(err)
	})
}

func TestRefreshWithServiceAccountJSON(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)

	iap.HttpClient = &HttpClientMock{}

	googleFindDefaultCredentials = googleFindDefaultCredentialsServiceAccountJSONMock
	metadataGet = metadataGetMock
	signJwt = signJwtMock

	iap.Context = context.Background()

	t.Run("refresh", func(t *testing.T) {
		err = iap.refresh(iap.Context)
		assert.Nil(err)
	})

	t.Run("getSignerEmail", func(t *testing.T) {
		assert.Equal("some-email@some-project.iam.gserviceaccount.com", iap.SignerEmail)
	})

	t.Run("refreshJwt", func(t *testing.T) {
		assert.NotNil(iap.SignedJwt)
		// In testing context iap.SignedJwt is actually the iam.SignJwtRequest.Payload
		var cs claimSet
		err = json.Unmarshal([]byte(iap.SignedJwt), &cs)
		assert.Nil(err)

		assert.Equal("https://www.googleapis.com/oauth2/v4/token", cs.Aud)
		assert.Equal("some-email@some-project.iam.gserviceaccount.com", cs.Iss)
		assert.Equal("client-id", cs.TargetAudience)
	})

	t.Run("refreshJwt", func(t *testing.T) {
		assert.NotNil(iap.OIDC)
		assert.Equal("fake_id_token", iap.OIDC)
	})
}

func TestRefreshWithAuthorizedUserJSON(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)

	iap.HttpClient = &HttpClientMock{}

	googleFindDefaultCredentials = googleFindDefaultCredentialsAuthorizedUserJSONMock
	metadataGet = metadataGetMock
	signJwt = signJwtMock

	iap.Context = context.Background()

	t.Run("refresh", func(t *testing.T) {
		err = iap.refresh(iap.Context)
		assert.NotNil(err)
	})
}

func TestRefreshWithFailingMetadata(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)

	iap.HttpClient = &HttpClientMock{}

	googleFindDefaultCredentials = googleFindDefaultCredentialsAuthorizedUserJSONMock
	metadataGet = metadataGetFailMock
	signJwt = signJwtMock

	iap.Context = context.Background()

	t.Run("refresh", func(t *testing.T) {
		err = iap.refresh(iap.Context)
		assert.NotNil(err)
	})
}

func TestRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)

	iap.HttpClient = &HttpClientMock{}

	googleFindDefaultCredentials = googleFindDefaultCredentialsAppDefaultMock
	metadataGet = metadataGetMock
	signJwt = signJwtMock

	iap.Context = context.Background()

	req, err := http.NewRequest("GET", "http://localhost", nil)
	assert.Nil(err)
	resp, err := iap.RoundTrip(req)
	assert.NotNil(err)
	_ = resp
	//assert.Equal("", resp)
}
