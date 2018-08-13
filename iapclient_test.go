package iapclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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

type TransportMock struct{}

func (c *TransportMock) RoundTrip(req *http.Request) (*http.Response, error) {
	resp := &http.Response{}
	resp.StatusCode = 200
	resp.Status = "200 Success"
	switch req.URL.String() {
	case "https://www.googleapis.com/oauth2/v4/token":
		resp.Body = nopCloser{bytes.NewBufferString("{\"id_token\": \"fake_id_token\"}")}
	case "http://localhost/roundtrip":
		auth := req.Header.Get("Authorization")
		resp.Body = nopCloser{bytes.NewBufferString(fmt.Sprintf("auth header: %v", auth))}
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

func signJWTMock(httpClient *http.Client, name string, request *iam.SignJwtRequest) (string, error) {
	return string(request.Payload), nil
}

func TestNewIAP(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id", nil)

	require.Nil(err)
	require.NotNil(iap)
	assert.Equal("client-id", iap.clientID)
}

func TestRefreshWithAppDefault(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id", &Config{
		HTTPClient: &http.Client{Transport: &TransportMock{}},
	})

	require.Nil(err)
	require.NotNil(iap)

	googleFindDefaultCredentials = googleFindDefaultCredentialsAppDefaultMock
	metadataGet = metadataGetMock
	signJWT = signJWTMock

	iap.context = context.Background()

	t.Run("refresh", func(t *testing.T) {
		err = iap.refresh(iap.context)
		assert.Nil(err)
	})

	t.Run("getSignerEmail", func(t *testing.T) {
		assert.Equal("some-email@some-project.iam.gserviceaccount.com", iap.signerEmail)
	})

	t.Run("refreshJwt", func(t *testing.T) {
		assert.NotNil(iap.signedJWT)
		// In testing context iap.SignedJwt is actually the claimSet that was
		// sent to be signed
		var cs claimSet
		err = json.Unmarshal([]byte(iap.signedJWT), &cs)
		assert.Nil(err)

		assert.Equal("https://www.googleapis.com/oauth2/v4/token", cs.Aud)
		assert.Equal("some-email@some-project.iam.gserviceaccount.com", cs.Iss)
		assert.Equal("client-id", cs.TargetAudience)
	})

	t.Run("refreshJwt", func(t *testing.T) {
		assert.NotNil(iap.oidc)
		assert.Equal("fake_id_token", iap.oidc)
	})

	t.Run("refresh", func(t *testing.T) {
		err = iap.refresh(iap.context)
		assert.Nil(err)
	})
}

func TestRefreshWithServiceAccountJSON(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id", &Config{
		HTTPClient: &http.Client{Transport: &TransportMock{}},
	})

	require.Nil(err)
	require.NotNil(iap)

	googleFindDefaultCredentials = googleFindDefaultCredentialsServiceAccountJSONMock
	metadataGet = metadataGetMock
	signJWT = signJWTMock

	iap.context = context.Background()

	t.Run("refresh", func(t *testing.T) {
		err = iap.refresh(iap.context)
		assert.Nil(err)
	})

	t.Run("getSignerEmail", func(t *testing.T) {
		assert.Equal("some-email@some-project.iam.gserviceaccount.com", iap.signerEmail)
	})

	t.Run("refreshJwt", func(t *testing.T) {
		assert.NotNil(iap.signedJWT)
		// In testing context iap.SignedJwt is actually the iam.SignJwtRequest.Payload
		var cs claimSet
		err = json.Unmarshal([]byte(iap.signedJWT), &cs)
		assert.Nil(err)

		assert.Equal("https://www.googleapis.com/oauth2/v4/token", cs.Aud)
		assert.Equal("some-email@some-project.iam.gserviceaccount.com", cs.Iss)
		assert.Equal("client-id", cs.TargetAudience)
	})

	t.Run("refreshJwt", func(t *testing.T) {
		assert.NotNil(iap.oidc)
		assert.Equal("fake_id_token", iap.oidc)
	})
}

func TestRefreshWithAuthorizedUserJSON(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id", &Config{
		HTTPClient: &http.Client{Transport: &TransportMock{}},
	})

	require.Nil(err)
	require.NotNil(iap)

	googleFindDefaultCredentials = googleFindDefaultCredentialsAuthorizedUserJSONMock
	metadataGet = metadataGetMock
	signJWT = signJWTMock

	iap.context = context.Background()

	t.Run("refresh", func(t *testing.T) {
		err = iap.refresh(iap.context)
		assert.NotNil(err)
	})
}

func TestRefreshWithFailingMetadata(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id", &Config{
		HTTPClient: &http.Client{Transport: &TransportMock{}},
	})

	require.Nil(err)
	require.NotNil(iap)

	googleFindDefaultCredentials = googleFindDefaultCredentialsAuthorizedUserJSONMock
	metadataGet = metadataGetFailMock
	signJWT = signJWTMock

	iap.context = context.Background()

	t.Run("refresh", func(t *testing.T) {
		err = iap.refresh(iap.context)
		assert.NotNil(err)
	})
}

func TestRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id", &Config{
		HTTPClient: &http.Client{Transport: &TransportMock{}},
		Transport:  &TransportMock{},
	})

	require.Nil(err)
	require.NotNil(iap)

	googleFindDefaultCredentials = googleFindDefaultCredentialsAppDefaultMock
	metadataGet = metadataGetMock
	signJWT = signJWTMock

	iap.context = context.Background()

	req, err := http.NewRequest("GET", "http://localhost/roundtrip", nil)
	assert.Nil(err)

	resp, err := iap.RoundTrip(req)
	assert.Nil(err)
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(err)

	assert.Equal("auth header: Bearer fake_id_token", string(body))
}

func TestGetToken(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id", &Config{
		HTTPClient: &http.Client{Transport: &TransportMock{}},
		Transport:  &TransportMock{},
	})

	require.Nil(err)
	require.NotNil(iap)

	googleFindDefaultCredentials = googleFindDefaultCredentialsAppDefaultMock
	metadataGet = metadataGetMock
	signJWT = signJWTMock

	iap.context = context.Background()

	resp, err := iap.GetToken(context.Background())
	assert.Nil(err)
	assert.Equal("fake_id_token", resp)
}
