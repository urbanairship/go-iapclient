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

type MockedGoogleClient struct {
	mock.Mock
}

func (m *MockedGoogleClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	log.Printf("shit: %v", args)
	//return args.Bool(0), args.Error(1)
	return nil, fmt.Errorf("MockedGoogleClient")
	return nil, args.Error(1)
}

/*
func googleFindDefaultCredentialsMock(ctx context.Context, scope ...string) (*google.Credentials, error) {
	creds := google.Credentials{}
	creds.JSON = []byte{'{', '}'}
	return &creds, nil
}

func googleDefaultClientMock(ctx context.Context, scope ...string) (*http.Client, error) {
	return nil, fmt.Errorf("ahh fuck 2")
}

func metadataGetMock(path string) (string, error) {
	return "example@example.com", nil
}
*/

func TestNewIAP(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)
	assert.Equal("client-id", iap.ClientID)
}

func TestRefresh(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	iap, err := NewIAP("client-id")

	require.Nil(err)
	require.NotNil(iap)

	iap.Transport = new(MockedTransport)
	iap.GoogleClient = new(MockedGoogleClient)

	ctx := context.Background()
	err = iap.refresh(ctx)

	assert.Nil(err)
}
